/**
 * The signing key of the OP: one RS256 private JWK held in the SIGNING_KEY
 * Worker secret (scripts/lib/keys.ts generates it).
 *
 * The generated provider publishes the public part of every key this provider
 * returns at the JWKS endpoint, so nothing else has to be stored. There is no
 * rotation: the certification tests the OP is built for (Basic OP / Config OP)
 * do not rotate keys, and replacing the secret takes effect with the next
 * deployment version.
 */
import {
  extractAlgorithmParamsFromJwk,
  type SigningKey,
  type SigningKeyProvider,
} from '@maronn-openid-connect/core';

type PrivateJwk = JsonWebKey & { kid?: string };

const PUBLIC_JWK_MEMBERS = ['kty', 'use', 'alg', 'kid', 'n', 'e', 'crv', 'x', 'y'] as const;

/** Keep only public members, so the private key can never leak through the JWKS endpoint. */
function toPublicJwk(jwk: PrivateJwk): SigningKey['publicJwk'] {
  const publicJwk: Record<string, unknown> = {};
  for (const member of PUBLIC_JWK_MEMBERS) {
    if (typeof jwk[member] === 'string') publicJwk[member] = jwk[member];
  }
  return publicJwk as SigningKey['publicJwk'];
}

async function importSigningKey(secret: string | undefined): Promise<SigningKey> {
  if (!secret) {
    throw new Error('SIGNING_KEY is not set');
  }
  const jwk = JSON.parse(secret) as PrivateJwk;
  if (typeof jwk.kid !== 'string' || jwk.kid === '') {
    throw new Error('SIGNING_KEY must have a kid');
  }
  const publicJwk = toPublicJwk(jwk);
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    jwk,
    extractAlgorithmParamsFromJwk(publicJwk),
    false,
    ['sign'],
  );
  return { privateKey, publicJwk, keyId: jwk.kid };
}

/**
 * secret: the value of the SIGNING_KEY binding. The imported key is kept for
 * the life of the isolate: a new secret value only arrives with a new
 * deployment version, which starts new isolates. Only the imported value is
 * shared between requests, never an in-flight promise (on Workers a promise
 * belongs to the request that created it).
 */
export function createSigningKeyProvider(secret: string | undefined): SigningKeyProvider {
  let imported: SigningKey | undefined;
  return {
    async getSigningKeys() {
      imported ??= await importSigningKey(secret);
      return [imported];
    },
  };
}
