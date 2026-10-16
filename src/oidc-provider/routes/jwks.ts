import { Hono } from 'hono';
import {
  type SigningKey,
  exportJwks,
  extractAlgorithmParamsFromJwk,
  type JwkSet,
} from '@maronn-openid-connect/core';

/**
 * JWKS endpoint (API layer).
 * Serves the public keys used to verify token signatures.
 *
 * Every function exported below is one box of the JWKS endpoint's pipeline
 * (`maronn-oidc graph --detail steps --endpoint jwks`).
 */

export const jwksApp = new Hono<{ Variables: Record<string, any> }>();

/**
 * Collect every registered signing key of the per-purpose key sets
 * (signingKeys / idTokenSigningKeys / userinfoSigningKeys).
 *
 * T-022: every key is published so rotated-out keys remain verifiable until
 * tokens signed with them expire.
 */
export function collectPublishedKeys(c: any): SigningKey[] {
  return [
    ...((c.get('signingKeys') as SigningKey[] | undefined) ?? []),
    ...((c.get('idTokenSigningKeys') as SigningKey[] | undefined) ?? []),
    ...((c.get('userinfoSigningKeys') as SigningKey[] | undefined) ?? []),
  ];
}

/**
 * Export the public halves as a JWK Set (RFC 7517 §5). kid 指定がある鍵は kid で
 * 重複排除し、kid 未指定の鍵は最新の 1 件のみ採用する（鍵セットは新しい鍵ほど
 * 先頭にある）。An empty key set is a server configuration error.
 */
export async function buildJwksDocument(keys: SigningKey[]): Promise<JwkSet> {
  if (keys.length === 0) {
    throw new Error('No signing key is registered');
  }

  // 同じ kid の鍵は最初に出現したものだけを採用する（ID Token / UserInfo 用の
  // プロバイダは既定で汎用プロバイダと同じ鍵を返すため）。kid 未指定の鍵も同様に
  // 最初の 1 件（= 最新）だけを採用する。
  const seenKids = new Set<string>();
  const entries: { publicKey: CryptoKey; keyId?: string }[] = [];
  for (const key of keys) {
    if (seenKids.has(key.keyId)) continue;
    seenKids.add(key.keyId);
    const jwk = key.publicJwk as JsonWebKey;
    const algParams = extractAlgorithmParamsFromJwk(jwk);
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      algParams,
      true,
      ['verify'],
    );
    entries.push({ publicKey, keyId: key.keyId });
  }

  return exportJwks(entries);
}

/** Respond with the cacheable JWK Set (3600s, symmetric with discovery). */
export function respondJwks(c: any, jwks: JwkSet): Response {
  c.header('Cache-Control', 'public, max-age=3600');
  return c.json(jwks);
}

/**
 * JWKS Endpoint
 */
jwksApp.get('/', async (c) => {
  try {
    // [collect-public-keys] Collect every registered signing key
    const keys = collectPublishedKeys(c);

    // [export-jwks] Export the public halves as a JWK Set — RFC 7517 §5
    const jwks = await buildJwksDocument(keys);

    // [respond] Respond with the cacheable JWK Set
    return respondJwks(c, jwks);
  } catch {
    // An empty key set (or a key that cannot be exported) is a configuration
    // problem of the OP, never the caller's.
    return c.json({ error: 'server_error' }, 500);
  }
});
