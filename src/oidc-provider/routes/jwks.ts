import { Hono } from 'hono';
import { exportJwks, extractAlgorithmParamsFromJwk, type SigningKey } from '@maronn-openid-connect/core';

export const jwksApp = new Hono<{ Variables: Record<string, any> }>();

/**
 * JWKS Endpoint
 * Serves the public keys used to verify token signatures.
 *
 * T-022: every key of the per-purpose key sets (signingKeys / idTokenSigningKeys /
 * userinfoSigningKeys) is published so rotated-out keys remain verifiable until
 * tokens signed with them expire. kid 指定がある鍵は kid で重複排除し、kid 未指定の
 * 鍵は最新の 1 件のみ採用する（鍵セットは新しい鍵ほど先頭にある）。
 */
jwksApp.get('/', async (c) => {
  const keys: SigningKey[] = [
    ...((c.get('signingKeys') as SigningKey[] | undefined) ?? []),
    ...((c.get('idTokenSigningKeys') as SigningKey[] | undefined) ?? []),
    ...((c.get('userinfoSigningKeys') as SigningKey[] | undefined) ?? []),
  ];

  if (keys.length === 0) {
    return c.json({ error: 'server_error' }, 500);
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

  const jwks = await exportJwks(entries);

  c.header('Cache-Control', 'public, max-age=3600');
  return c.json(jwks);
});
