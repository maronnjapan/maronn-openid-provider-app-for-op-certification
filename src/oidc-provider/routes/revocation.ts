import { Hono } from 'hono';
import {
  extractClientCredentials,
  resolveAuthenticatedTokenClient,
  validateClientAuthMethod,
  verifyClientSecret,
  requireRevocationToken,
  requireRevocationClient,
  resolveRevocationTarget,
  validateRevocationTokenClient,
  revokeResolvedToken,
  revokeGrantAccessTokens,
  RevocationError,
  TokenError,
} from '@maronn-openid-connect/core';
import {
  tokenClientResolver as defaultTokenClientResolver,
  revocationResolvers as defaultRevocationResolvers,
} from '../resolvers.js';

export const revocationApp = new Hono<{ Variables: Record<string, any> }>();

function isFormUrlEncoded(contentType: string): boolean {
  return contentType.toLowerCase().split(';')[0]?.trim() === 'application/x-www-form-urlencoded';
}

/**
 * Token Revocation Endpoint
 * RFC 7009 Section 2
 *
 * Confidential clients authenticate with their registered secret method. Public
 * clients registered with token_endpoint_auth_method=none identify themselves
 * with client_id only (RFC 7009 §2.1).
 * Always returns 200 OK with no body for both "revoked" and "not found" cases
 * to prevent client side-channels (RFC 7009 Section 2.2).
 *
 * Refresh token revocation also revokes sibling access tokens via grantId
 * (RFC 7009 Section 2.1 SHOULD).
 */
revocationApp.post('/', async (c) => {
  c.header('Cache-Control', 'no-store');
  c.header('Pragma', 'no-cache');

  if (!isFormUrlEncoded(c.req.header('Content-Type') ?? '')) {
    return c.json(
      {
        error: 'invalid_request',
        error_description: 'Content-Type must be application/x-www-form-urlencoded',
      },
      400,
    );
  }

  const body = Object.fromEntries(new URLSearchParams(await c.req.text()));
  const authorization = c.req.header('Authorization') ?? '';
  const params = Object.fromEntries(
    Object.entries(body).map(([k, v]) => [k, String(v)]),
  );

  try {
    const tokenClientResolver = c.get('tokenClientResolver') ?? defaultTokenClientResolver;
    const resolvers = c.get('revocationResolvers') ?? defaultRevocationResolvers;

    // --- Client authentication pipeline -------------------------------------
    // OAuth 2.1 §2.3 / OIDC Core 1.0 §9, the same steps as the token endpoint.
    // Public clients registered with token_endpoint_auth_method=none pass with
    // client_id only (RFC 7009 §2.1).
    const presentedCredentials = extractClientCredentials({
      params,
      authorizationHeader: authorization,
    });
    const revokingClient = await resolveAuthenticatedTokenClient(
      presentedCredentials.clientId,
      tokenClientResolver,
    );
    validateClientAuthMethod(revokingClient, presentedCredentials);
    await verifyClientSecret(revokingClient, presentedCredentials.clientSecret);
    const authenticatedClientId = presentedCredentials.clientId;

    // --- Revocation pipeline ------------------------------------------------
    // Each step below is an independent core function, called in RFC 7009 §2
    // order. Delete a call to drop that step, or insert your own logic between
    // steps.

    // RFC 7009 §2.1: token is REQUIRED (invalid_request when absent).
    const token = requireRevocationToken({
      token: typeof params.token === 'string' ? params.token : undefined,
    });

    // RFC 7009 §2.1: the caller must be an identified client (invalid_client).
    requireRevocationClient(authenticatedClientId);

    // RFC 7009 §2.1: token_type_hint only reorders the lookup — the other token
    // type is still searched when the hint misses.
    const resolved = await resolveRevocationTarget({
      token,
      tokenTypeHint:
        typeof params.token_type_hint === 'string' ? params.token_type_hint : undefined,
      resolvers,
    });

    // RFC 7009 §2.2: an unknown token is still a success, so the client cannot
    // probe which token values exist.
    if (resolved !== null) {
      // RFC 7009 §2.1: a token issued to another client is refused (invalid_grant).
      validateRevocationTokenClient(resolved, authenticatedClientId);

      await revokeResolvedToken(token, resolved, resolvers);

      // RFC 7009 §2.1 SHOULD: revoking a refresh token also revokes the access
      // tokens of the same grant. Delete this call to revoke only the presented
      // token.
      await revokeGrantAccessTokens(resolved, resolvers);
    }

    // RFC 7009 Section 2.2: empty body, 200 OK
    return c.body(null, 200);
  } catch (error) {
    if (error instanceof TokenError) {
      const status = error.statusCode as 400 | 401;
      if (error.wwwAuthenticate) c.header('WWW-Authenticate', error.wwwAuthenticate);
      return c.json(
        { error: error.error, error_description: error.errorDescription },
        status,
      );
    }
    if (error instanceof RevocationError) {
      const status = error.statusCode as 400 | 401;
      if (error.wwwAuthenticate) c.header('WWW-Authenticate', error.wwwAuthenticate);
      return c.json(
        { error: error.error, error_description: error.errorDescription },
        status,
      );
    }
    return c.json({ error: 'server_error' }, 500);
  }
});
