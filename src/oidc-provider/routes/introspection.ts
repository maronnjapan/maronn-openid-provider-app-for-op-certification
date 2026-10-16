import { Hono } from 'hono';
import {
  extractClientCredentials,
  resolveAuthenticatedTokenClient,
  validateClientAuthMethod,
  verifyClientSecret,
  requireIntrospectionToken,
  requireIntrospectionClient,
  requireConfidentialIntrospectionCaller,
  resolveIntrospectionToken,
  isIntrospectionTokenActive,
  buildIntrospectionResponse,
  INACTIVE_INTROSPECTION_RESPONSE,
  IntrospectionError,
  TokenError,
  type IntrospectionResponse,
} from '@maronn-openid-connect/core';
import {
  tokenClientResolver as defaultTokenClientResolver,
  introspectionAccessTokenResolver as defaultAccessResolver,
  introspectionRefreshTokenResolver as defaultRefreshResolver,
} from '../resolvers.js';

export const introspectionApp = new Hono<{ Variables: Record<string, any> }>();

function isFormUrlEncoded(contentType: string): boolean {
  return contentType.toLowerCase().split(';')[0]?.trim() === 'application/x-www-form-urlencoded';
}

/**
 * Token Introspection Endpoint
 * RFC 7662 Section 2
 *
 * Confidential client only — a caller registered with
 * token_endpoint_auth_method 'none' is rejected with invalid_client
 * (RFC 7662 §2.1 / RFC 9701 §5), because a public client_id alone is not
 * authentication. Response is always cache-busting per RFC 7662 Section 2.2.
 */
introspectionApp.post('/', async (c) => {
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
    const accessTokenResolver =
      c.get('introspectionAccessTokenResolver') ?? defaultAccessResolver;
    const refreshTokenResolver =
      c.get('introspectionRefreshTokenResolver') ?? defaultRefreshResolver;

    // --- Client authentication pipeline -------------------------------------
    // OAuth 2.1 §2.3 / OIDC Core 1.0 §9, the same steps as the token endpoint.
    // RFC 7662 §2.1 requires the caller to authenticate.
    const presentedCredentials = extractClientCredentials({
      params,
      authorizationHeader: authorization,
    });
    const introspectingClient = await resolveAuthenticatedTokenClient(
      presentedCredentials.clientId,
      tokenClientResolver,
    );
    validateClientAuthMethod(introspectingClient, presentedCredentials);
    await verifyClientSecret(introspectingClient, presentedCredentials.clientSecret);
    // RFC 7662 §2.1 / RFC 9701 §5: the caller must be an authenticated
    // confidential client. A client registered with token_endpoint_auth_method
    // 'none' passes the pipeline above by presenting its client_id alone —
    // public information — so treating it as authenticated would let anyone
    // scan tokens. Revocation deliberately has no such step: RFC 7009 §2.1
    // lets a public client revoke its own tokens.
    requireConfidentialIntrospectionCaller(introspectingClient);
    const authenticatedClientId = presentedCredentials.clientId;

    // --- Introspection pipeline ---------------------------------------------
    // Each step below is an independent core function, called in RFC 7662 §2
    // order. Delete a call to drop that step, or insert your own logic between
    // steps.

    // RFC 7662 §2.1: token is REQUIRED (invalid_request when absent).
    const token = requireIntrospectionToken({
      token: typeof params.token === 'string' ? params.token : undefined,
    });

    // RFC 7662 §2.1: the caller must be an authenticated client (invalid_client).
    requireIntrospectionClient(authenticatedClientId);

    // RFC 7662 §2.1: token_type_hint only reorders the lookup — the other token
    // type is still searched when the hint misses.
    const resolved = await resolveIntrospectionToken({
      token,
      tokenTypeHint:
        typeof params.token_type_hint === 'string' ? params.token_type_hint : undefined,
      accessTokenResolver,
      refreshTokenResolver,
    });

    // RFC 7662 §2.2: an unknown, expired, not-yet-valid or rotated token is
    // reported as { active: false } with no other member, so the caller cannot
    // distinguish "never existed" from "no longer valid".
    let response: IntrospectionResponse = INACTIVE_INTROSPECTION_RESPONSE;
    if (resolved !== null && isIntrospectionTokenActive(resolved)) {
      response = buildIntrospectionResponse(resolved);
    }

    return c.json(response);
  } catch (error) {
    if (error instanceof TokenError) {
      const status = error.statusCode as 400 | 401;
      if (error.wwwAuthenticate) c.header('WWW-Authenticate', error.wwwAuthenticate);
      return c.json(
        { error: error.error, error_description: error.errorDescription },
        status,
      );
    }
    if (error instanceof IntrospectionError) {
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
