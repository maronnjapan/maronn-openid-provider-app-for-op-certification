import { Hono } from 'hono';
import {
  extractClientCredentials,
  resolveAuthenticatedTokenClient,
  validateClientAuthMethod,
  verifyClientSecret,
  requireRevocationToken,
  requireRevocationClient,
  resolveRevocationTarget,
  type ResolvedRevocationToken,
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

/**
 * Token Revocation endpoint (API layer).
 * RFC 7009 Section 2
 *
 * Every function exported below is one box of the revocation endpoint's
 * pipeline (`maronn-oidc graph --detail steps --endpoint revocation`): parse
 * the request, authenticate the client, resolve the token, revoke it with its
 * grant siblings, and answer. The handler at the bottom calls them in order.
 *
 * Confidential clients authenticate with their registered secret method. Public
 * clients registered with token_endpoint_auth_method=none identify themselves
 * with client_id only (RFC 7009 §2.1).
 * Always returns 200 OK with no body for both "revoked" and "not found" cases
 * to prevent client side-channels (RFC 7009 Section 2.2).
 */

/** What the revocation endpoint answers on a failure; respondRevocationError() turns it into HTTP. */
export interface RevocationEndpointResponse {
  status: number;
  body: object;
  headers?: Record<string, string>;
}

/** A failure a step answers with a fixed response (a malformed request). */
export class RevocationEndpointError extends Error {
  constructor(readonly response: RevocationEndpointResponse) {
    const details = response.body as { error?: unknown; error_description?: unknown };
    super(String(details.error_description ?? details.error ?? 'revocation endpoint error'));
    this.name = 'RevocationEndpointError';
  }
}

export const revocationApp = new Hono<{ Variables: Record<string, any> }>();

function isFormUrlEncoded(contentType: string): boolean {
  return contentType.toLowerCase().split(';')[0]?.trim() === 'application/x-www-form-urlencoded';
}

function noStore(c: any): void {
  c.header('Cache-Control', 'no-store');
  c.header('Pragma', 'no-cache');
}

/**
 * Parse the revocation request: the form body and the Authorization header.
 * RFC 7009 §2.1 (the body MUST be application/x-www-form-urlencoded)
 */
export async function parseRevocationRequest(
  c: any,
): Promise<{ params: Record<string, string>; authorization: string }> {
  if (!isFormUrlEncoded(c.req.header('Content-Type') ?? '')) {
    throw new RevocationEndpointError({
      status: 400,
      body: { error: 'invalid_request', error_description: 'Content-Type must be application/x-www-form-urlencoded' },
    });
  }
  const body = Object.fromEntries(new URLSearchParams(await c.req.text()));
  const authorization = c.req.header('Authorization') ?? '';
  const params = Object.fromEntries(
    Object.entries(body).map(([k, v]) => [k, String(v)]),
  );
  return { params, authorization };
}

/**
 * Authenticate the caller — the same steps as the token endpoint
 * (OAuth 2.1 §2.3 / OIDC Core 1.0 §9). Public clients registered with
 * token_endpoint_auth_method=none pass with client_id only (RFC 7009 §2.1).
 */
export async function authenticateRevocationClient(
  c: any,
  params: Record<string, string>,
  authorization: string,
): Promise<string> {
  const tokenClientResolver = c.get('tokenClientResolver') ?? defaultTokenClientResolver;
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
  return presentedCredentials.clientId;
}

/**
 * Resolve the presented token (access or refresh token); null when unknown.
 * RFC 7009 §2.1
 *
 * Each check is an independent core function. token_type_hint only reorders
 * the lookup — the other token type is still searched when the hint misses.
 */
export async function resolveRevocationTokenTarget(
  c: any,
  params: Record<string, string>,
  authenticatedClientId: string,
): Promise<{ token: string; resolved: ResolvedRevocationToken | null }> {
  const resolvers = c.get('revocationResolvers') ?? defaultRevocationResolvers;

  // RFC 7009 §2.1: token is REQUIRED (invalid_request when absent).
  const token = requireRevocationToken({
    token: typeof params.token === 'string' ? params.token : undefined,
  });

  // RFC 7009 §2.1: the caller must be an identified client (invalid_client).
  requireRevocationClient(authenticatedClientId);

  const resolved = await resolveRevocationTarget({
    token,
    tokenTypeHint:
      typeof params.token_type_hint === 'string' ? params.token_type_hint : undefined,
    resolvers,
  });
  return { token, resolved };
}

/**
 * Revoke the token, and the access tokens of its grant when it is a refresh
 * token (RFC 7009 §2.1 SHOULD). RFC 7009 §2.2: an unknown token is still a
 * success, so the client cannot probe which token values exist.
 */
export async function revokeToken(
  c: any,
  token: string,
  resolved: ResolvedRevocationToken | null,
  authenticatedClientId: string,
): Promise<void> {
  if (resolved === null) return;
  const resolvers = c.get('revocationResolvers') ?? defaultRevocationResolvers;

  // RFC 7009 §2.1: a token issued to another client is refused (invalid_grant).
  validateRevocationTokenClient(resolved, authenticatedClientId);

  await revokeResolvedToken(token, resolved, resolvers);

  // RFC 7009 §2.1 SHOULD: revoking a refresh token also revokes the access
  // tokens of the same grant. Delete this call to revoke only the presented
  // token.
  await revokeGrantAccessTokens(resolved, resolvers);
}

/**
 * RFC 7009 Section 2.2: empty body, 200 OK — for "revoked" and "not found" alike.
 */
export function respondRevocation(c: any): Response {
  noStore(c);
  return c.body(null, 200);
}

/**
 * Answer a failure of any step with the OAuth error response.
 * RFC 7009 §2.2.1 / RFC 6749 §5.2
 */
export function respondRevocationError(c: any, error: unknown): Response {
  noStore(c);
  if (error instanceof RevocationEndpointError) {
    for (const [name, value] of Object.entries(error.response.headers ?? {})) {
      c.header(name, value);
    }
    return c.json(error.response.body, error.response.status);
  }
  if (error instanceof TokenError || error instanceof RevocationError) {
    if (error.wwwAuthenticate) c.header('WWW-Authenticate', error.wwwAuthenticate);
    return c.json(
      { error: error.error, error_description: error.errorDescription },
      error.statusCode,
    );
  }
  return c.json({ error: 'server_error' }, 500);
}

/**
 * Token Revocation Endpoint
 * RFC 7009 Section 2
 *
 * The pipeline: each statement below is one step function of this module, in
 * the order of the flow. A step that throws ends in respondRevocationError().
 */
revocationApp.post('/', async (c) => {
  try {
    // [parse-request] Parse the revocation request — RFC 7009 §2.1
    const { params, authorization } = await parseRevocationRequest(c);

    // [authenticate-client] Authenticate the client — RFC 7009 §2.1 / OAuth 2.1 §2.3
    const authenticatedClientId = await authenticateRevocationClient(c, params, authorization);

    // [resolve-token] Resolve the presented token — RFC 7009 §2.1
    const { token, resolved } = await resolveRevocationTokenTarget(c, params, authenticatedClientId);

    // [revoke-token] Revoke the token and its grant siblings — RFC 7009 §2.1
    await revokeToken(c, token, resolved, authenticatedClientId);

    // [respond] Respond 200 with an empty body — RFC 7009 §2.2
    return respondRevocation(c);
  } catch (error) {
    return respondRevocationError(c, error);
  }
});
