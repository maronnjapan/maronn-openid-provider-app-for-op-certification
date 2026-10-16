import { Hono } from 'hono';
import {
  extractClientCredentials,
  resolveAuthenticatedTokenClient,
  validateClientAuthMethod,
  verifyClientSecret,
  requireConfidentialIntrospectionCaller,
  requireIntrospectionToken,
  requireIntrospectionClient,
  resolveIntrospectionToken,
  type ResolvedIntrospectionToken,
  isIntrospectionTokenActive,
  buildIntrospectionResponse,
  INACTIVE_INTROSPECTION_RESPONSE,
  type IntrospectionResponse,
  IntrospectionError,
  TokenError,
} from '@maronn-openid-connect/core';
import {
  tokenClientResolver as defaultTokenClientResolver,
  introspectionAccessTokenResolver as defaultAccessResolver,
  introspectionRefreshTokenResolver as defaultRefreshResolver,
} from '../resolvers.js';

/**
 * Token Introspection endpoint (API layer).
 * RFC 7662 Section 2
 *
 * Every function exported below is one box of the introspection endpoint's
 * pipeline (`maronn-oidc graph --detail steps --endpoint introspection`):
 * parse the request, authenticate the confidential client, resolve the token,
 * describe it, and answer. The handler at the bottom calls them in order.
 *
 * Confidential client only — a caller registered with
 * token_endpoint_auth_method 'none' is rejected with invalid_client
 * (RFC 7662 §2.1 / RFC 9701 §5), because a public client_id alone is not
 * authentication. Response is always cache-busting per RFC 7662 Section 2.2.
 */

/** What the introspection endpoint answers; respondIntrospection() turns it into HTTP. */
export interface IntrospectionEndpointResponse {
  status: number;
  /** A JSON body (application/json). */
  body?: object;
  /** A raw body with its own Content-Type (the signed JWT of RFC 9701). */
  text?: string;
  headers?: Record<string, string>;
}

/** A failure a step answers with a fixed response (a malformed request). */
export class IntrospectionEndpointError extends Error {
  constructor(readonly response: IntrospectionEndpointResponse) {
    const details = (response.body ?? {}) as { error?: unknown; error_description?: unknown };
    super(String(details.error_description ?? details.error ?? 'introspection endpoint error'));
    this.name = 'IntrospectionEndpointError';
  }
}

export const introspectionApp = new Hono<{ Variables: Record<string, any> }>();

function isFormUrlEncoded(contentType: string): boolean {
  return contentType.toLowerCase().split(';')[0]?.trim() === 'application/x-www-form-urlencoded';
}

/**
 * Parse the introspection request: the form body and the Authorization header.
 * RFC 7662 §2.1 (the body MUST be application/x-www-form-urlencoded)
 */
export async function parseIntrospectionRequest(
  c: any,
): Promise<{ params: Record<string, string>; authorization: string }> {
  if (!isFormUrlEncoded(c.req.header('Content-Type') ?? '')) {
    throw new IntrospectionEndpointError({
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
 * (OAuth 2.1 §2.3 / OIDC Core 1.0 §9) — and require a confidential client.
 * RFC 7662 §2.1 / RFC 9701 §5
 *
 * A client registered with token_endpoint_auth_method 'none' passes the
 * pipeline by presenting its client_id alone — public information — so
 * treating it as authenticated would let anyone scan tokens. Revocation
 * deliberately has no such step: RFC 7009 §2.1 lets a public client revoke
 * its own tokens.
 */
export async function authenticateIntrospectionClient(
  c: any,
  params: Record<string, string>,
  authorization: string,
): Promise<string> {
  const tokenClientResolver = c.get('tokenClientResolver') ?? defaultTokenClientResolver;
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
  requireConfidentialIntrospectionCaller(introspectingClient);
  return presentedCredentials.clientId;
}

/**
 * Resolve the presented token (access or refresh token); null when unknown.
 * RFC 7662 §2.1
 *
 * Each check is an independent core function. token_type_hint only reorders
 * the lookup — the other token type is still searched when the hint misses.
 */
export async function resolveIntrospectedToken(
  c: any,
  params: Record<string, string>,
  authenticatedClientId: string,
): Promise<ResolvedIntrospectionToken | null> {
  const accessTokenResolver =
    c.get('introspectionAccessTokenResolver') ?? defaultAccessResolver;
  const refreshTokenResolver =
    c.get('introspectionRefreshTokenResolver') ?? defaultRefreshResolver;

  // RFC 7662 §2.1: token is REQUIRED (invalid_request when absent).
  const token = requireIntrospectionToken({
    token: typeof params.token === 'string' ? params.token : undefined,
  });

  // RFC 7662 §2.1: the caller must be an authenticated client (invalid_client).
  requireIntrospectionClient(authenticatedClientId);

  return resolveIntrospectionToken({
    token,
    tokenTypeHint:
      typeof params.token_type_hint === 'string' ? params.token_type_hint : undefined,
    accessTokenResolver,
    refreshTokenResolver,
  });
}

/**
 * Describe the token. RFC 7662 §2.2: an unknown, expired, not-yet-valid or
 * rotated token is reported as { active: false } with no other member, so the
 * caller cannot distinguish "never existed" from "no longer valid".
 */
export function describeIntrospectedToken(resolved: ResolvedIntrospectionToken | null): IntrospectionResponse {
  if (resolved !== null && isIntrospectionTokenActive(resolved)) {
    return buildIntrospectionResponse(resolved);
  }
  return INACTIVE_INTROSPECTION_RESPONSE;
}

/**
 * Send an introspection answer. RFC 7662 Section 2.2: never cached.
 */
export function respondIntrospection(c: any, response: IntrospectionEndpointResponse): Response {
  c.header('Cache-Control', 'no-store');
  c.header('Pragma', 'no-cache');
  for (const [name, value] of Object.entries(response.headers ?? {})) {
    c.header(name, value);
  }
  if (response.text !== undefined) {
    return c.body(response.text, response.status);
  }
  return c.json(response.body ?? {}, response.status);
}

/**
 * Answer a failure of any step with the OAuth error response.
 * RFC 7662 §2.3 / RFC 6749 §5.2
 */
export function respondIntrospectionError(c: any, error: unknown): Response {
  if (error instanceof IntrospectionEndpointError) {
    return respondIntrospection(c, error.response);
  }
  if (error instanceof TokenError || error instanceof IntrospectionError) {
    return respondIntrospection(c, {
      status: error.statusCode,
      body: { error: error.error, error_description: error.errorDescription },
      headers: error.wwwAuthenticate ? { 'WWW-Authenticate': error.wwwAuthenticate } : undefined,
    });
  }
  return respondIntrospection(c, { status: 500, body: { error: 'server_error' } });
}

/**
 * Token Introspection Endpoint
 * RFC 7662 Section 2
 *
 * The pipeline: each statement below is one step function of this module, in
 * the order of the flow. A step that throws ends in respondIntrospectionError().
 */
introspectionApp.post('/', async (c) => {
  try {
    // [parse-request] Parse the introspection request — RFC 7662 §2.1
    const { params, authorization } = await parseIntrospectionRequest(c);

    // [authenticate-client] Authenticate the confidential client — RFC 7662 §2.1 / OAuth 2.1 §2.3
    const authenticatedClientId = await authenticateIntrospectionClient(c, params, authorization);

    // [resolve-token] Resolve the presented token — RFC 7662 §2.1
    const resolved = await resolveIntrospectedToken(c, params, authenticatedClientId);

    // [build-response] Describe the token (active or not) — RFC 7662 §2.2
    const introspection = describeIntrospectedToken(resolved);

    // [respond] Respond (no-store) — RFC 7662 §2.2
    return respondIntrospection(c, { status: 200, body: introspection });
  } catch (error) {
    return respondIntrospectionError(c, error);
  }
});
