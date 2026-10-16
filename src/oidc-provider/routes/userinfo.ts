import { Hono } from 'hono';
import {
  resolveUserInfoAccessToken,
  validateUserInfoTokenExpiration,
  validateUserInfoScope,
  validateUserInfoAudience,
  type AccessTokenInfo,
  resolveUserInfoClaims,
  filterClaimsByScope,
  applyRequestedClaims,
  type UserInfoResponse,
  generateUserInfoJwt,
  selectSigningKeyByAlg,
  type SigningKey,
  UserInfoError,
} from '@maronn-openid-connect/core';
import {
  accessTokenResolver as defaultAccessTokenResolver,
  userClaimsResolver as defaultUserClaimsResolver,
  clientResolver as defaultClientResolver,
} from '../resolvers.js';
import { type RegisteredClient } from '../config.js';

/**
 * UserInfo endpoint (API layer).
 * OIDC Core 1.0 Section 5.3
 *
 * Every function exported below is one box of the UserInfo endpoint's pipeline
 * (`maronn-oidc graph --detail steps --endpoint userinfo`): read the Bearer
 * token, resolve and validate it, resolve the claims it may see, build the
 * response (JSON, or a signed JWT when the client registered
 * userinfo_signed_response_alg) and answer. The handler at the bottom calls
 * them in order.
 */

/** What the UserInfo endpoint answers; respondUserInfo() turns it into HTTP. */
export interface UserInfoEndpointResponse {
  status: number;
  /** A JSON body (application/json). */
  body?: object;
  /** A raw body with its own Content-Type (the signed JWT, application/jwt). */
  text?: string;
  headers?: Record<string, string>;
}

/**
 * A failure a step answers with a fixed response: a malformed request, a
 * missing token (with its Bearer challenge), or a server configuration problem.
 */
export class UserInfoEndpointError extends Error {
  constructor(readonly response: UserInfoEndpointResponse) {
    const details = (response.body ?? {}) as { error?: unknown; error_description?: unknown };
    super(String(details.error_description ?? details.error ?? 'userinfo endpoint error'));
    this.name = 'UserInfoEndpointError';
  }
}

export const userinfoApp = new Hono<{ Variables: Record<string, any> }>();

/**
 * Read the access token from the request, supporting:
 * - Authorization: Bearer header (RFC 6750 Section 2.1, REQUIRED)
 * - access_token form body parameter on POST (RFC 6750 Section 2.2, OPTIONAL)
 *
 * Per RFC 6750 Section 2, clients MUST NOT use more than one method per request.
 * URL query parameter (Section 2.3) is intentionally NOT supported (OAuth 2.1 prohibits it).
 * A request without a token is answered 401 with the realm-only challenge of
 * RFC 6750 §3.1; one that uses two methods is answered 400.
 */
export async function parseUserInfoRequest(c: any): Promise<string> {
  let headerToken = '';
  let bodyToken = '';
  try {
    const authHeader = c.req.header('Authorization') ?? '';
    // RFC 7235 Section 2.1: HTTP authentication scheme is case-insensitive.
    // Match the "Bearer" scheme case-insensitively but preserve the token value verbatim.
    const bearerSpaceIndex = authHeader.indexOf(' ');
    headerToken =
      bearerSpaceIndex !== -1 &&
      authHeader.slice(0, bearerSpaceIndex).toLowerCase() === 'bearer'
        ? authHeader.slice(bearerSpaceIndex + 1)
        : '';

    if (c.req.method === 'POST') {
      const contentType = c.req.header('Content-Type') ?? '';
      const mediaType = contentType.toLowerCase().split(';')[0]?.trim() ?? '';
      if (mediaType === 'application/x-www-form-urlencoded') {
        // Parse the form payload ourselves after media-type normalization. Hono's
        // parseBody() dispatch is case-sensitive for some Content-Type spellings.
        const body = Object.fromEntries(new URLSearchParams(await c.req.text()));
        const candidate = body['access_token'];
        if (typeof candidate === 'string') {
          bodyToken = candidate;
        }
      }
    }
  } catch {
    throw new UserInfoEndpointError({ status: 400, body: { error: 'invalid_request' } });
  }

  const methodCount = (headerToken ? 1 : 0) + (bodyToken ? 1 : 0);
  if (methodCount > 1) {
    // RFC 6750 Section 2: clients MUST NOT use more than one method per request.
    throw new UserInfoEndpointError({
      status: 400,
      body: { error: 'invalid_request', error_description: 'Multiple access token methods are not allowed' },
      headers: { 'WWW-Authenticate': 'Bearer realm="UserInfo", error="invalid_request"' },
    });
  }
  const accessToken = headerToken || bodyToken;
  if (!accessToken) {
    // RFC 6750 §3.1: when the request has no authentication information, the
    // challenge omits error/error_description and only identifies the realm.
    throw new UserInfoEndpointError({
      status: 401,
      body: { error: 'invalid_token', error_description: 'Access token is required' },
      headers: { 'WWW-Authenticate': 'Bearer realm="UserInfo"' },
    });
  }
  return accessToken;
}

/**
 * Resolve the presented Bearer token and validate it: known, not expired,
 * carries the openid scope, and names this UserInfo endpoint in its audience.
 * OIDC Core 1.0 §5.3.1 / RFC 6750 §3.1 / RFC 9068 §4
 *
 * Each check is an independent core function that throws UserInfoError, which
 * respondUserInfoError() renders as an RFC 6750 Bearer challenge.
 */
export async function resolveUserInfoToken(c: any, accessToken: string): Promise<AccessTokenInfo> {
  const accessTokenResolver = c.get('accessTokenResolver') ?? defaultAccessTokenResolver;

  // OIDC Core 1.0 §5.3.1: resolve the presented Bearer token (invalid_token when unknown).
  const tokenInfo = await resolveUserInfoAccessToken(accessToken, accessTokenResolver);

  // RFC 6750 §3.1: an expired access token is invalid_token.
  validateUserInfoTokenExpiration(tokenInfo);

  // OIDC Core 1.0 §5.3.1: the token must carry the openid scope (insufficient_scope).
  validateUserInfoScope(tokenInfo);

  // RFC 9068 §4: this UserInfo endpoint must appear in the access token's aud.
  // The token endpoint always stores the UserInfo endpoint URL in aud
  // (buildAccessTokenAudience), so audience validation is on by default for
  // both JWT and opaque tokens. Pass undefined to turn it off.
  validateUserInfoAudience(tokenInfo, `${c.get('config').issuer}/userinfo`);

  return tokenInfo;
}

/**
 * Resolve the claims the token may see: every claim the OP knows about the
 * subject, narrowed to the granted scopes, plus the individually requested
 * claims stored with the token. OIDC Core 1.0 §5.4 / §5.5
 */
export async function resolveUserInfoResponseClaims(
  c: any,
  tokenInfo: AccessTokenInfo,
): Promise<UserInfoResponse> {
  const userClaimsResolver = c.get('userClaimsResolver') ?? defaultUserClaimsResolver;

  // Load every claim the OP knows about the token's subject.
  const userClaims = await resolveUserInfoClaims(tokenInfo, userClaimsResolver);

  // OIDC Core 1.0 §5.4: keep only the claims the granted scopes allow.
  const scopedResponse = filterClaimsByScope(userClaims, tokenInfo.scope);

  // OIDC Core 1.0 §5.5: overlay the individually requested claims that the
  // token endpoint stored with this access token (claims.userinfo members).
  return applyRequestedClaims(scopedResponse, userClaims, tokenInfo.claims);
}

/**
 * Build the response in the format the client registered: a signed JWT when
 * userinfo_signed_response_alg is set, JSON otherwise.
 * OIDC Core 1.0 §5.3.2
 */
export async function buildUserInfoResponse(
  c: any,
  tokenInfo: AccessTokenInfo,
  claims: UserInfoResponse,
): Promise<UserInfoEndpointResponse> {
  const clientResolver = c.get('clientResolver') ?? defaultClientResolver;
  const client = (await clientResolver.findClient(
    tokenInfo.clientId,
  )) as RegisteredClient | null;

  const requestedUserinfoAlg = client?.userinfoSignedResponseAlg;
  if (!requestedUserinfoAlg) {
    return { status: 200, body: claims };
  }

  // OIDC Core 1.0 §5.3.2: when the client registered userinfo_signed_response_alg,
  // the UserInfo Response MUST be a JWS signed with THAT alg (RS256, ES256, ...),
  // not unconditionally RS256. Pick a registered UserInfo signing key whose alg
  // matches the request — mirroring the ID Token key selection. A request whose
  // alg has no matching key is a server configuration error (never silently
  // signed with another alg).
  const config = c.get('config');
  const userinfoSigningKeys = (c.get('userinfoSigningKeys') as SigningKey[] | undefined) ?? [];
  let selectedUserinfoKey: SigningKey;
  try {
    selectedUserinfoKey = selectSigningKeyByAlg(userinfoSigningKeys, requestedUserinfoAlg);
  } catch {
    throw new UserInfoEndpointError({
      status: 500,
      body: {
        error: 'server_error',
        error_description: `No UserInfo signing key registered for alg "${requestedUserinfoAlg}"`,
      },
    });
  }
  const jwt = await generateUserInfoJwt(claims, {
    issuer: config.issuer,
    audience: client.clientId,
    privateKey: selectedUserinfoKey.privateKey,
    keyId: selectedUserinfoKey.keyId,
  });
  return { status: 200, text: jwt, headers: { 'Content-Type': 'application/jwt' } };
}

/**
 * Send a UserInfo answer.
 * RFC 6750 Section 5.2 / OIDC Core 1.0 Section 16.4: UserInfo responses
 * (success and error) expose PII and must not be cached by intermediaries.
 */
export function respondUserInfo(c: any, response: UserInfoEndpointResponse): Response {
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
 * Answer a failure of any step: the Bearer challenge of RFC 6750 §3 for a
 * token the pipeline rejected, the fixed response a step decided, or
 * server_error.
 */
export function respondUserInfoError(c: any, error: unknown): Response {
  if (error instanceof UserInfoEndpointError) {
    return respondUserInfo(c, error.response);
  }
  if (error instanceof UserInfoError) {
    return respondUserInfo(c, {
      status: error.statusCode,
      body: { error: error.error, error_description: error.errorDescription },
      headers: {
        'WWW-Authenticate': `Bearer realm="UserInfo", error="${error.error}", error_description="${error.errorDescription}"`,
      },
    });
  }
  return respondUserInfo(c, { status: 500, body: { error: 'server_error' } });
}

/**
 * UserInfo Endpoint
 * OIDC Core 1.0 Section 5.3
 *
 * The pipeline: each statement below is one step function of this module, in
 * the order of the flow. A step that throws ends in respondUserInfoError().
 */
const handler = async (c: any) => {
  try {
    // [parse-access-token] Read the Bearer token — RFC 6750 §2.1 / §2.2
    const accessToken = await parseUserInfoRequest(c);

    // [resolve-access-token] Resolve and validate the access token — OIDC Core 1.0 §5.3.1 / RFC 6750 §3.1 / RFC 9068 §4
    const tokenInfo = await resolveUserInfoToken(c, accessToken);

    // [resolve-claims] Resolve the claims the token may see — OIDC Core 1.0 §5.4 / §5.5
    const claims = await resolveUserInfoResponseClaims(c, tokenInfo);

    // [build-response] Build the response (JSON or signed JWT) — OIDC Core 1.0 §5.3.2
    const userInfoResponse = await buildUserInfoResponse(c, tokenInfo, claims);

    // [respond] Respond (no-store) — RFC 6750 §5.2
    return respondUserInfo(c, userInfoResponse);
  } catch (error) {
    return respondUserInfoError(c, error);
  }
};

userinfoApp.get('/', handler);
userinfoApp.post('/', handler);
