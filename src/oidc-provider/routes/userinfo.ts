import { Hono } from 'hono';
import {
  resolveUserInfoAccessToken,
  validateUserInfoTokenExpiration,
  validateUserInfoScope,
  validateUserInfoAudience,
  resolveUserInfoClaims,
  filterClaimsByScope,
  applyRequestedClaims,
  generateUserInfoJwt,
  selectSigningKeyByAlg,
  UserInfoError,
  type SigningKey,
} from '@maronn-openid-connect/core';
import {
  accessTokenResolver as defaultAccessTokenResolver,
  userClaimsResolver as defaultUserClaimsResolver,
  clientResolver as defaultClientResolver,
} from '../resolvers.js';
import type { RegisteredClient } from '../config.js';

export const userinfoApp = new Hono<{ Variables: Record<string, any> }>();

/**
 * Extract the access token from the request, supporting:
 * - Authorization: Bearer header (RFC 6750 Section 2.1, REQUIRED)
 * - access_token form body parameter on POST (RFC 6750 Section 2.2, OPTIONAL)
 *
 * Per RFC 6750 Section 2, clients MUST NOT use more than one method per request.
 * URL query parameter (Section 2.3) is intentionally NOT supported (OAuth 2.1 prohibits it).
 */
async function extractAccessToken(c: any): Promise<{ token: string; methodCount: number }> {
  const authHeader = c.req.header('Authorization') ?? '';
  // RFC 7235 Section 2.1: HTTP authentication scheme is case-insensitive.
  // Match the "Bearer" scheme case-insensitively but preserve the token value verbatim.
  const bearerSpaceIndex = authHeader.indexOf(' ');
  const headerToken =
    bearerSpaceIndex !== -1 &&
    authHeader.slice(0, bearerSpaceIndex).toLowerCase() === 'bearer'
      ? authHeader.slice(bearerSpaceIndex + 1)
      : '';

  let bodyToken = '';
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

  const methodCount = (headerToken ? 1 : 0) + (bodyToken ? 1 : 0);
  return { token: headerToken || bodyToken, methodCount };
}

/**
 * UserInfo Endpoint
 * OIDC Core 1.0 Section 5.3
 *
 * Response format is selected by the client metadata `userinfo_signed_response_alg`:
 * - When present (e.g. 'RS256'), respond as a signed JWT with content-type application/jwt
 *   (OIDC Core 1.0 Section 5.3.2).
 * - When absent, respond as application/json.
 */
const handler = async (c: any) => {
  // RFC 6750 Section 5.2 / OIDC Core 1.0 Section 16.4:
  // UserInfo responses (success and error) expose PII and must not be cached
  // by intermediaries. Set the no-cache headers once up-front so every branch
  // below inherits them.
  c.header('Cache-Control', 'no-store');
  c.header('Pragma', 'no-cache');

  let accessToken: string;
  try {
    const { token, methodCount } = await extractAccessToken(c);
    if (methodCount > 1) {
      // RFC 6750 Section 2: clients MUST NOT use more than one method per request.
      c.header('WWW-Authenticate', 'Bearer realm="UserInfo", error="invalid_request"');
      return c.json(
        {
          error: 'invalid_request',
          error_description: 'Multiple access token methods are not allowed',
        },
        400,
      );
    }
    accessToken = token;
    if (!accessToken) {
      // RFC 6750 §3.1: when the request has no authentication information, the
      // challenge omits error/error_description and only identifies the realm.
      c.header('WWW-Authenticate', 'Bearer realm="UserInfo"');
      return c.json(
        { error: 'invalid_token', error_description: 'Access token is required' },
        401,
      );
    }
  } catch {
    return c.json({ error: 'invalid_request' }, 400);
  }

  try {
    const accessTokenResolver =
      c.get('accessTokenResolver') ?? defaultAccessTokenResolver;
    const userClaimsResolver =
      c.get('userClaimsResolver') ?? defaultUserClaimsResolver;
    const clientResolver = c.get('clientResolver') ?? defaultClientResolver;

    // --- UserInfo request pipeline ------------------------------------------
    // Each step below is an independent core function. Delete a call to drop
    // that validation, or insert your own logic between steps. Every step
    // throws UserInfoError, which the catch block below renders as an RFC 6750
    // Bearer challenge.

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

    // Load every claim the OP knows about the token's subject.
    const userClaims = await resolveUserInfoClaims(tokenInfo, userClaimsResolver);

    // OIDC Core 1.0 §5.4: keep only the claims the granted scopes allow.
    const scopedResponse = filterClaimsByScope(userClaims, tokenInfo.scope);

    // OIDC Core 1.0 §5.5: overlay the individually requested claims that the
    // token endpoint stored with this access token (claims.userinfo members).
    const response = applyRequestedClaims(scopedResponse, userClaims, tokenInfo.claims);

    const client = (await clientResolver.findClient(
      tokenInfo.clientId,
    )) as RegisteredClient | null;

    const requestedUserinfoAlg = client?.userinfoSignedResponseAlg;
    if (requestedUserinfoAlg) {
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
        return c.json(
          {
            error: 'server_error',
            error_description: `No UserInfo signing key registered for alg "${requestedUserinfoAlg}"`,
          },
          500,
        );
      }
      const jwt = await generateUserInfoJwt(response, {
        issuer: config.issuer,
        audience: client.clientId,
        privateKey: selectedUserinfoKey.privateKey,
        keyId: selectedUserinfoKey.keyId,
      });
      c.header('Content-Type', 'application/jwt');
      return c.body(jwt);
    }

    return c.json(response);
  } catch (error) {
    if (error instanceof UserInfoError) {
      const status = error.statusCode as 401 | 403;
      c.header(
        'WWW-Authenticate',
        `Bearer realm="UserInfo", error="${error.error}", error_description="${error.errorDescription}"`,
      );
      return c.json(
        { error: error.error, error_description: error.errorDescription },
        status,
      );
    }
    return c.json({ error: 'server_error' }, 500);
  }
};

userinfoApp.get('/', handler);
userinfoApp.post('/', handler);
