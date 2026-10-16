import { Hono } from 'hono';
import {
  type TokenRequestParams,
  extractClientCredentials,
  resolveAuthenticatedTokenClient,
  validateClientAuthMethod,
  verifyClientSecret,
  type TokenClientInfo,
  validateGrantTypeSupported,
  validateClientGrantType,
  resolveAuthorizationCode,
  validateAuthorizationCodeUnused,
  validateAuthorizationCodeClient,
  validateAuthorizationCodeExpiration,
  validateAuthorizationCodeRedirectUri,
  verifyAuthorizationCodePkce,
  consumeAuthorizationCode,
  buildValidatedAuthorizationCodeRequest,
  type ValidatedAuthorizationCodeRequest,
  type ValidatedTokenRequest,
  resolveRefreshToken,
  validateRefreshTokenUnused,
  validateRefreshTokenClient,
  validateRefreshTokenExpiration,
  validateRefreshTokenIdleTimeout,
  validateRefreshTokenSession,
  validateRefreshTokenScope,
  buildValidatedRefreshTokenRequest,
  type ValidatedRefreshTokenRequest,
  selectSigningKeyByAlg,
  type SigningKey,
  TokenError,
  TokenErrorCode,
  clientAllowsRefreshTokenGrant,
  resolveAcrAmr,
  selectPreferredAcr,
  selectRequestedAcrValues,
  type AcrResolver,
  buildAccessTokenAudience,
  buildAccessTokenPayload,
  createJwtAccessTokenIssuer,
  createOpaqueAccessTokenIssuer,
  type AccessTokenIssuer,
  computeAtHash,
  buildIdTokenPayload,
  generateIdToken,
  generateRandomString,
} from '@maronn-openid-connect/core';
import {
  tokenClientResolver as defaultTokenClientResolver,
  authorizationCodeResolver as defaultAuthorizationCodeResolver,
  refreshTokenResolver as defaultRefreshTokenResolver,
  authenticationSessionResolver as defaultAuthenticationSessionResolver,
} from '../resolvers.js';
import {
  authCodeStore as defaultAuthCodeStore,
  accessTokenStore as defaultAccessTokenStore,
  refreshTokenStore as defaultRefreshTokenStore,
} from '../store.js';
import { type RegisteredClient } from '../config.js';

/**
 * Token endpoint (API layer).
 * OIDC Core 1.0 Section 3.1.3 / RFC 6749 Section 4.1.3
 *
 * Every function exported below is one box of the token endpoint's pipeline
 * (`maronn-oidc graph --detail steps --endpoint token`): parse the request,
 * authenticate the client, dispatch the experimental grants, validate the
 * grant, select the keys, resolve the subject, issue and store the tokens,
 * and answer. The handler at the bottom calls them in order; delete a call to
 * drop that step, or insert your own logic between two steps. A box that is
 * left out of a `--flow` document is left out of this file.
 */

/**
 * The form parameters of a token request: the fields OIDC Core / OAuth 2.1
 * name, plus every other field the client posted (the experimental grants
 * read their own parameters from it).
 */
export type TokenRequestBody = TokenRequestParams & Record<string, string>;

/** What the token endpoint answers; respondToken() turns it into HTTP. */
export interface TokenEndpointResponse {
  status: number;
  body: object;
  /** Headers beside the no-store pair every answer carries (e.g. WWW-Authenticate). */
  headers?: Record<string, string>;
}

/**
 * A failure a step answers with a fixed response: a malformed request (400)
 * or a server configuration problem (500). respondTokenError() sends the
 * response as it is.
 */
export class TokenEndpointError extends Error {
  constructor(readonly response: TokenEndpointResponse) {
    const details = response.body as { error?: unknown; error_description?: unknown };
    super(String(details.error_description ?? details.error ?? 'token endpoint error'));
    this.name = 'TokenEndpointError';
  }
}

export const tokenApp = new Hono<{ Variables: Record<string, any> }>();

/**
 * Narrows raw body params to the typed TokenRequestParams.
 * Returns false when the required grant_type field is absent.
 */
function isTokenRequestParams(
  params: unknown,
): params is TokenRequestParams {
  if (typeof params !== 'object' || params === null) return false;
  const p = params as Record<string, unknown>;
  return typeof p['grant_type'] === 'string';
}

/**
 * Returns true when the Content-Type names application/x-www-form-urlencoded.
 * RFC 6749 §4.1.3 / Appendix B / OIDC Core 1.0 §3.1.3.1: the Token Request
 * entity-body MUST be application/x-www-form-urlencoded. Media types are
 * case-insensitive (RFC 9110 §8.3.1) and may carry parameters such as
 * "; charset=UTF-8", so we lowercase and strip everything after the first ';'.
 */
function isFormUrlEncoded(contentType: string): boolean {
  const [mediaType = ''] = contentType.toLowerCase().split(';');
  return mediaType.trim() === 'application/x-www-form-urlencoded';
}

/**
 * Parse the token request: the form body and the Authorization header.
 * RFC 6749 §4.1.3 / §3.2 / OIDC Core 1.0 §3.1.3.1
 *
 * Rejects (TokenEndpointError, 400 invalid_request) a body that is not
 * application/x-www-form-urlencoded, a repeated parameter and a missing
 * grant_type before anything is consumed as token parameters.
 */
export async function parseTokenRequest(
  c: any,
): Promise<{ params: TokenRequestBody; authorization: string }> {
  // RFC 6749 §4.1.3 / OIDC Core 1.0 §3.1.3.1: reject any body that is not
  // application/x-www-form-urlencoded (e.g. multipart/form-data, application/json)
  // before parsing so a non-form payload is never consumed as token parameters.
  const contentType = c.req.header('Content-Type') ?? '';
  if (!isFormUrlEncoded(contentType)) {
    throw new TokenEndpointError({
      status: 400,
      body: { error: 'invalid_request', error_description: 'Token requests must use application/x-www-form-urlencoded' },
    });
  }

  // RFC 6749 §3.2: token endpoint request parameters MUST NOT be repeated.
  // Read the raw form body so URLSearchParams iteration exposes duplicate keys
  // instead of letting parseBody silently keep only the last value.
  const rawBody = await c.req.text();
  const searchParams = new URLSearchParams(rawBody);
  const rawParams: Record<string, string> = {};
  const seen = new Set<string>();
  let duplicateKey: string | undefined;
  for (const [key, value] of searchParams) {
    if (seen.has(key)) {
      duplicateKey = key;
      break;
    }
    seen.add(key);
    rawParams[key] = value;
  }
  const authorization = c.req.header('Authorization') ?? '';

  if (duplicateKey !== undefined) {
    throw new TokenEndpointError({
      status: 400,
      body: { error: 'invalid_request', error_description: `Parameter "${duplicateKey}" must not be repeated` },
    });
  }

  if (!isTokenRequestParams(rawParams)) {
    throw new TokenEndpointError({
      status: 400,
      body: { error: 'invalid_request', error_description: 'Missing required parameter: grant_type' },
    });
  }

  return { params: rawParams, authorization };
}

/**
 * Authenticate the client.
 * OAuth 2.1 §2.3 / OIDC Core 1.0 §9: client_secret_basic / client_secret_post.
 *
 * Each step inside is an independent core function. Replace verifyClientSecret
 * with your own assertion check (e.g. private_key_jwt) without touching the rest.
 */
export async function authenticateTokenClient(
  c: any,
  params: TokenRequestBody,
  authorization: string,
): Promise<{ tokenClient: TokenClientInfo; authenticatedClientId: string }> {
  const tokenClientResolver = c.get('tokenClientResolver') ?? defaultTokenClientResolver;

  // Read the presented credentials and which method was actually used.
  const presentedCredentials = extractClientCredentials({
    params,
    authorizationHeader: authorization,
  });

  // RFC 6749 §5.2: the presented client_id must resolve to a registered client.
  const tokenClient = await resolveAuthenticatedTokenClient(
    presentedCredentials.clientId,
    tokenClientResolver,
  );

  // OIDC Core 1.0 §9: the method used must match the registered
  // token_endpoint_auth_method (blocks auth method downgrade / public-client mixups).
  validateClientAuthMethod(tokenClient, presentedCredentials);

  // OAuth 2.1 §7.4.1: constant-time client_secret comparison.
  await verifyClientSecret(tokenClient, presentedCredentials.clientSecret);

  return { tokenClient, authenticatedClientId: presentedCredentials.clientId };
}

/**
 * Validate grant_type: offered by this OP, and allowed for this client.
 * RFC 6749 §5.2 (unsupported_grant_type / unauthorized_client)
 */
export function validateTokenGrantType(
  params: TokenRequestParams,
  tokenClient: TokenClientInfo,
): 'authorization_code' | 'refresh_token' {
  // RFC 6749 §5.2: is the grant_type offered by this OP at all?
  // (defaults to ['authorization_code', 'refresh_token'])
  const grantType = validateGrantTypeSupported(params.grant_type);

  // RFC 6749 §5.2: per-client grant_type authorization (unauthorized_client).
  validateClientGrantType(tokenClient, grantType);

  return grantType;
}

/**
 * Validate the authorization_code grant.
 * OAuth 2.1 §4.1.2 / RFC 7636 / OIDC Core 1.0 §3.1.3.2
 *
 * Each security rule is a separate core call so it can be removed, replaced,
 * or surrounded with experiment-specific logic.
 */
export async function validateAuthorizationCodeGrant(
  c: any,
  params: TokenRequestParams,
  authenticatedClientId: string,
): Promise<ValidatedAuthorizationCodeRequest> {
  const authorizationCodeResolver = c.get('authCodeResolver') ?? defaultAuthorizationCodeResolver;

  // Resolve the presented authorization code and retain the non-optional code.
  const { code, authorizationCode } = await resolveAuthorizationCode(
    params,
    authorizationCodeResolver,
  );

  // OAuth 2.1 §4.1.2: reject reuse and revoke tokens from the compromised grant.
  await validateAuthorizationCodeUnused(
    authorizationCode,
    authorizationCodeResolver,
  );

  // Bind the authorization code to the authenticated client and its lifetime.
  validateAuthorizationCodeClient(authorizationCode, authenticatedClientId);
  validateAuthorizationCodeExpiration(authorizationCode);

  // OIDC Core 1.0 §3.1.3.2: bind the token request redirect_uri.
  validateAuthorizationCodeRedirectUri(
    authorizationCode,
    params.redirect_uri,
  );

  // RFC 7636: validate the S256 verifier when the code carries a PKCE binding.
  const codeVerified = await verifyAuthorizationCodePkce(
    authorizationCode,
    params.code_verifier,
  );

  // Mark used (do not physically delete) so a later replay remains detectable.
  await consumeAuthorizationCode(code, authorizationCodeResolver);

  return buildValidatedAuthorizationCodeRequest(
    code,
    authorizationCode,
    authenticatedClientId,
    codeVerified,
  );
}

/**
 * Validate the refresh_token grant.
 * OAuth 2.1 §4.3.1 / RFC 6749 §6
 *
 * Each security rule is a separate core call so it can be removed, replaced,
 * or surrounded with experiment-specific logic.
 */
export async function validateRefreshTokenGrant(
  c: any,
  params: TokenRequestParams,
  authenticatedClientId: string,
): Promise<ValidatedRefreshTokenRequest> {
  const refreshTokenResolver = c.get('refreshTokenResolver') ?? defaultRefreshTokenResolver;
  // online refresh token の束縛先セッションを sessionId から引く。差し替えると
  // 「セッションが生きているか」の判定そのものを差し替えられる。
  const authenticationSessionResolver =
    c.get('authenticationSessionResolver') ?? defaultAuthenticationSessionResolver;

  // Resolve the presented refresh token and retain its stored grant context.
  const { refreshTokenInfo } = await resolveRefreshToken(
    params,
    refreshTokenResolver,
  );

  // OAuth 2.1 §4.3.1: reject rotation reuse and revoke the token family.
  await validateRefreshTokenUnused(refreshTokenInfo, refreshTokenResolver);

  // Bind the refresh token to the authenticated client.
  validateRefreshTokenClient(refreshTokenInfo, authenticatedClientId);

  // Absolute lifetime: expiresAt <= now is expired.
  validateRefreshTokenExpiration(refreshTokenInfo);

  // Optional inactivity policy. Replace undefined with your timeout in seconds
  // to enable it, or remove this step if your experiment has no idle lifetime.
  validateRefreshTokenIdleTimeout(refreshTokenInfo, undefined);

  // online refresh token（sessionId を持つ RT）は、束縛先のログインセッションが
  // 生きている間だけ使える。ログアウト・別ユーザーでの再ログインでセッションが
  // 消えれば invalid_grant になる。offline_access が付与された RT は sessionId を
  // 持たないため、このステップを素通りしてログアウト後も使い続けられる。
  await validateRefreshTokenSession(refreshTokenInfo, authenticationSessionResolver);

  // RFC 6749 §6: requested scope may only narrow the original grant.
  const effectiveScope = validateRefreshTokenScope(
    params.scope,
    refreshTokenInfo.scope,
  );

  return buildValidatedRefreshTokenRequest(
    refreshTokenInfo,
    authenticatedClientId,
    effectiveScope,
  );
}

/**
 * Select the signing keys: the first registered key signs the access token
 * (SigningKeyProvider contract); the ID Token key is picked by the alg the
 * client registered as id_token_signed_response_alg (OIDC Dynamic Client
 * Registration 1.0 §2; RS256 when unregistered). No matching key is a server
 * configuration error (TokenEndpointError, 500 server_error).
 */
export async function selectTokenSigningKeys(
  c: any,
  authenticatedClientId: string,
): Promise<{ signingKey: SigningKey; idTokenSigningKey: SigningKey }> {
  const tokenClientResolver = c.get('tokenClientResolver') ?? defaultTokenClientResolver;
  // The first registered key signs new tokens (SigningKeyProvider contract).
  const signingKey: SigningKey = c.get('signingKeys')[0];

  // T-022: pick an ID Token signing key whose alg matches the client's
  // id_token_signed_response_alg (OIDC Dynamic Client Registration §2).
  // - 未指定クライアントは OIDC 仕様デフォルトの RS256 で扱う。
  // - alg に合う鍵が登録されていなければサーバ設定エラー (server_error)。
  const idTokenSigningKeys = (c.get('idTokenSigningKeys') as SigningKey[] | undefined) ?? [];
  const registeredClient = (await tokenClientResolver.findClient(authenticatedClientId)) as
    | RegisteredClient
    | null;
  const requestedIdTokenAlg = registeredClient?.idTokenSignedResponseAlg;
  let idTokenSigningKey: SigningKey;
  try {
    idTokenSigningKey = selectSigningKeyByAlg(idTokenSigningKeys, requestedIdTokenAlg);
  } catch {
    throw new TokenEndpointError({
      status: 500,
      body: {
        error: 'server_error',
        error_description: `No ID Token signing key registered for alg "${requestedIdTokenAlg ?? 'RS256'}"`,
      },
    });
  }
  return { signingKey, idTokenSigningKey };
}

/**
 * Resolve the subject, auth_time and nonce the tokens are issued for: from the
 * authorization code record (authorization_code), or from the refresh token's
 * stored grant (refresh_token).
 * OIDC Core 1.0 §12.2
 */
export async function resolveTokenSubject(
  c: any,
  validatedRequest: ValidatedTokenRequest,
): Promise<{ subject: string; authTime: number | undefined; nonce: string | undefined }> {
  if (validatedRequest.grantType === 'authorization_code') {
    const authCodeStore = c.get('authCodeStore') ?? defaultAuthCodeStore;
    const authCode = await authCodeStore.get(validatedRequest.code);
    if (!authCode?.subject || !authCode.authTime) {
      throw new TokenError(
        TokenErrorCode.InvalidGrant,
        'Authorization code missing required subject context',
      );
    }
    return { subject: authCode.subject, authTime: authCode.authTime, nonce: validatedRequest.nonce };
  }
  // refresh_token grant
  // OIDC Core 1.0 §12.2: the re-issued ID Token retains iss/sub/aud/exp/iat/
  // auth_time/azp/acr/amr — nonce is NOT in that list. nonce binds an
  // Authentication Request to its ID Token (§2); a refresh has no such request,
  // so carrying the old nonce adds no replay protection. Major OPs (Google,
  // Auth0) omit it on refresh, so we omit it here by default. auth_time is
  // still preserved per §12.1.
  return { subject: validatedRequest.subject, authTime: validatedRequest.authTime, nonce: undefined };
}

/** Whether, and how, a refresh token is issued with this response. */
export interface RefreshTokenDecision {
  /** The grant holds offline_access: the refresh token outlives the login session. */
  grantHasOfflineAccess: boolean;
  /** The login session an online refresh token is bound to (undefined: not bound). */
  boundSessionId: string | undefined;
  /** Whether a refresh token is minted at all. */
  issueRefreshToken: boolean;
}

/**
 * Decide whether a refresh token is issued, and whether it is bound to the
 * login session (online) or outlives it (offline_access).
 * OIDC Core 1.0 §11 / RFC 9700 §4.14 / RFC 6749 §6
 */
export function decideRefreshTokenIssuance(
  c: any,
  tokenClient: TokenClientInfo,
  validatedRequest: ValidatedTokenRequest,
): RefreshTokenDecision {
  const config = c.get('config');

  // RFC 7591 §2 / OIDC Dynamic Client Registration 1.0 §2: grant_types の既定は
  // ["authorization_code"]。refresh_token を登録していないクライアントへ RT を渡しても、
  // 次に grant_type=refresh_token を出した瞬間 validateClientGrantType が
  // unauthorized_client で拒否する。一度も使えない長期資格情報を保存させるだけなので
  // （RFC 9700 §4.14）、登録が無ければ発行しない。
  const clientAllowsRefreshGrant = clientAllowsRefreshTokenGrant(tokenClient);

  // RFC 6749 §6 / OIDC Core 1.0 §11: refresh 時の scope 縮小は当該リクエストの access token /
  // ID Token の権限縮小として扱い、refresh token rotation の可否とは切り離す。rotation 可否は
  // 「元の grant が offline_access を持っていたか」で判断する。
  // - authorization_code grant: 今回付与された scope に offline_access があるか。
  // - refresh_token grant: 元 refresh token の grant が offline_access を持っていたか
  //   (validatedRequest.hadOfflineAccess)。縮小後 scope から offline_access を落としても
  //   元 grant の権限は失われないため rotation を継続する。
  const grantHasOfflineAccess =
    clientAllowsRefreshGrant &&
    (validatedRequest.grantType === 'refresh_token'
      ? validatedRequest.hadOfflineAccess
      : validatedRequest.scope.includes('offline_access'));

  // online refresh token の束縛先セッション。
  // OIDC Core 1.0 §11 は offline_access を「End-User が居ない（not logged in）ときにも
  // 使える Refresh Token」と定義したうえで、Refresh Token の利用がその用途に限られない
  // ことも明示している（"The Authorization Server MAY grant Refresh Tokens in other
  // contexts"）。この OP はその other contexts を online refresh token として実装し、
  // ログインセッションへ束縛する。offline_access がある grant は束縛しない。
  // - authorization_code grant: 認可コードが持つ sessionId（ログイン時に確立したもの）。
  // - refresh_token grant: 元 RT の束縛をそのまま引き継ぎ、rotation で外れないようにする。
  const boundSessionId = grantHasOfflineAccess ? undefined : validatedRequest.sessionId;

  // 束縛先が分からなければ online refresh token は発行しない。ブラウザセッションを
  // 持たない経路（device authorization grant）が該当する。ログアウトで止まる保証を
  // 付けられない RT を配らないための fail-closed。
  const issueRefreshToken =
    clientAllowsRefreshGrant &&
    (grantHasOfflineAccess ||
      (config.onlineRefreshTokenEnabled && boundSessionId !== undefined));

  return { grantHasOfflineAccess, boundSessionId, issueRefreshToken };
}

/**
 * Resolve the acr / amr the tokens carry: the ID Token gets both, and the
 * access token gets the acr, so a resource server can tell how the End-User
 * authenticated (RFC 9068 §2.2.1).
 * OIDC Core 1.0 §2 / §3.1.2.1 / §12.1
 *
 * - authorization_code: the acrResolver option of the app decides from the
 *   acr values the client requested (acr_values, or claims.id_token.acr.values,
 *   OIDC Core 1.0 §5.5.1.1). Without an acrResolver the tokens carry the most
 *   preferred requested value and no amr, and no acr when none was requested.
 * - refresh_token: the acr / amr of the first authentication are kept
 *   (OIDC Core 1.0 §12.1); the resolver is not asked again.
 */
export async function resolveTokenAcrAmr(
  c: any,
  input: { subject: string; validatedRequest: ValidatedTokenRequest },
): Promise<{ acr: string | undefined; amr: string[] | undefined }> {
  const { subject, validatedRequest } = input;
  if (validatedRequest.grantType === 'refresh_token') {
    return { acr: validatedRequest.acr, amr: validatedRequest.amr };
  }

  // The requested acr values, in order of preference.
  const requestedAcrValues = selectRequestedAcrValues(validatedRequest.acrValues, validatedRequest.claims);

  const acrResolver = c.get('acrResolver') as AcrResolver | undefined;
  if (acrResolver !== undefined) {
    const { acr, amr } = await resolveAcrAmr({
      subject,
      clientId: validatedRequest.clientId,
      requestedAcrValues,
      acrResolver,
    });
    return { acr, amr };
  }

  // No acrResolver: the tokens carry the most preferred requested acr as it
  // is. This trusts the request; pass an acrResolver that reports the acr your
  // login actually satisfied before a resource server relies on it.
  return { acr: selectPreferredAcr(requestedAcrValues), amr: undefined };
}

/**
 * Issue the access token: decide its audience, build the RFC 9068 payload
 * and sign it (JWT) or mint an opaque reference, as config.accessTokenFormat says.
 * RFC 9068 §2.2 / §2.2.1 / §3
 */
export async function issueAccessToken(
  c: any,
  input: {
    signingKey: SigningKey;
    subject: string;
    validatedRequest: ValidatedTokenRequest;
    /** One timestamp for the whole response so the tokens and the stored records agree on iat / exp. */
    issuedAt: number;
    /** The acr of the authentication (the ID Token carries the same); undefined leaves the claim out. */
    acr: string | undefined;
  },
): Promise<{ accessToken: string; accessTokenPayload: { jti?: string }; audience: string[] }> {
  const { signingKey, subject, validatedRequest, issuedAt, acr } = input;
  const config = c.get('config');

  // Choose access token issuer based on config (default: JWT).
  // Opaque tokens are recommended when immediate revocation is required,
  // since the resource server can call the introspection endpoint instead
  // of self-validating a JWT.
  const accessTokenIssuer: AccessTokenIssuer =
    config.accessTokenFormat === 'opaque'
      ? createOpaqueAccessTokenIssuer()
      : createJwtAccessTokenIssuer();

  // アクセストークンの audience を決定する（合成ポリシーは core の buildAccessTokenAudience に集約）。
  // RFC 9068 §3: JWT access token の aud は非空でなければならない。
  // このアクセストークンは常に OP 自身の UserInfo エンドポイントで使用できるため、UserInfo
  // エンドポイント（discovery が広告する userinfo_endpoint と同じ URL）を aud の恒久メンバとして
  // 必ず含める。resource 指定（validatedRequest.audience）があれば末尾に追加し、UserInfo
  // エンドポイントを取り除くことはしない。重複は除去される。
  // refresh では保存済み aud（既に UserInfo を含む）を引き継ぐため、再計算しても同一集合になる。
  const audience = buildAccessTokenAudience({
    userInfoEndpoint: `${config.issuer}/userinfo`,
    requested: validatedRequest.audience,
    issuer: config.issuer,
  });

  // RFC 9068 §2.2: iss / sub / aud / exp / iat / scope / client_id, and the
  // acr of the authentication (§2.2.1) when there is one.
  // Add access token claims here before the payload is signed.
  const accessTokenPayload = buildAccessTokenPayload({
    issuer: config.issuer,
    subject,
    clientId: validatedRequest.clientId,
    scope: validatedRequest.scope,
    audience,
    expiresIn: config.accessTokenExpiresIn,
    issuedAt,
    acr,
  });

  // JWT or opaque, chosen above from config.accessTokenFormat.
  const accessToken = await accessTokenIssuer.issue({
    payload: accessTokenPayload,
    privateKey: signingKey.privateKey,
    keyId: signingKey.keyId,
  });

  return { accessToken, accessTokenPayload, audience };
}

/**
 * Issue the ID Token when the grant carries the openid scope: at_hash binds
 * it to the access token (§3.1.3.6), and acr / amr are the ones
 * resolveTokenAcrAmr() settled on (kept from the first authentication on a
 * refresh, §12.1).
 * OIDC Core 1.0 §3.1.3.6 / §12.1
 */
export async function issueIdToken(
  c: any,
  input: {
    idTokenSigningKey: SigningKey;
    accessToken: string;
    subject: string;
    authTime: number | undefined;
    nonce: string | undefined;
    validatedRequest: ValidatedTokenRequest;
    issuedAt: number;
    acr: string | undefined;
    amr: string[] | undefined;
  },
): Promise<string | undefined> {
  const { idTokenSigningKey, accessToken, subject, authTime, nonce, validatedRequest, issuedAt, acr, amr } = input;
  const config = c.get('config');

  // OIDC Core 1.0 §12: refresh_token grant でも id_token は MAY。
  // openid scope を持つ場合は §12.1 に従い初回認証時と同じ auth_time / acr / amr / azp で再発行する。
  // （§12.2 は nonce を再発行 ID Token の保持クレームに挙げないため nonce は refresh では undefined）
  if (!validatedRequest.scope.includes('openid')) {
    return undefined;
  }

  // OIDC Core 1.0 §3.1.3.6: at_hash binds the ID Token to this access token.
  // The hash function follows the ID Token signing alg.
  const atHash = await computeAtHash(accessToken, idTokenSigningKey.privateKey);

  const idTokenPayload = buildIdTokenPayload({
    issuer: config.issuer,
    subject,
    clientId: validatedRequest.clientId,
    scope: validatedRequest.scope,
    expiresIn: config.idTokenExpiresIn,
    issuedAt,
    atHash,
    nonce,
    authTime,
    acr,
    amr,
  });

  // Add your own ID Token claims here, e.g.:
  //   idTokenPayload.tenant_id = await lookupTenant(subject);

  return generateIdToken({
    payload: idTokenPayload,
    privateKey: idTokenSigningKey.privateKey,
    keyId: idTokenSigningKey.keyId,
  });
}

/**
 * Store the access token record for the UserInfo, introspection and
 * revocation endpoints.
 * RFC 7662 §2.2 / RFC 9068 §2.2 / OIDC Core 1.0 §5.5 / RFC 9470 §6.2
 *
 * iat / nbf / audience / issuer / acr are kept so introspection can echo
 * them. grantId binds this token to the original authorization grant so it can
 * be revoked together with sibling tokens on code reuse (OAuth 2.1 §4.1.2).
 */
export async function persistAccessToken(
  c: any,
  input: {
    accessToken: string;
    accessTokenPayload: { jti?: string };
    subject: string;
    validatedRequest: ValidatedTokenRequest;
    issuedAt: number;
    audience: string[];
    acr: string | undefined;
  },
): Promise<void> {
  const { accessToken, accessTokenPayload, subject, validatedRequest, issuedAt, audience, acr } = input;
  const accessTokenStore = c.get('accessTokenStore') ?? defaultAccessTokenStore;
  const config = c.get('config');

  await accessTokenStore.set(accessToken, {
    sub: subject,
    clientId: validatedRequest.clientId,
    scope: validatedRequest.scope,
    expiresAt: issuedAt + config.accessTokenExpiresIn,
    grantId: validatedRequest.grantId,
    iat: issuedAt,
    // RFC 7519 §4.1.5 / RFC 7662 §2.2: persist nbf (= iat) for JWT and opaque
    // tokens alike so introspection reports a not-yet-valid token inactive and
    // can echo nbf. The JWT issuer emits the same nbf = iat inside the token.
    nbf: issuedAt,
    audience,
    issuer: config.issuer,
    // RFC 9068 §2.2 / RFC 7662 §2.2: persist the token identifier core minted
    // for this issuance so introspection can echo jti. It is also what makes
    // two same-second issuances distinct token strings (RS256 is deterministic),
    // so this store key never collides across grants.
    jti: accessTokenPayload.jti,
    // OIDC Core 1.0 §5.5: persist the authorization request's claims parameter
    // so the UserInfo endpoint can honor claims.userinfo members (e.g.
    // {"userinfo":{"name":{"essential":true}}}) independently of scope.
    claims: validatedRequest.grantType === 'authorization_code' ? validatedRequest.claims : undefined,
    // RFC 9068 §2.2.1 / RFC 9470 §6.2: the acr the token was issued with, so
    // introspection reports it for an opaque token too.
    acr,
  });
}

/**
 * Mint the refresh token the decision asked for and store its record for
 * rotation. Returns undefined when none is issued.
 * OAuth 2.1 §4.3.1 / §6.1 / OIDC Core 1.0 §12.1
 *
 * The same grantId / audience / authTime / nonce / acr / amr / azp is propagated
 * through rotations so descendants can be revoked on code reuse, the audience
 * never expands, and the ID Token a refresh re-issues keeps the values of the
 * first authentication (OIDC Core 1.0 §12.1).
 */
export async function issueRefreshToken(
  c: any,
  input: {
    decision: RefreshTokenDecision;
    subject: string;
    authTime: number | undefined;
    nonce: string | undefined;
    validatedRequest: ValidatedTokenRequest;
    issuedAt: number;
    audience: string[];
    acr: string | undefined;
    amr: string[] | undefined;
  },
): Promise<string | undefined> {
  const { decision, subject, authTime, nonce, validatedRequest, issuedAt, audience, acr, amr } = input;
  if (!decision.issueRefreshToken) return undefined;

  const refreshTokenStore = c.get('refreshTokenStore') ?? defaultRefreshTokenStore;
  const config = c.get('config');
  const refreshToken = generateRandomString(32);

  // authTime はここで必ず確定する: authorization_code 経由は authCode.authTime、
  // refresh_token 経由は validatedRequest.authTime。
  if (authTime === undefined) {
    throw new TokenError(
      TokenErrorCode.InvalidGrant,
      'authTime is required to issue a refresh token',
    );
  }
  // OAuth 2.1 §6.1: refresh token は initial issuance からの absolute lifetime のみで失効する。
  // rotation を跨いで originalIssuedAt を引き継ぎ、expiresAt はそこからの絶対的な期限で固定する。
  // sliding expiry は持たないため、リフレッシュを繰り返しても失効時刻は前に進まず、
  // 漏洩 RT の長期 abuse を防ぐ。
  // - authorization_code grant: 今回が初回発行なので originalIssuedAt = issuedAt。
  // - refresh_token grant: 元 RT の originalIssuedAt をそのまま引き継ぐ。
  const originalIssuedAt =
    validatedRequest.grantType === 'refresh_token'
      ? validatedRequest.originalIssuedAt
      : issuedAt;
  const refreshTokenExpiresAt = originalIssuedAt + config.refreshTokenAbsoluteLifetime;
  // RFC 6749 §6: 縮小後 scope（validatedRequest.scope）から offline_access が落ちても、
  // grant が offline_access を持つ限り次回以降の rotation を継続できるよう、永続化する
  // refresh token の scope には offline_access を保持する。access token は
  // validatedRequest.scope をそのまま使うため、当該リクエストの権限は縮小されたままになる。
  const refreshTokenScope =
    decision.grantHasOfflineAccess && !validatedRequest.scope.includes('offline_access')
      ? [...validatedRequest.scope, 'offline_access']
      : validatedRequest.scope;
  await refreshTokenStore.set(refreshToken, {
    subject,
    clientId: validatedRequest.clientId,
    scope: refreshTokenScope,
    expiresAt: refreshTokenExpiresAt,
    originalIssuedAt,
    used: false,
    grantId: validatedRequest.grantId,
    iat: issuedAt,
    issuer: config.issuer,
    audience,
    authTime,
    nonce,
    // OIDC Core 1.0 §12.1: refresh で再発行する ID Token は初回認証時の acr / amr を保持する。
    // - authorization_code grant: resolveTokenAcrAmr() が決めた値をそのまま永続化する。
    // - refresh_token grant: 既に保存済みの値を引き継ぐ（resolver は呼ばれていない）。
    acr: validatedRequest.grantType === 'refresh_token' ? validatedRequest.acr : acr,
    amr: validatedRequest.grantType === 'refresh_token' ? validatedRequest.amr : amr,
    azp: validatedRequest.grantType === 'refresh_token' ? validatedRequest.azp : undefined,
    // online refresh token の束縛。undefined なら offline refresh token として
    // セッションから独立し、ログアウト後も使える。
    sessionId: decision.boundSessionId,
  });

  return refreshToken;
}

/**
 * Rotation: revoke the refresh token the request presented, now that its
 * successor is stored. Always this order, so a failure never leaves the
 * End-User without a refresh token.
 * OAuth 2.1 §4.3.1
 */
export async function revokeRotatedRefreshToken(
  c: any,
  params: TokenRequestParams,
  validatedRequest: ValidatedTokenRequest,
): Promise<void> {
  if (validatedRequest.grantType !== 'refresh_token' || !params.refresh_token) return;
  const refreshTokenResolver = c.get('refreshTokenResolver') ?? defaultRefreshTokenResolver;
  await refreshTokenResolver.revokeRefreshToken(params.refresh_token);
}

/**
 * Build the token response body.
 * OIDC Core 1.0 §3.1.3.3 / RFC 6749 §5.1
 */
export function buildTokenResponse(
  c: any,
  input: {
    accessToken: string;
    idToken: string | undefined;
    refreshToken?: string;
    validatedRequest: ValidatedTokenRequest;
  },
): TokenEndpointResponse {
  const { accessToken, idToken, refreshToken, validatedRequest } = input;
  const config = c.get('config');
  return {
    status: 200,
    body: {
      access_token: accessToken,
      token_type: 'Bearer' as const,
      expires_in: config.accessTokenExpiresIn,
      id_token: idToken,
      scope: validatedRequest.scope.join(' '),
      refresh_token: refreshToken,
    },
  };
}

/**
 * Send a token endpoint answer.
 * RFC 6749 §5.1 / §5.2: token responses and error responses MUST NOT be cached.
 */
export function respondToken(c: any, response: TokenEndpointResponse): Response {
  c.header('Cache-Control', 'no-store');
  c.header('Pragma', 'no-cache');
  for (const [name, value] of Object.entries(response.headers ?? {})) {
    c.header(name, value);
  }
  return c.json(response.body, response.status);
}

/**
 * Answer a failure of any step with the OAuth error response.
 * RFC 6749 §5.2 / RFC 6750 §3 / OAuth 2.1 §5.2
 */
export function respondTokenError(c: any, error: unknown): Response {
  // A step already decided the whole response (malformed request, server
  // configuration problem): send it as it is.
  if (error instanceof TokenEndpointError) {
    return respondToken(c, error.response);
  }
  if (error instanceof TokenError) {
    // RFC 6750 Section 3 / OAuth 2.1 Section 5.2: 401 responses include WWW-Authenticate
    return respondToken(c, {
      status: error.statusCode,
      body: { error: error.error, error_description: error.errorDescription },
      headers: error.wwwAuthenticate ? { 'WWW-Authenticate': error.wwwAuthenticate } : undefined,
    });
  }
  // RFC 6749 Section 5.2: server_error responses MUST NOT be cached either.
  return respondToken(c, { status: 500, body: { error: 'server_error' } });
}

/**
 * Token Endpoint
 * OIDC Core 1.0 Section 3.1.3
 *
 * The pipeline: each statement below is one step function of this module, in
 * the order of the flow. A step that throws ends in respondTokenError().
 */
tokenApp.post('/', async (c) => {
  try {
    // [parse-request] Parse the token request — RFC 6749 §4.1.3 / §3.2
    const { params, authorization } = await parseTokenRequest(c);

    // [authenticate-client] Authenticate the client — OAuth 2.1 §2.3 / OIDC Core 1.0 §9
    const { tokenClient, authenticatedClientId } = await authenticateTokenClient(c, params, authorization);

    // [validate-grant-type] Validate grant_type — RFC 6749 §5.2
    const grantType = validateTokenGrantType(params, tokenClient);

    // [validate-authorization-code-grant] Validate the authorization_code grant — OAuth 2.1 §4.1.2 / RFC 7636 / OIDC Core 1.0 §3.1.3.2
    const validatedRequest: ValidatedTokenRequest =
      grantType === 'refresh_token'
        ? await validateRefreshTokenGrant(c, params, authenticatedClientId)
        : await validateAuthorizationCodeGrant(c, params, authenticatedClientId);

    // [select-signing-keys] Select the signing keys — OIDC Dynamic Client Registration 1.0 §2 (id_token_signed_response_alg)
    const { signingKey, idTokenSigningKey } = await selectTokenSigningKeys(c, authenticatedClientId);

    // [resolve-subject] Resolve the subject, auth_time and nonce — OIDC Core 1.0 §12.2
    const { subject, authTime, nonce } = await resolveTokenSubject(c, validatedRequest);

    // [decide-refresh-token-issuance] Decide whether a refresh token is issued — OIDC Core 1.0 §11 / RFC 9700 §4.14
    const refreshTokenDecision = decideRefreshTokenIssuance(c, tokenClient, validatedRequest);

    // [resolve-acr-amr] Resolve the acr / amr the tokens carry — OIDC Core 1.0 §3.1.2.1 / §12.1 / RFC 9068 §2.2.1
    const { acr, amr } = await resolveTokenAcrAmr(c, { subject, validatedRequest });

    // [issue-access-token] Issue the access token — RFC 9068 §2.2 / §2.2.1 / §3
    // One timestamp for the whole response so the issued tokens and the stored
    // token metadata agree on iat / exp.
    const issuedAt = Math.floor(Date.now() / 1000);
    const { accessToken, accessTokenPayload, audience } = await issueAccessToken(c, { signingKey, subject, validatedRequest, issuedAt, acr });

    // [issue-id-token] Issue the ID Token — OIDC Core 1.0 §3.1.3.6 / §12.1
    const idToken = await issueIdToken(c, { idTokenSigningKey, accessToken, subject, authTime, nonce, validatedRequest, issuedAt, acr, amr });

    // [persist-access-token] Store the access token record — RFC 7662 §2.2 / OIDC Core 1.0 §5.5 / RFC 9470 §6.2
    await persistAccessToken(c, { accessToken, accessTokenPayload, subject, validatedRequest, issuedAt, audience, acr });

    // [issue-refresh-token] Mint and store the refresh token — OAuth 2.1 §4.3.1 / §6.1
    const refreshToken = await issueRefreshToken(c, {
      decision: refreshTokenDecision,
      subject,
      authTime,
      nonce,
      validatedRequest,
      issuedAt,
      audience,
      acr,
      amr,
    });

    // [revoke-rotated-refresh-token] Revoke the presented refresh token (rotation) — OAuth 2.1 §4.3.1
    await revokeRotatedRefreshToken(c, params, validatedRequest);

    // [build-token-response] Build the token response body — OIDC Core 1.0 §3.1.3.3 / RFC 6749 §5.1
    const tokenResponse = buildTokenResponse(c, { accessToken, idToken, refreshToken, validatedRequest });

    // [respond] Respond (no-store) — RFC 6749 §5.1
    return respondToken(c, tokenResponse);
  } catch (error) {
    return respondTokenError(c, error);
  }
});
