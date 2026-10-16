import { Hono } from 'hono';
import {
  validateGrantTypeSupported,
  resolveAuthenticatedTokenClient,
  validateClientGrantType,
  resolveAuthorizationCode,
  validateAuthorizationCodeUnused,
  validateAuthorizationCodeClient,
  validateAuthorizationCodeExpiration,
  validateAuthorizationCodeRedirectUri,
  verifyAuthorizationCodePkce,
  consumeAuthorizationCode,
  buildValidatedAuthorizationCodeRequest,
  resolveRefreshToken,
  validateRefreshTokenUnused,
  validateRefreshTokenClient,
  validateRefreshTokenExpiration,
  validateRefreshTokenIdleTimeout,
  validateRefreshTokenScope,
  validateRefreshTokenSession,
  clientAllowsRefreshTokenGrant,
  buildValidatedRefreshTokenRequest,
  buildAccessTokenPayload,
  computeAtHash,
  resolveAcrAmr,
  buildIdTokenPayload,
  generateIdToken,
  generateRandomString,
  buildAccessTokenAudience,
  extractClientCredentials,
  validateClientAuthMethod,
  verifyClientSecret,
  createJwtAccessTokenIssuer,
  createOpaqueAccessTokenIssuer,
  selectSigningKeyByAlg,
  TokenError,
  TokenErrorCode,
  type AccessTokenIssuer,
  type AcrResolver,
  type SigningKey,
  type TokenRequestParams,
  type ValidatedTokenRequest,
} from '@maronn-openid-connect/core';
import {
  tokenClientResolver as defaultTokenClientResolver,
  authorizationCodeResolver as defaultAuthorizationCodeResolver,
  refreshTokenResolver as defaultRefreshTokenResolver,
  authenticationSessionResolver as defaultAuthenticationSessionResolver,
} from '../resolvers.js';
import {
  accessTokenStore as defaultAccessTokenStore,
  authCodeStore as defaultAuthCodeStore,
  refreshTokenStore as defaultRefreshTokenStore,
} from '../store.js';
import type { RegisteredClient } from '../config.js';

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
 * Token Endpoint
 * OIDC Core 1.0 Section 3.1.3
 */
tokenApp.post('/', async (c) => {
  // RFC 6749 §4.1.3 / OIDC Core 1.0 §3.1.3.1: reject any body that is not
  // application/x-www-form-urlencoded (e.g. multipart/form-data, application/json)
  // before parsing so a non-form payload is never consumed as token parameters.
  const contentType = c.req.header('Content-Type') ?? '';
  if (!isFormUrlEncoded(contentType)) {
    // RFC 6749 Section 5.2: error responses MUST set Cache-Control: no-store / Pragma: no-cache.
    c.header('Cache-Control', 'no-store');
    c.header('Pragma', 'no-cache');
    return c.json({ error: 'invalid_request', error_description: 'Token requests must use application/x-www-form-urlencoded' }, 400);
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
    // RFC 6749 Section 5.2: error responses MUST set Cache-Control: no-store / Pragma: no-cache.
    c.header('Cache-Control', 'no-store');
    c.header('Pragma', 'no-cache');
    return c.json({ error: 'invalid_request', error_description: `Parameter "${duplicateKey}" must not be repeated` }, 400);
  }

  if (!isTokenRequestParams(rawParams)) {
    // RFC 6749 Section 5.2: error responses MUST set Cache-Control: no-store / Pragma: no-cache.
    c.header('Cache-Control', 'no-store');
    c.header('Pragma', 'no-cache');
    return c.json({ error: 'invalid_request', error_description: 'Missing required parameter: grant_type' }, 400);
  }

  const params = rawParams;

  try {
    const tokenClientResolver = c.get('tokenClientResolver') ?? defaultTokenClientResolver;
    const authorizationCodeResolver =
      c.get('authCodeResolver') ?? defaultAuthorizationCodeResolver;
    const refreshTokenResolver =
      c.get('refreshTokenResolver') ?? defaultRefreshTokenResolver;
    // online refresh token の束縛先セッションを sessionId から引く。差し替えると
    // 「セッションが生きているか」の判定そのものを差し替えられる。
    const authenticationSessionResolver =
      c.get('authenticationSessionResolver') ?? defaultAuthenticationSessionResolver;
    const authCodeStore = c.get('authCodeStore') ?? defaultAuthCodeStore;
    const accessTokenStore = c.get('accessTokenStore') ?? defaultAccessTokenStore;
    const refreshTokenStore = c.get('refreshTokenStore') ?? defaultRefreshTokenStore;

    // --- Client authentication pipeline -------------------------------------
    // OAuth 2.1 §2.3 / OIDC Core 1.0 §9: client_secret_basic / client_secret_post.
    // Each step below is an independent core function. Replace
    // verifyClientSecret with your own assertion check (e.g. private_key_jwt)
    // without touching the rest.

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

    const authenticatedClientId = presentedCredentials.clientId;

    // --- Token request validation pipeline --------------------------------
    // Each step below is an independent core function. Delete a call to drop
    // that validation, or insert your own logic between steps.

    // RFC 6749 §5.2: is the grant_type offered by this OP at all?
    // (defaults to ['authorization_code', 'refresh_token'])
    const grantType = validateGrantTypeSupported(params.grant_type);

    // RFC 6749 §5.2: per-client grant_type authorization (unauthorized_client).
    validateClientGrantType(tokenClient, grantType);

    // Grant-specific validation. Each security rule is a separate core call so
    // it can be removed, replaced, or surrounded with experiment-specific logic.
    let validatedRequest: ValidatedTokenRequest;
    if (grantType === 'refresh_token') {
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

      validatedRequest = buildValidatedRefreshTokenRequest(
        refreshTokenInfo,
        authenticatedClientId,
        effectiveScope,
      );
    } else {
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

      validatedRequest = buildValidatedAuthorizationCodeRequest(
        code,
        authorizationCode,
        authenticatedClientId,
        codeVerified,
      );
    }


    const config = c.get('config');
    // The first registered key signs new tokens (SigningKeyProvider contract).
    const signingKey: SigningKey = c.get('signingKeys')[0];
    const privateKey = signingKey.privateKey;
    const keyId = signingKey.keyId;

    // T-022: pick an ID Token signing key whose alg matches the client's
    // id_token_signed_response_alg (OIDC Dynamic Client Registration §2).
    // - 未指定クライアントは OIDC 仕様デフォルトの RS256 で扱う。
    // - alg に合う鍵が登録されていなければサーバ設定エラー (server_error)。
    const idTokenSigningKeys = (c.get('idTokenSigningKeys') as SigningKey[] | undefined) ?? [];
    const registeredClient = (await tokenClientResolver.findClient(authenticatedClientId)) as
      | RegisteredClient
      | null;
    const requestedIdTokenAlg = registeredClient?.idTokenSignedResponseAlg;
    let selectedIdTokenKey: SigningKey;
    try {
      selectedIdTokenKey = selectSigningKeyByAlg(idTokenSigningKeys, requestedIdTokenAlg);
    } catch {
      return c.json(
        {
          error: 'server_error',
          error_description: `No ID Token signing key registered for alg "${requestedIdTokenAlg ?? 'RS256'}"`,
        },
        500,
      );
    }
    const idTokenPrivateKey = selectedIdTokenKey.privateKey;
    const idTokenKeyId = selectedIdTokenKey.keyId;

    let subject: string;
    let authTime: number | undefined;
    let nonce: string | undefined;

    if (validatedRequest.grantType === 'authorization_code') {
      const authCode = await authCodeStore.get(validatedRequest.code);
      if (!authCode?.subject || !authCode.authTime) {
        throw new TokenError(
          TokenErrorCode.InvalidGrant,
          'Authorization code missing required subject context',
        );
      }
      subject = authCode.subject;
      authTime = authCode.authTime;
      nonce = validatedRequest.nonce;
    } else {
      // refresh_token grant
      // OIDC Core 1.0 §12.2: the re-issued ID Token retains iss/sub/aud/exp/iat/
      // auth_time/azp/acr/amr — nonce is NOT in that list. nonce binds an
      // Authentication Request to its ID Token (§2); a refresh has no such request,
      // so carrying the old nonce adds no replay protection. Major OPs (Google,
      // Auth0) omit it on refresh, so we omit it here by default. auth_time is
      // still preserved per §12.1.
      subject = validatedRequest.subject;
      authTime = validatedRequest.authTime;
      nonce = undefined;
    }

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
    const effectiveAudience = buildAccessTokenAudience({
      userInfoEndpoint: `${config.issuer}/userinfo`,
      requested: validatedRequest.audience,
      issuer: config.issuer,
    });

    // T-015: acr / amr resolver injection.
    // - authorization_code: pass acrResolver so the host app can decide acr / amr policy.
    // - refresh_token: pass stored acr / amr directly so OIDC Core 1.0 §12.1 SHOULD
    //   "preserve initial auth context" is satisfied; resolver is bypassed.
    const acrResolver = c.get('acrResolver') as AcrResolver | undefined;
    const directAcr = validatedRequest.grantType === 'refresh_token' ? validatedRequest.acr : undefined;
    const directAmr = validatedRequest.grantType === 'refresh_token' ? validatedRequest.amr : undefined;

    // --- Refresh Token を発行するかの判定 -------------------------------------
    //
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

    // --- Token response pipeline --------------------------------------------
    // Each step below is an independent core function. Add your own ID Token
    // claims by editing idTokenPayload before it is signed, or swap in another
    // issuer.

    // One timestamp for the whole response so the issued tokens and the stored
    // token metadata agree on iat / exp.
    const issuedAt = Math.floor(Date.now() / 1000);

    // RFC 9068 §2.2: iss / sub / aud / exp / iat / scope / client_id.
    // Add access token claims here before the payload is signed.
    const accessTokenPayload = buildAccessTokenPayload({
      issuer: config.issuer,
      subject,
      clientId: validatedRequest.clientId,
      scope: validatedRequest.scope,
      audience: effectiveAudience,
      expiresIn: config.accessTokenExpiresIn,
      issuedAt,
    });

    // JWT or opaque, chosen above from config.accessTokenFormat.
    const accessToken = await accessTokenIssuer.issue({
      payload: accessTokenPayload,
      privateKey,
      keyId,
    });

    // OIDC Core 1.0 §12: refresh_token grant でも id_token は MAY。
    // openid scope を持つ場合は §12.1 に従い初回認証時と同じ auth_time / acr / amr / azp で再発行する。
    // （§12.2 は nonce を再発行 ID Token の保持クレームに挙げないため nonce は refresh では undefined）
    let idToken: string | undefined;
    let resolvedAcr: string | undefined = undefined;
    let resolvedAmr: string[] | undefined = undefined;
    if (validatedRequest.scope.includes('openid')) {
      // OIDC Core 1.0 §3.1.3.6: at_hash binds the ID Token to this access token.
      // The hash function follows the ID Token signing alg.
      const atHash = await computeAtHash(accessToken, idTokenPrivateKey);

      // T-015: acr / amr resolution.
      // - authorization_code: ask the host app's AcrResolver (acr_values / claims
      //   are forwarded so it can honor the request).
      // - refresh_token: pass the stored acr / amr directly so OIDC Core 1.0 §12.1
      //   "preserve initial auth context" holds; the resolver is bypassed.
      ({ acr: resolvedAcr, amr: resolvedAmr } = await resolveAcrAmr({
        subject,
        clientId: validatedRequest.clientId,
        acr: directAcr,
        amr: directAmr,
        acrResolver: validatedRequest.grantType === 'authorization_code' ? acrResolver : undefined,
        requestedAcrValues:
          validatedRequest.grantType === 'authorization_code' ? validatedRequest.acrValues : undefined,
        // OIDC Core 1.0 §5.5: the parsed claims request lets the resolver satisfy
        // id_token member requests (e.g. acr.values).
        claims: validatedRequest.grantType === 'authorization_code' ? validatedRequest.claims : undefined,
      }));

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
        acr: resolvedAcr,
        amr: resolvedAmr,
      });

      // Add your own ID Token claims here, e.g.:
      //   idTokenPayload.tenant_id = await lookupTenant(subject);

      idToken = await generateIdToken({
        payload: idTokenPayload,
        privateKey: idTokenPrivateKey,
        keyId: idTokenKeyId,
      });
    }

    // OIDC Core 1.0 §3.1.3.3 / RFC 6749 §5.1: the token response body.
    const tokenResponse = {
      access_token: accessToken,
      token_type: 'Bearer' as const,
      expires_in: config.accessTokenExpiresIn,
      id_token: idToken,
      scope: validatedRequest.scope.join(' '),
      refresh_token: issueRefreshToken ? generateRandomString(32) : undefined,
    };

    // Store access token info for UserInfo / Introspection / Revocation endpoints.
    // iat / nbf / audience / issuer are kept so RFC 7662 introspection can echo them.
    // grantId binds this token to the original authorization grant so it can be
    // revoked together with sibling tokens on code reuse (OAuth 2.1 Section 4.1.2).
    await accessTokenStore.set(tokenResponse.access_token, {
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
      audience: effectiveAudience,
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
    });

    // Store the new refresh token for rotation (OAuth 2.1 Section 4.3.1).
    // The same grantId / audience / authTime / nonce / acr / amr / azp is propagated through
    // rotations so descendants can be revoked on code reuse, the audience never expands,
    // and refresh で再発行する ID Token は OIDC Core 1.0 §12.1 に従い初回認証時の値を保持する。
    if (tokenResponse.refresh_token) {
      // authTime はここで必ず確定する: authorization_code 経由は authCode.authTime、
      // refresh_token 経由は validatedRequest.authTime（前段で代入済み）。
      const rtAuthTime = authTime;
      if (rtAuthTime === undefined) {
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
        grantHasOfflineAccess && !validatedRequest.scope.includes('offline_access')
          ? [...validatedRequest.scope, 'offline_access']
          : validatedRequest.scope;
      await refreshTokenStore.set(tokenResponse.refresh_token, {
        subject,
        clientId: validatedRequest.clientId,
        scope: refreshTokenScope,
        expiresAt: refreshTokenExpiresAt,
        originalIssuedAt,
        used: false,
        grantId: validatedRequest.grantId,
        iat: issuedAt,
        issuer: config.issuer,
        audience: effectiveAudience,
        authTime: rtAuthTime,
        nonce,
        // OIDC Core 1.0 §12.1: refresh で再発行する ID Token は初回認証時の acr / amr を保持する。
        // - authorization_code grant: 直前で resolver が解決した値をそのまま永続化する。
        // - refresh_token grant: 既に保存済みの値を引き継ぐ（resolver は呼ばれていない）。
        acr: validatedRequest.grantType === 'refresh_token' ? validatedRequest.acr : resolvedAcr,
        amr: validatedRequest.grantType === 'refresh_token' ? validatedRequest.amr : resolvedAmr,
        azp: validatedRequest.grantType === 'refresh_token' ? validatedRequest.azp : undefined,
        // online refresh token の束縛。undefined なら offline refresh token として
        // セッションから独立し、ログアウト後も使える。
        sessionId: boundSessionId,
      });
    }

    // OAuth 2.1 Section 4.3.1: ローテーションは新トークン保存成功後に旧 RT を失効する。
    // 失敗時にユーザーがリフレッシュ不能になることを防ぐため、必ずこの順序にする。
    if (validatedRequest.grantType === 'refresh_token' && params.refresh_token) {
      await refreshTokenResolver.revokeRefreshToken(params.refresh_token);
    }

    c.header('Cache-Control', 'no-store');
    c.header('Pragma', 'no-cache');
    return c.json(tokenResponse);
  } catch (error) {
    if (error instanceof TokenError) {
      const status = error.statusCode as 400 | 401;
      // RFC 6750 Section 3 / OAuth 2.1 Section 5.2: 401 responses include WWW-Authenticate
      if (error.wwwAuthenticate) {
        c.header('WWW-Authenticate', error.wwwAuthenticate);
      }
      // RFC 6749 Section 5.2: error responses MUST set Cache-Control: no-store / Pragma: no-cache.
      c.header('Cache-Control', 'no-store');
      c.header('Pragma', 'no-cache');
      return c.json(
        { error: error.error, error_description: error.errorDescription },
        status,
      );
    }
    // RFC 6749 Section 5.2: server_error responses MUST NOT be cached either.
    c.header('Cache-Control', 'no-store');
    c.header('Pragma', 'no-cache');
    return c.json({ error: 'server_error' }, 500);
  }
});
