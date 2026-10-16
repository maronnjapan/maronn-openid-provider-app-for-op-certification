/**
 * Authorization endpoint (API layer: logic only).
 *
 * processAuthorizationRequest() runs the whole OIDC Core 1.0 §3.1.2 pipeline —
 * request validation, the transaction, id_token_hint, prompt=none, SSO — and
 * reports what the endpoint decided as an outcome: the authorization response
 * URL for the client, "continue on the login / consent screen", or an error
 * that must stay on the OP. It never builds a Response; pages/authorize.ts,
 * which owns GET|POST /authorize, turns the outcome into HTTP.
 */
import {
  resolveClientForAuthorization,
  validateRegisteredRedirectUris,
  resolveRequestObjectParams,
  validateRequestObjectConsistency,
  resolveAuthorizationRedirectUri,
  rejectUnsupportedRequestParams,
  validateResponseType,
  validateAuthorizationScope,
  validateAuthorizationCodePkce,
  validatePromptParameter,
  applyOfflineAccessPolicy,
  validateClientScope,
  validateDisplayParameter,
  resolveMaxAge,
  parseAudienceParameter,
  parseClaimsRequestParameter,
  validateIdTokenHint,
  createAuthTransaction,
  createAuthorizationCode,
  completeAuthTransaction,
  generateRandomString,
  resolvePromptNoneSession,
  validatePromptNoneIdTokenHint,
  validatePromptNoneConsent,
  requiresReauthentication,
  sanitizeErrorDescription,
  AuthorizationError,
  IdTokenHintError,
  type AuthorizationRequestParams,
  type JwkSet,
} from '@maronn-openid-connect/core';
import { clientResolver as defaultClientResolver } from '../resolvers.js';
import {
  transactionStore as defaultTransactionStore,
  authCodeStore as defaultAuthCodeStore,
  authSessionStore as defaultAuthSessionStore,
  buildTransactionCookie,
} from '../store.js';

/** What the authorization endpoint decided; pages/authorize.ts turns it into HTTP. */
export type AuthorizationOutcome =
  /** Malformed transport: OAuth error JSON (400), no transaction exists yet. */
  | { kind: 'bad_request'; error: string; errorDescription: string }
  /**
   * The authorization response for the client — code, redirectable error or
   * (EXPERIMENTAL JARM) signed response JWT — ready in the URL.
   */
  | { kind: 'authorization_response'; location: string }
  /**
   * Interactive authentication is needed: continue on the login screen. cookies
   * carries the transaction cookie, the only place the transaction id goes.
   */
  | { kind: 'login'; cookies: string[] }
  /** The End-User is signed in but consent is needed: continue on the consent screen. */
  | { kind: 'consent'; cookies: string[] }
  /** OIDC Core 1.0 §3.1.2.2: the error cannot be redirected and stays on the OP. */
  | { kind: 'error'; error: string; errorDescription?: string }
  /** An unexpected failure: OAuth error JSON (500). */
  | { kind: 'server_error' };

/**
 * Narrows raw query-string params to the typed AuthorizationRequestParams.
 * PKCE parameters are validated by core so conformance compatibility mode can
 * intentionally pass requests that omit them.
 */
function isAuthorizationRequestParams(
  params: unknown,
): params is AuthorizationRequestParams {
  if (typeof params !== 'object' || params === null) return false;
  const p = params as Record<string, unknown>;
  return typeof p['client_id'] === 'string';
}

/**
 * Builds a redirect URL with an OAuth error response.
 * OIDC Core 1.0 Section 3.1.2.6 / RFC 6749 Section 4.1.2.1.
 *
 * errorDescription is optional; when supplied it is sanitized to the RFC 6749
 * Section 5.2 allowed character set before being appended so user-controlled
 * fragments cannot smuggle control bytes into the redirect URL.
 *
 * RFC 9207 §2: when issuer is provided, the iss parameter is appended so the
 * client can pin the issuer that produced this authorization response.
 */
function buildErrorRedirect(
  redirectUri: string,
  error: string,
  state?: string,
  errorDescription?: string,
  issuer?: string,
): string {
  const url = new URL(redirectUri);
  url.searchParams.set('error', error);
  if (errorDescription) {
    url.searchParams.set('error_description', sanitizeErrorDescription(errorDescription));
  }
  if (state) url.searchParams.set('state', state);
  if (issuer) url.searchParams.set('iss', issuer);
  return url.toString();
}

/**
 * Iterates URLSearchParams and reports the first repeated key, if any.
 * OIDC Core 1.0 §3.1.2.1 / RFC 6749 §3.1: authorization request parameters
 * MUST NOT be repeated. Object.fromEntries(searchParams) silently keeps the
 * last value, which would let `response_type=code&response_type=token` slip
 * through, so we scan entries explicitly.
 */
function collectUniqueParams(
  searchParams: URLSearchParams,
): { params: Record<string, string>; duplicateKey?: string } {
  const params: Record<string, string> = {};
  const seen = new Set<string>();
  for (const [key, value] of searchParams) {
    if (seen.has(key)) {
      return { params, duplicateKey: key };
    }
    seen.add(key);
    params[key] = value;
  }
  return { params };
}

/**
 * OIDC Core 1.0 Section 3.1.2.1 / Section 13.2: parses the authorization request
 * parameters from either GET (query string) or POST (application/x-www-form-urlencoded).
 * Returns null if the request transport is invalid (e.g. unsupported Content-Type on POST).
 */
async function parseAuthorizationRequestParams(
  c: any,
): Promise<{ params: Record<string, string>; duplicateKey?: string } | null> {
  if (c.req.method === 'POST') {
    const contentType = c.req.header('Content-Type') ?? '';
    // OIDC Core 1.0 Section 13.2: POST must use application/x-www-form-urlencoded.
    if (!contentType.toLowerCase().split(';')[0].trim().startsWith('application/x-www-form-urlencoded')) {
      return null;
    }
    // Read the raw body so URLSearchParams preserves duplicate keys
    // (parseBody silently dedupes them).
    const raw = await c.req.text();
    return collectUniqueParams(new URLSearchParams(raw));
  }
  return collectUniqueParams(new URL(c.req.url).searchParams);
}

/**
 * Process one authorization request (OIDC Core 1.0 Section 3.1.2). Shared by
 * GET and POST /authorize (pages/authorize.ts).
 */
export async function processAuthorizationRequest(c: any): Promise<AuthorizationOutcome> {
  const parsed = await parseAuthorizationRequestParams(c);

  if (parsed === null) {
    return { kind: 'bad_request', error: 'invalid_request', errorDescription: 'Authorization POST requests must use application/x-www-form-urlencoded' };
  }

  // OIDC Core 1.0 §3.1.2.1 / RFC 6749 §3.1: request parameters MUST NOT be repeated.
  if (parsed.duplicateKey !== undefined) {
    return { kind: 'bad_request', error: 'invalid_request', errorDescription: `Parameter "${parsed.duplicateKey}" must not be repeated` };
  }

  const rawParams = parsed.params;

  if (!isAuthorizationRequestParams(rawParams)) {
    return { kind: 'bad_request', error: 'invalid_request', errorDescription: 'Missing required parameter: client_id' };
  }

  const params = rawParams;

  try {
    const clientResolver = c.get('clientResolver') ?? defaultClientResolver;
    const transactionStore = c.get('transactionStore') ?? defaultTransactionStore;
    const authCodeStore = c.get('authCodeStore') ?? defaultAuthCodeStore;
    // RFC 9207 §2: include the issuer identifier on every authorization
    // response (success and error) so clients can pin the issuer that
    // produced the response.
    const config = c.get('config');
    const issuer = config.issuer;

    // --- Authorization request validation pipeline ---------------------------
    // Each step below is an independent core function, called in OIDC Core 1.0
    // §3.1.2 order. Delete a call to drop that validation, or insert your own
    // logic between steps. Steps that run before
    // redirectUri is resolved throw non-redirectable errors (shown to the user
    // agent); steps after it throw redirectable errors (sent to the client).

    // OAuth 2.1 §4.1.2.1: resolve client_id into the registered client.
    const client = await resolveClientForAuthorization(params, clientResolver);

    // Fail fast on misconfigured registered redirect URIs (fragments, dangerous
    // schemes, non-loopback http) — OIDC Core 1.0 §3.1.2.1 / RFC 8252 §8.
    validateRegisteredRedirectUris(client.redirectUris);

    // OIDC Core 1.0 §6.1: verify the signed Request Object (request parameter)
    // against the client's registered JWKS and overlay its claims onto the query
    // parameters. RS256 is required; alg=none is accepted only when
    // allowUnsignedRequestObject is enabled (conformance compat).
    // effectiveParams is what every later step validates.
    const { effectiveParams, requestObjectClaims } = await resolveRequestObjectParams(
      params,
      client,
      { allowUnsigned: config.allowUnsignedRequestObject },
    );

    // Resolve redirect_uri against the registered URIs (OIDC Core 1.0 §3.1.2.1).
    const redirectUri = resolveAuthorizationRedirectUri(effectiveParams, client);
    // RFC 6749 §4.1.2.1: state is echoed only on redirectable errors from here on.
    const state = effectiveParams.state;

    // OIDC Core 1.0 §6.3: request_uri / registration are not supported here.
    rejectUnsupportedRequestParams(params, redirectUri, state);

    // OIDC Core 1.0 §6.1: response_type / client_id inside the Request Object
    // must match the OAuth query parameters.
    validateRequestObjectConsistency(params, requestObjectClaims, redirectUri, state);

    // response_type=code and per-client response_type authorization.
    const responseType = validateResponseType(params, client, redirectUri, state);

    // scope must be in the query (OIDC Core 1.0 §6.1) and contain openid (§3.1.2.1).
    let scope = validateAuthorizationScope(params, effectiveParams, redirectUri, state);

    // RFC 7591 §2: a client registered with a scope list (client.scope) may only
    // request those scopes. Any other one, offline_access included, is invalid_scope.
    validateClientScope(scope, client.scope, redirectUri, state);

    // OAuth 2.1 §4.1.1 / §7.5: PKCE with S256 (allowNonPkceAuthorizationCodeFlow
    // exists only for the OIDF Basic OP static-client compatibility target).
    const pkce = validateAuthorizationCodePkce(effectiveParams, client, redirectUri, state, {
      allowNonPkceAuthorizationCodeFlow: config.allowNonPkceAuthorizationCodeFlow,
    });

    // OIDC Core 1.0 §3.1.2.1: prompt is none|login|consent|select_account.
    const prompt = validatePromptParameter(effectiveParams, redirectUri, state);

    // offline_access は 2 つの独立した条件を両方満たしたときだけ残る。
    // - OIDC Core 1.0 §11: エンドユーザーの同意（prompt=consent）
    // - RFC 7591 §2: クライアント登録の grant_types に refresh_token があること
    //   （既定は ["authorization_code"]）。無いまま offline_access を通すと、発行した
    //   Refresh Token が unauthorized_client で拒否されるだけの死んだ資格情報になる。
    // 独自の許可条件を差し込むならコールバックを渡す（client も受け取れる）:
    //   scope = await applyOfflineAccessPolicy(scope, effectiveParams, prompt, client,
    //     (req, { promptValues }) => promptValues.includes('consent') || hasStoredConsent(req));
    scope = await applyOfflineAccessPolicy(scope, effectiveParams, prompt, client);

    // OIDC Core 1.0 §3.1.2.1: display is page|popup|touch|wap.
    const display = validateDisplayParameter(effectiveParams, redirectUri, state);

    // OIDC Core 1.0 §3.1.2.1 / Dynamic Client Registration 1.0 §2: max_age from
    // the request, falling back to the client's registered default_max_age.
    const maxAge = resolveMaxAge(effectiveParams, client, redirectUri, state);

    // Space-delimited audience for the access token.
    const audience = parseAudienceParameter(effectiveParams);

    // OIDC Core 1.0 §5.5: parse the claims request parameter (userinfo / id_token).
    const claims = parseClaimsRequestParameter(effectiveParams, redirectUri, state);

    // Assemble the validated request from each step's result. This is core's
    // ValidatedAuthorizationRequest (what createAuthTransaction() takes), so
    // downstream code (transactions, authorization codes) is unaffected by
    // adding or removing steps above.
    const validatedRequest = {
      responseType,
      clientId: client.clientId,
      redirectUri,
      // OIDC Core 1.0 §3.1.3.2: when redirect_uri was sent explicitly, the token
      // request must repeat it; remember which case produced this authorization.
      redirectUriExplicit: effectiveParams.redirect_uri !== undefined,
      scope,
      codeChallenge: pkce.codeChallenge,
      codeChallengeMethod: pkce.codeChallengeMethod,
      state,
      nonce: effectiveParams.nonce,
      prompt,
      display,
      maxAge,
      uiLocales: effectiveParams.ui_locales,
      claimsLocales: effectiveParams.claims_locales,
      acrValues: effectiveParams.acr_values,
      loginHint: effectiveParams.login_hint,
      idTokenHint: effectiveParams.id_token_hint,
      audience,
      claims,
    };

    // Create authentication transaction. csrfToken is embedded in the login /
    // consent forms; transactionId never leaves the OP except in the HttpOnly
    // transaction cookie (buildTransactionCookie() in store.ts).
    const csrfToken = await generateRandomString(32);
    const transaction = createAuthTransaction(validatedRequest, csrfToken);
    const transactionId = await generateRandomString(32);

    // Store transaction
    const transactionTtlSeconds = 10 * 60; // 10 minutes TTL
    await transactionStore.put(
      'auth_txn:' + transactionId,
      transaction,
      transactionTtlSeconds,
    );

    // OIDC Core 1.0 Section 3.1.2.1: prompt is a space-delimited list
    const promptValues = transaction.prompt?.trim().split(/\s+/).filter(Boolean) ?? [];

    // prompt=none must not be combined with other values (OIDC Core 1.0 Section 3.1.2.1)
    if (promptValues.includes('none') && promptValues.length > 1) {
      await transactionStore.delete('auth_txn:' + transactionId);
      return { kind: 'authorization_response', location: buildErrorRedirect(transaction.redirectUri, 'invalid_request', transaction.state, 'prompt=none must not be combined with other prompt values', issuer) };
    }

    // OIDC Core 1.0 §3.1.2.1: the id_token_hint rule ("if the End-User identified
    // by the ID Token is logged in ... otherwise it SHOULD return an error") is NOT
    // conditioned on prompt, so the hint is verified here — outside the prompt=none
    // branch — and therefore on every prompt path (no prompt / login / consent /
    // select_account / none). Verification covers signature, iss, aud, exp and iat;
    // the verified subject is shared by the prompt=none check below and by the SSO
    // fast path, so an unverified hint never reaches a session decision.
    let verifiedHintSubject: string | undefined;
    if (transaction.idTokenHint !== undefined) {
      const jwksProvider = c.get('jwksProvider') as undefined | (() => Promise<JwkSet> | JwkSet);
      if (!jwksProvider) {
        // jwksProvider 未提供では hint を検証できない → login_required で拒否
        await transactionStore.delete('auth_txn:' + transactionId);
        return { kind: 'authorization_response', location: buildErrorRedirect(transaction.redirectUri, 'login_required', transaction.state, 'jwksProvider is not configured; cannot verify id_token_hint', issuer) };
      }
      try {
        const jwks = await jwksProvider();
        const verified = await validateIdTokenHint(transaction.idTokenHint, {
          expectedIss: issuer,
          expectedAud: transaction.clientId,
          jwks,
        });
        verifiedHintSubject = verified.sub;
      } catch (hintError) {
        await transactionStore.delete('auth_txn:' + transactionId);
        const code = hintError instanceof IdTokenHintError ? hintError.error : 'login_required';
        return { kind: 'authorization_response', location: buildErrorRedirect(transaction.redirectUri, code, transaction.state, hintError instanceof Error && hintError.message ? hintError.message : 'id_token_hint verification failed', issuer) };
      }
    }

    // prompt=none: silent authentication without any user interaction
    // OIDC Core 1.0 Section 3.1.2.1
    if (promptValues.includes('none')) {
      const sessionResolver = c.get('sessionResolver');
      const consentResolver = c.get('consentResolver');

      // No sessionResolver configured → cannot verify session → login_required
      if (!sessionResolver) {
        await transactionStore.delete('auth_txn:' + transactionId);
        return { kind: 'authorization_response', location: buildErrorRedirect(transaction.redirectUri, 'login_required', transaction.state, 'sessionResolver is not configured; cannot satisfy prompt=none', issuer) };
      }

      // No consentResolver configured → cannot confirm consent → consent_required
      // (OIDC Core 1.0 Section 3.1.2.1: prompt=none must not display consent screen)
      if (!consentResolver) {
        await transactionStore.delete('auth_txn:' + transactionId);
        return { kind: 'authorization_response', location: buildErrorRedirect(transaction.redirectUri, 'consent_required', transaction.state, 'consentResolver is not configured; cannot satisfy prompt=none', issuer) };
      }

      let session;
      try {
        // --- prompt=none pipeline ---------------------------------------
        // Each step below is an independent core function: the session, then
        // id_token_hint (before consent, so consent is never looked up for
        // another End-User), then consent. Delete a call to drop that check,
        // or insert your own logic between steps. Every step throws
        // AuthorizationError(login_required | consent_required) on failure.

        // OIDC Core 1.0 §3.1.2.1: no active session → login_required (the OP
        // must not show a login screen for prompt=none).
        session = await resolvePromptNoneSession(transaction, sessionResolver, c.req.raw);

        // verifiedHintSubject は上流（prompt 非依存の検証ブロック）で確定済み。
        // ここでは prompt=none 固有の「不一致なら login_required」判定だけを行う。
        // コンセント確認より前に置くのは、コンセント検索が session.subject をキーに
        // するため — 不一致のまま進むと別ユーザーのコンセントを見てしまう。
        validatePromptNoneIdTokenHint(transaction, session, verifiedHintSubject);

        // OIDC Core 1.0 §3.1.2.1: not consented → consent_required (the OP must
        // not show a consent screen for prompt=none).
        await validatePromptNoneConsent(transaction, session, consentResolver);
      } catch (promptError) {
        await transactionStore.delete('auth_txn:' + transactionId);
        if (promptError instanceof AuthorizationError) {
          return { kind: 'authorization_response', location: buildErrorRedirect(transaction.redirectUri, promptError.error, transaction.state, promptError.errorDescription, issuer) };
        }
        const serverDescription =
          promptError instanceof Error && promptError.message
            ? promptError.message
            : 'Unexpected error while evaluating prompt=none';
        return { kind: 'authorization_response', location: buildErrorRedirect(transaction.redirectUri, 'server_error', transaction.state, serverDescription, issuer) };
      }

      // Check max_age: if session is too old, prompt=none cannot trigger re-authentication
      // OIDC Core 1.0 Section 3.1.2.1
      if (transaction.maxAge !== undefined && requiresReauthentication(transaction.maxAge, session.authTime)) {
        await transactionStore.delete('auth_txn:' + transactionId);
        return { kind: 'authorization_response', location: buildErrorRedirect(transaction.redirectUri, 'login_required', transaction.state, 'Session exceeds the requested max_age; re-authentication required', issuer) };
      }

      // transaction.scope は認可リクエスト検証時に applyOfflineAccessPolicy を通した
      // 後の値。offline_access の可否（OIDC Core 1.0 §11 の prompt=consent と、
      // クライアント登録 grant_types に refresh_token があるか）はそこで判定済みなので、
      // ここで再フィルタしない。
      const grantedScope = transaction.scope.split(' ').filter(Boolean);

      // Generate authorization code via core helper
      const responseParams = await completeAuthTransaction(
        transactionId,
        transaction,
        transactionStore,
      );
      const authCodeData = await createAuthorizationCode({
        authorizationResponse: { ...responseParams, scope: grantedScope },
        subject: session.subject,
        authTime: session.authTime,
        // online refresh token をこのログインセッションへ束縛するために引き継ぐ。
        // セッションが終われば、その RT は invalid_grant になる。
        sessionId: session.sessionId,
        // OIDC Core 1.0 §3.1.3.1: TTL は ProviderConfig から設定可能（既定 300 秒）。
        ttlSeconds: config.authorizationCodeTtl,
      });
      await authCodeStore.set(authCodeData.code, authCodeData);
      await consentResolver.recordGrant?.(
        session.subject,
        transaction.clientId,
        authCodeData.grantId,
      );

      const redirectUrl = new URL(transaction.redirectUri);
      redirectUrl.searchParams.set('code', authCodeData.code);
      if (transaction.state) redirectUrl.searchParams.set('state', transaction.state);
      // RFC 9207 §2: include iss in success responses too.
      redirectUrl.searchParams.set('iss', issuer);
      return { kind: 'authorization_response', location: redirectUrl.toString() };
    }

    // OIDC Core 1.0 Section 3.1.2.3: an active OP session enables Single Sign-On.
    // Reuse it (skipping the login screen) unless prompt forces fresh auth.
    // - When max_age is requested, the session must also satisfy the freshness
    //   bound (Section 3.1.2.1).
    // - When max_age is absent, any active session is reused (SSO).
    // prompt=login / prompt=select_account always force re-authentication.
    if (!promptValues.includes('login') && !promptValues.includes('select_account')) {
      const sessionResolver = c.get('sessionResolver');
      if (sessionResolver) {
        const existingSession = await sessionResolver.resolve(c.req.raw);
        const sessionIsFresh =
          existingSession !== null &&
          (transaction.maxAge === undefined ||
            !requiresReauthentication(transaction.maxAge, existingSession.authTime));
        // OIDC Core 1.0 §3.1.2.1: id_token_hint が指す End-User でなければ既存
        // セッションを再利用しない。これが無いと「セッションは User B / hint は
        // User A」の要求に対し B の認可コードを黙って発行してしまう。
        // 不一致はエラーにせずログイン画面へ落とし、正しい End-User として認証さ
        // せる（login_required を即返すかは方針判断に委ねる）。
        const hintMatchesSession =
          verifiedHintSubject === undefined ||
          (existingSession !== null && verifiedHintSubject === existingSession.subject);
        if (existingSession && sessionIsFresh && hintMatchesSession) {
          // OIDC Core 1.0 §3.1.2.1: prompt=consent MUST re-display the consent UI.
          // Otherwise, if the user already granted (a superset of) the requested
          // scopes to this client, skip the consent screen and issue the code
          // directly — the interactive analogue of the prompt=none silent path.
          const consentResolver = c.get('consentResolver');
          const requestedScopes = transaction.scope.split(' ').filter(Boolean);
          const consentAlreadyGranted =
            !promptValues.includes('consent') &&
            consentResolver !== undefined &&
            (await consentResolver.hasConsent(
              existingSession.subject,
              transaction.clientId,
              requestedScopes,
            ));

          if (consentAlreadyGranted) {
            // transaction.scope は applyOfflineAccessPolicy 通過後の値（prompt=consent と
            // クライアントの grant_types で offline_access の可否は判定済み）。再フィルタしない。
            const grantedScope = transaction.scope.split(' ').filter(Boolean);

            const responseParams = await completeAuthTransaction(
              transactionId,
              transaction,
              transactionStore,
            );
            const authCodeData = await createAuthorizationCode({
              authorizationResponse: { ...responseParams, scope: grantedScope },
              subject: existingSession.subject,
              authTime: existingSession.authTime,
              // online refresh token を、この SSO で再利用したログインセッションへ束縛する。
              sessionId: existingSession.sessionId,
              // OIDC Core 1.0 §3.1.3.1: TTL は ProviderConfig から設定可能（既定 300 秒）。
              ttlSeconds: config.authorizationCodeTtl,
            });
            await authCodeStore.set(authCodeData.code, authCodeData);
            await consentResolver.recordGrant?.(
              existingSession.subject,
              transaction.clientId,
              authCodeData.grantId,
            );

            const redirectUrl = new URL(transaction.redirectUri);
            redirectUrl.searchParams.set('code', authCodeData.code);
            if (transaction.state) redirectUrl.searchParams.set('state', transaction.state);
            // RFC 9207 §2: include iss in success responses.
            redirectUrl.searchParams.set('iss', issuer);
            return { kind: 'authorization_response', location: redirectUrl.toString() };
          }

          const authSessionStore = c.get('authSessionStore') ?? defaultAuthSessionStore;
          await authSessionStore.set(transactionId, {
            subject: existingSession.subject,
            authTime: existingSession.authTime,
            // consent 画面を経由しても online refresh token の束縛先を見失わないよう、
            // login → consent の受け渡しに sessionId も載せる。
            sessionId: existingSession.sessionId,
          });
          // Continue on the consent screen (pages/consent.tsx), which finds the
          // transaction through the cookie that travels with this answer.
          return {
            kind: 'consent',
            cookies: [buildTransactionCookie(transactionId, transactionTtlSeconds)],
          };
        }
      }
    }

    // Interactive authentication: continue on the login screen (pages/login.tsx;
    // prompt=login forces re-authentication there), which finds the transaction
    // through the cookie that travels with this answer.
    return { kind: 'login', cookies: [buildTransactionCookie(transactionId, transactionTtlSeconds)] };
  } catch (error) {
    if (error instanceof AuthorizationError) {
      if (error.redirectUri) {
        const redirectUrl = new URL(error.redirectUri);
        redirectUrl.searchParams.set('error', error.error);
        if (error.errorDescription) {
          redirectUrl.searchParams.set('error_description', error.errorDescription);
        }
        if (error.state) {
          redirectUrl.searchParams.set('state', error.state);
        }
        // RFC 9207 §2: include iss on error redirects so the client can
        // pin the issuer. config has already been read into context by
        // middleware; reread it here because the early-bound issuer is
        // scoped to the try block.
        redirectUrl.searchParams.set('iss', c.get('config').issuer);
        return { kind: 'authorization_response', location: redirectUrl.toString() };
      }
      // OIDC Core 1.0 §3.1.2.2: errors that cannot be redirected (unknown
      // client_id, unregistered redirect_uri, redirect_uri with a fragment) MUST
      // NOT redirect to the supplied redirect_uri. They stay on the OP:
      // pages/authorize.ts answers programmatic callers (Accept:
      // application/json) with the OAuth error JSON and browsers with the OP's
      // own error page.
      return { kind: 'error', error: error.error, errorDescription: error.errorDescription };
    }
    return { kind: 'server_error' };
  }
}
