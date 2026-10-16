import {
  type AuthorizationRequestParams,
  type AuthTransaction,
  sanitizeErrorDescription,
  resolveClientForAuthorization,
  validateRegisteredRedirectUris,
  type ClientInfo,
  resolveRequestObjectParams,
  type ResolvedRequestObjectParams,
  resolveAuthorizationRedirectUri,
  rejectUnsupportedRequestParams,
  validateRequestObjectConsistency,
  validateResponseType,
  validateAuthorizationScope,
  validateClientScope,
  validateAuthorizationCodePkce,
  validatePromptParameter,
  applyOfflineAccessPolicy,
  validateDisplayParameter,
  resolveMaxAge,
  parseAudienceParameter,
  parseClaimsRequestParameter,
  validateAcrValuesParameter,
  type ValidatedAuthorizationRequest,
  createAuthTransaction,
  generateRandomString,
  validateIdTokenHint,
  IdTokenHintError,
  type JwkSet,
  resolvePromptNoneSession,
  validatePromptNoneIdTokenHint,
  validatePromptNoneConsent,
  requiresReauthentication,
  AuthorizationError,
  type SessionInfo,
  completeAuthTransaction,
  createAuthorizationCode,
} from '@maronn-openid-connect/core';
import { clientResolver as defaultClientResolver } from '../resolvers.js';
import {
  transactionStore as defaultTransactionStore,
  authSessionStore as defaultAuthSessionStore,
  buildTransactionCookie,
  authCodeStore as defaultAuthCodeStore,
} from '../store.js';

/**
 * Authorization endpoint (API layer: logic only).
 * OIDC Core 1.0 Section 3.1.2
 *
 * Every function exported below is one box of the authorization endpoint's
 * pipeline (`maronn-oidc graph --detail steps --endpoint authorize`): parse the
 * request, resolve the client and the redirect_uri, validate the parameters,
 * create the transaction, verify id_token_hint, then try prompt=none and
 * Single Sign-On before continuing on the login screen.
 * processAuthorizationRequest() at the bottom calls them in order and reports
 * what the endpoint decided as an outcome: the authorization response URL for
 * the client, "continue on the login / consent screen", or an error that must
 * stay on the OP. It never builds a Response; pages/authorize.ts, which owns
 * GET|POST /authorize, turns the outcome into HTTP. A box that is left out of
 * a `--flow` document is left out of this file.
 */

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
 * The request parameters as parsed: the fields OIDC Core 1.0 §3.1.2.1 names,
 * plus every other parameter the client sent.
 */
export type AuthorizationRequestInput = AuthorizationRequestParams & Record<string, string>;

/** The transaction the pipeline created, with the lifetime its cookie gets. */
export interface AuthorizationTransaction {
  transactionId: string;
  transaction: AuthTransaction;
  transactionTtlSeconds: number;
}

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
 * Builds the success redirect URL carrying the authorization code.
 * OIDC Core 1.0 Section 3.1.2.5 / RFC 9207 Section 2 (iss).
 */
function buildSuccessRedirect(
  redirectUri: string,
  code: string,
  state: string | undefined,
  issuer: string,
): string {
  const url = new URL(redirectUri);
  url.searchParams.set('code', code);
  if (state) url.searchParams.set('state', state);
  // RFC 9207 Section 2: include iss in success responses.
  url.searchParams.set('iss', issuer);
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
 * Parse the authorization request (GET query or POST form).
 * OIDC Core 1.0 §3.1.2.1 / §13.2 / RFC 6749 §3.1
 *
 * Returns the bad_request outcome for malformed transport: a POST that is not
 * application/x-www-form-urlencoded, a repeated parameter, or no client_id.
 * There is no transaction yet, so those are answered as OAuth error JSON.
 */
export async function parseAuthorizationRequest(
  c: any,
): Promise<{ params: AuthorizationRequestInput } | AuthorizationOutcome> {
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

  return { params: rawParams };
}

/**
 * Resolve client_id into the registered client and fail fast on misconfigured
 * registered redirect URIs (fragments, dangerous schemes, non-loopback http).
 * OAuth 2.1 §4.1.2.1 / OIDC Core 1.0 §3.1.2.1 / RFC 8252 §8
 *
 * Errors thrown here are not redirectable: the OP has no redirect_uri it may
 * trust yet, so they stay on the OP (OIDC Core 1.0 §3.1.2.2).
 */
export async function resolveAuthorizationClient(
  c: any,
  params: AuthorizationRequestInput,
): Promise<ClientInfo> {
  const clientResolver = c.get('clientResolver') ?? defaultClientResolver;
  const client = await resolveClientForAuthorization(params, clientResolver);
  validateRegisteredRedirectUris(client.redirectUris);
  return client;
}

/**
 * Verify the signed Request Object (request parameter) against the client's
 * registered JWKS and overlay its claims onto the query parameters.
 * OIDC Core 1.0 §6.1
 *
 * RS256 is required; alg=none is accepted only when
 * config.allowUnsignedRequestObject is enabled (conformance compat).
 * effectiveParams is what every later step validates.
 */
export async function resolveRequestObject(
  c: any,
  params: AuthorizationRequestInput,
  client: ClientInfo,
): Promise<ResolvedRequestObjectParams> {
  const config = c.get('config');
  return resolveRequestObjectParams(params, client, { allowUnsigned: config.allowUnsignedRequestObject });
}

/**
 * Resolve redirect_uri against the registered URIs.
 * OIDC Core 1.0 §3.1.2.1 / RFC 6749 §4.1.2.1
 *
 * From here on an error is redirectable: it is sent to the client together
 * with the request's state. Everything before this step stays on the OP.
 */
export function resolveRedirectTarget(
  params: AuthorizationRequestParams,
  client: ClientInfo,
): { redirectUri: string; state: string | undefined } {
  const redirectUri = resolveAuthorizationRedirectUri(params, client);
  return { redirectUri, state: params.state };
}

/**
 * Validate the authorization request parameters and assemble the validated
 * request. OIDC Core 1.0 §3.1.2.1 - §3.1.2.2 / OAuth 2.1 §4.1.1 / §7.5
 *
 * Each check is an independent core function, called in OIDC Core 1.0 §3.1.2
 * order. Delete a call to drop that validation, or insert your own logic
 * between two checks. Every failure here is redirectable (sent to the client
 * with the state), because redirect_uri was resolved before this step.
 */
export async function validateAuthorizationRequestParams(
  c: any,
  input: {
    /** The parameters as sent (OAuth query parameters). */
    params: AuthorizationRequestInput;
    /** The parameters after the Request Object overlay (OIDC Core 1.0 §6.1). */
    effectiveParams: AuthorizationRequestParams;
    requestObjectClaims: ResolvedRequestObjectParams['requestObjectClaims'];
    client: ClientInfo;
    redirectUri: string;
    state: string | undefined;
  },
): Promise<ValidatedAuthorizationRequest> {
  const { params, effectiveParams, requestObjectClaims, client, redirectUri, state } = input;
  const config = c.get('config');

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

  // OIDC Core 1.0 §3.1.2.1: acr_values is optional, space-separated acr values
  // in order of preference, each of visible ASCII characters other than " and \.
  // The token endpoint puts the acr it settles on into the ID Token and the
  // access token (routes/token.ts).
  const acrValues = validateAcrValuesParameter(effectiveParams, redirectUri, state);

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
    acrValues,
    loginHint: effectiveParams.login_hint,
    idTokenHint: effectiveParams.id_token_hint,
    audience,
    claims,
  };
  return validatedRequest;
}

/**
 * Create the authorization transaction and store it for the login / consent
 * steps. OIDC Core 1.0 §3.1.2.3
 *
 * csrfToken is embedded in the login / consent forms; transactionId never
 * leaves the OP except in the HttpOnly transaction cookie
 * (buildTransactionCookie() in store.ts).
 */
export async function createAuthorizationTransaction(
  c: any,
  validatedRequest: ValidatedAuthorizationRequest,
): Promise<AuthorizationTransaction> {
  const transactionStore = c.get('transactionStore') ?? defaultTransactionStore;
  const csrfToken = await generateRandomString(32);
  const transaction: AuthTransaction = createAuthTransaction(validatedRequest, csrfToken);
  const transactionId = await generateRandomString(32);

  const transactionTtlSeconds = 10 * 60; // 10 minutes TTL
  await transactionStore.put(
    'auth_txn:' + transactionId,
    transaction,
    transactionTtlSeconds,
  );
  return { transactionId, transaction, transactionTtlSeconds };
}

/**
 * OIDC Core 1.0 §3.1.2.1: prompt=none must not be combined with other values.
 * Returns the redirectable error outcome (and drops the transaction) when it
 * is; undefined otherwise.
 */
export async function rejectCombinedPromptNone(
  c: any,
  promptValues: string[],
  transactionId: string,
  transaction: AuthTransaction,
  issuer: string,
): Promise<AuthorizationOutcome | undefined> {
  if (!(promptValues.includes('none') && promptValues.length > 1)) return undefined;
  const transactionStore = c.get('transactionStore') ?? defaultTransactionStore;
  await transactionStore.delete('auth_txn:' + transactionId);
  return {
    kind: 'authorization_response',
    location: buildErrorRedirect(transaction.redirectUri, 'invalid_request', transaction.state, 'prompt=none must not be combined with other prompt values', issuer),
  };
}

/**
 * Verify id_token_hint: signature, iss, aud, exp and iat against the OP's own
 * JWKS. OIDC Core 1.0 §3.1.2.1
 *
 * The rule ("if the End-User identified by the ID Token is logged in ...
 * otherwise it SHOULD return an error") is NOT conditioned on prompt, so the
 * hint is verified on every prompt path (no prompt / login / consent /
 * select_account / none). The verified subject is shared by the prompt=none
 * check and by the SSO fast path, so an unverified hint never reaches a
 * session decision. A hint that does not verify is a redirectable error
 * (login_required, or the hint's own code), and the transaction is dropped.
 */
export async function verifyIdTokenHint(
  c: any,
  transactionId: string,
  transaction: AuthTransaction,
  issuer: string,
): Promise<{ verifiedHintSubject: string | undefined } | AuthorizationOutcome> {
  if (transaction.idTokenHint === undefined) return { verifiedHintSubject: undefined };
  const transactionStore = c.get('transactionStore') ?? defaultTransactionStore;
  const jwksProvider = c.get('jwksProvider') as undefined | (() => Promise<JwkSet> | JwkSet);
  if (!jwksProvider) {
    // jwksProvider 未提供では hint を検証できない → login_required で拒否
    await transactionStore.delete('auth_txn:' + transactionId);
    return {
      kind: 'authorization_response',
      location: buildErrorRedirect(transaction.redirectUri, 'login_required', transaction.state, 'jwksProvider is not configured; cannot verify id_token_hint', issuer),
    };
  }
  try {
    const jwks = await jwksProvider();
    const verified = await validateIdTokenHint(transaction.idTokenHint, {
      expectedIss: issuer,
      expectedAud: transaction.clientId,
      jwks,
    });
    return { verifiedHintSubject: verified.sub };
  } catch (hintError) {
    await transactionStore.delete('auth_txn:' + transactionId);
    const code = hintError instanceof IdTokenHintError ? hintError.error : 'login_required';
    return {
      kind: 'authorization_response',
      location: buildErrorRedirect(transaction.redirectUri, code, transaction.state, hintError instanceof Error && hintError.message ? hintError.message : 'id_token_hint verification failed', issuer),
    };
  }
}

/**
 * prompt=none: silent authentication without any user interaction.
 * OIDC Core 1.0 §3.1.2.1
 *
 * Returns undefined when the request did not ask for prompt=none (the
 * pipeline goes on to SSO and the login screen). Otherwise the session the
 * code is issued for, or the redirectable error (login_required /
 * consent_required / server_error) and the transaction is dropped: the OP
 * must not show a login or consent screen for prompt=none.
 */
export async function completePromptNoneRequest(
  c: any,
  input: {
    promptValues: string[];
    transactionId: string;
    transaction: AuthTransaction;
    verifiedHintSubject: string | undefined;
    issuer: string;
  },
): Promise<{ session: SessionInfo } | AuthorizationOutcome | undefined> {
  const { promptValues, transactionId, transaction, verifiedHintSubject, issuer } = input;
  if (!promptValues.includes('none')) return undefined;

  const transactionStore = c.get('transactionStore') ?? defaultTransactionStore;
  const sessionResolver = c.get('sessionResolver');
  const consentResolver = c.get('consentResolver');
  const errorResponse = async (error: string, description: string): Promise<AuthorizationOutcome> => {
    await transactionStore.delete('auth_txn:' + transactionId);
    return {
      kind: 'authorization_response',
      location: buildErrorRedirect(transaction.redirectUri, error, transaction.state, description, issuer),
    };
  };

  // No sessionResolver configured → cannot verify session → login_required
  if (!sessionResolver) {
    return errorResponse('login_required', 'sessionResolver is not configured; cannot satisfy prompt=none');
  }

  // No consentResolver configured → cannot confirm consent → consent_required
  // (OIDC Core 1.0 Section 3.1.2.1: prompt=none must not display consent screen)
  if (!consentResolver) {
    return errorResponse('consent_required', 'consentResolver is not configured; cannot satisfy prompt=none');
  }

  let session: SessionInfo;
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
    if (promptError instanceof AuthorizationError) {
      return errorResponse(promptError.error, promptError.errorDescription ?? '');
    }
    const serverDescription =
      promptError instanceof Error && promptError.message
        ? promptError.message
        : 'Unexpected error while evaluating prompt=none';
    return errorResponse('server_error', serverDescription);
  }

  // Check max_age: if session is too old, prompt=none cannot trigger re-authentication
  // OIDC Core 1.0 Section 3.1.2.1
  if (transaction.maxAge !== undefined && requiresReauthentication(transaction.maxAge, session.authTime)) {
    return errorResponse('login_required', 'Session exceeds the requested max_age; re-authentication required');
  }

  return { session };
}

/**
 * Single Sign-On: reuse the active OP session instead of showing the login
 * screen. OIDC Core 1.0 §3.1.2.3
 *
 * - prompt=login / prompt=select_account always force re-authentication.
 * - When max_age is requested, the session must also satisfy the freshness
 *   bound (§3.1.2.1); when it is absent, any active session is reused.
 * - The session must belong to the End-User id_token_hint names (§3.1.2.1):
 *   otherwise the request falls to the login screen rather than silently
 *   issuing a code for another End-User.
 *
 * Returns undefined when there is no session to reuse (continue on the login
 * screen); the session when consent was already granted (the code is issued);
 * or the consent outcome when the End-User still has to decide (prompt=consent
 * MUST re-display the consent UI).
 */
export async function reuseExistingSession(
  c: any,
  input: {
    promptValues: string[];
    transactionId: string;
    transaction: AuthTransaction;
    transactionTtlSeconds: number;
    verifiedHintSubject: string | undefined;
  },
): Promise<{ session: SessionInfo } | AuthorizationOutcome | undefined> {
  const { promptValues, transactionId, transaction, transactionTtlSeconds, verifiedHintSubject } = input;
  if (promptValues.includes('login') || promptValues.includes('select_account')) return undefined;
  const sessionResolver = c.get('sessionResolver');
  if (!sessionResolver) return undefined;

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
  if (!existingSession || !sessionIsFresh || !hintMatchesSession) return undefined;

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
    return { session: existingSession };
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

/**
 * Issue the authorization code for a session that needs no interaction
 * (prompt=none, or SSO with prior consent) and build the authorization
 * response URL. OIDC Core 1.0 §3.1.2.5 / §3.1.3.1 / RFC 9207 §2
 *
 * transaction.scope は認可リクエスト検証時に applyOfflineAccessPolicy を通した
 * 後の値。offline_access の可否（OIDC Core 1.0 §11 の prompt=consent と、
 * クライアント登録 grant_types に refresh_token があるか）はそこで判定済みなので、
 * ここで再フィルタしない。
 */
export async function issueAuthorizationCodeResponse(
  c: any,
  input: {
    transactionId: string;
    transaction: AuthTransaction;
    session: SessionInfo;
    issuer: string;
  },
): Promise<AuthorizationOutcome> {
  const { transactionId, transaction, session, issuer } = input;
  const transactionStore = c.get('transactionStore') ?? defaultTransactionStore;
  const authCodeStore = c.get('authCodeStore') ?? defaultAuthCodeStore;
  const consentResolver = c.get('consentResolver');
  const config = c.get('config');

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
  await consentResolver?.recordGrant?.(
    session.subject,
    transaction.clientId,
    authCodeData.grantId,
  );

  return {
    kind: 'authorization_response',
    location: buildSuccessRedirect(
      transaction.redirectUri,
      authCodeData.code,
      transaction.state,
      issuer,
    ),
  };
}

/**
 * Interactive authentication: continue on the login screen (pages/login.tsx;
 * prompt=login forces re-authentication there), which finds the transaction
 * through the cookie that travels with this answer. OIDC Core 1.0 §3.1.2.3
 */
export function continueToLogin(transactionId: string, transactionTtlSeconds: number): AuthorizationOutcome {
  return { kind: 'login', cookies: [buildTransactionCookie(transactionId, transactionTtlSeconds)] };
}

/**
 * Map a failure of any step to the outcome: a redirectable error goes back to
 * the client with the state and iss (RFC 9207 §2); an error thrown before the
 * redirect_uri was verified stays on the OP (OIDC Core 1.0 §3.1.2.2: unknown
 * client_id, unregistered redirect_uri, redirect_uri with a fragment);
 * anything else is a server_error.
 */
export async function authorizationErrorOutcome(
  c: any,
  error: unknown,
): Promise<AuthorizationOutcome> {
  if (error instanceof AuthorizationError) {
    if (error.redirectUri) {
      return {
        kind: 'authorization_response',
        location: buildErrorRedirect(
          error.redirectUri,
          error.error,
          error.state,
          error.errorDescription,
          c.get('config').issuer,
        ),
      };
    }
    // OIDC Core 1.0 §3.1.2.2: errors that cannot be redirected MUST NOT
    // redirect to the supplied redirect_uri. They stay on the OP:
    // pages/authorize.ts answers programmatic callers (Accept:
    // application/json) with the OAuth error JSON and browsers with the OP's
    // own error page.
    return { kind: 'error', error: error.error, errorDescription: error.errorDescription };
  }
  return { kind: 'server_error' };
}

/**
 * Process one authorization request (OIDC Core 1.0 Section 3.1.2). Shared by
 * GET and POST /authorize (pages/authorize.ts).
 *
 * The pipeline: each statement below is one step function of this module, in
 * the order of the flow. A step that throws ends in authorizationErrorOutcome().
 */
export async function processAuthorizationRequest(c: any): Promise<AuthorizationOutcome> {
  try {
    // RFC 9207 §2: include the issuer identifier on every authorization
    // response (success and error) so clients can pin the issuer that
    // produced the response.
    const issuer: string = c.get('config').issuer;
    // [parse-request] Parse the authorization request — OIDC Core 1.0 §3.1.2.1 / §13.2
    const parsed = await parseAuthorizationRequest(c);
    if ('kind' in parsed) return parsed;
    const params = parsed.params;

    // [resolve-client] Resolve the client — OAuth 2.1 §4.1.2.1 / RFC 8252 §8
    const client = await resolveAuthorizationClient(c, params);

    // [resolve-request-object] Verify the Request Object and overlay its claims — OIDC Core 1.0 §6.1
    const { effectiveParams, requestObjectClaims } = await resolveRequestObject(c, params, client);

    // [resolve-redirect-uri] Resolve redirect_uri (errors become redirectable) — OIDC Core 1.0 §3.1.2.1 / RFC 6749 §4.1.2.1
    const { redirectUri, state } = resolveRedirectTarget(effectiveParams, client);

    // [validate-request] Validate the request parameters — OIDC Core 1.0 §3.1.2.1-§3.1.2.2 / OAuth 2.1 §4.1.1 / §7.5
    const validatedRequest = await validateAuthorizationRequestParams(c, { params, effectiveParams, requestObjectClaims, client, redirectUri, state });

    // [create-transaction] Create and store the authorization transaction — OIDC Core 1.0 §3.1.2.3
    const { transactionId, transaction, transactionTtlSeconds } = await createAuthorizationTransaction(c, validatedRequest);

    // [validate-prompt-combination] Reject prompt=none combined with other values — OIDC Core 1.0 §3.1.2.1
    // OIDC Core 1.0 Section 3.1.2.1: prompt is a space-delimited list
    const promptValues = transaction.prompt?.trim().split(/\s+/).filter(Boolean) ?? [];
    const promptCombinationError = await rejectCombinedPromptNone(c, promptValues, transactionId, transaction, issuer);
    if (promptCombinationError) return promptCombinationError;
    ;

    // [verify-id-token-hint] Verify id_token_hint — OIDC Core 1.0 §3.1.2.1
    const hint = await verifyIdTokenHint(c, transactionId, transaction, issuer);
    if ('kind' in hint) return hint;
    const { verifiedHintSubject } = hint;

    // [authenticate-silently] prompt=none: authenticate without interaction — OIDC Core 1.0 §3.1.2.1
    const silent = await completePromptNoneRequest(c, { promptValues, transactionId, transaction, verifiedHintSubject, issuer });
    if (silent !== undefined) {
      if ('kind' in silent) return silent;
      return issueAuthorizationCodeResponse(c, { transactionId, transaction, session: silent.session, issuer });
    }

    // [reuse-session] Single Sign-On: reuse the active OP session — OIDC Core 1.0 §3.1.2.3
    const sso = await reuseExistingSession(c, { promptValues, transactionId, transaction, transactionTtlSeconds, verifiedHintSubject });
    if (sso !== undefined) {
      if ('kind' in sso) return sso;
      return issueAuthorizationCodeResponse(c, { transactionId, transaction, session: sso.session, issuer });
    }

    // [continue-to-login] Continue on the login screen — OIDC Core 1.0 §3.1.2.3
    return continueToLogin(transactionId, transactionTtlSeconds);
  } catch (error) {
    return authorizationErrorOutcome(c, error);
  }
}
