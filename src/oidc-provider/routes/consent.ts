/**
 * Consent step (API layer: logic only).
 *
 * Everything the consent screen has to decide lives here as plain functions,
 * one per box of `maronn-oidc graph --detail steps --endpoint consent`:
 * finding the transaction through the transaction cookie (loadTransaction),
 * the csrf_token check (validateConsentCsrfToken), the scope policy and the
 * form (describeConsentScreen), the authorization decision
 * (validateConsentDecision, denyAuthorizationRequest), the authorization code
 * (issueConsentedAuthorizationCode), the consent record
 * (recordConsentDecision) and the authorization response URL
 * (buildConsentRedirect: RFC 6749 §4.1.2 / RFC 9207 iss / JARM). None of them
 * builds a Response — each returns an outcome, and pages/consent.tsx turns that
 * outcome into a screen or a redirect. prepareConsent() (GET) and
 * submitConsent() (POST) run them in the order the screen needs, so the UI can
 * be changed without touching this file.
 */
import {
  getAuthTransaction,
  validateCsrfToken,
  completeAuthTransaction,
  createAuthorizationCode,
  AuthTransactionError,
  type AuthTransaction,
  type AuthorizationCodeData,
  type AuthorizationResponseParams,
} from '@maronn-openid-connect/core';
import {
  consentResolver as defaultConsentResolver,
} from '../resolvers.js';
import {
  transactionStore as defaultTransactionStore,
  authCodeStore as defaultAuthCodeStore,
  authSessionStore as defaultAuthSessionStore,
  buildClearedTransactionCookie,
  parseTransactionId,
  isSameOriginFormPost,
  CROSS_ORIGIN_FORM_POST_MESSAGE,
  type AuthSessionInfo,
} from '../store.js';

/** What the consent form needs, prepared for GET /consent. */
export interface ConsentScreen {
  kind: 'screen';
  /**
   * Must be posted back as the csrf_token field. It is the only value the form
   * carries about the transaction: the transaction itself travels in the
   * transaction cookie, and POST /consent accepts the token only for that one.
   */
  csrfToken: string;
  /** Scopes this End-User is asked to grant (already narrowed by the scope policy). */
  scopes: string[];
  /** Client requesting the authorization. */
  clientId: string;
}

/** A failure the OP shows on its own error page (never redirected to the client). */
export interface ConsentError {
  kind: 'error';
  error: string;
  errorDescription?: string;
  statusCode: number;
}

/** What POST /consent decided; pages/consent.tsx turns it into HTTP. */
export type ConsentOutcome =
  | ConsentError
  /**
   * OIDC Core 1.0 Section 3.1.2.4: no decision was obtained — action was
   * missing, empty or unknown. Not access_denied (Section 3.1.2.6), so the
   * browser stays on the OP (400).
   */
  | { kind: 'invalid_decision' }
  /** No authenticated subject for this transaction: the login step was skipped or expired (400). */
  | { kind: 'session_missing' }
  /** Approved or denied: the authorization response for the client, ready in the URL. */
  | { kind: 'authorization_response'; location: string; cookies: string[] };

/** The fields of the consent form. */
export interface ConsentSubmission {
  csrfToken: string;
  /** 'approve' or 'deny' — the submit button values of the consent view. */
  action: string;
}

/** What the approved request was issued: the response parameters, the code and the granted scope. */
export interface ConsentedAuthorization {
  responseParams: AuthorizationResponseParams;
  authCodeData: AuthorizationCodeData;
  grantedScope: string[];
}

/**
 * The OP's own error page for a transaction that cannot continue: unknown,
 * finished or expired (400), or a csrf_token that does not belong to it (403).
 * It is never redirected to the client's redirect_uri: until the transaction
 * and its csrf_token check out, the OP cannot tell whose request this is, and
 * answering the client could hand a code for this End-User to someone else.
 */
function transactionErrorOutcome(error: unknown): ConsentError {
  if (!(error instanceof AuthTransactionError)) throw error;
  return { kind: 'error', error: error.message, statusCode: error.httpStatusCode };
}

/**
 * [load-transaction] The transaction this browser is in the middle of: the id
 * from the transaction cookie /authorize set (buildTransactionCookie() in
 * store.ts), loaded from the store. Returns the error to show instead when
 * there is none. OIDC Core 1.0 §3.1.2.4
 */
export async function loadTransaction(
  c: any,
): Promise<{ transactionId: string; transaction: AuthTransaction } | ConsentError> {
  const transactionId = parseTransactionId(c.req.header('Cookie') ?? null);
  if (!transactionId) {
    return {
      kind: 'error',
      error: 'No authorization request is in progress in this browser. Start again from the application.',
      statusCode: 400,
    };
  }
  const transactionStore = c.get('transactionStore') ?? defaultTransactionStore;
  try {
    return { transactionId, transaction: await getAuthTransaction(transactionId, transactionStore) };
  } catch (error) {
    return transactionErrorOutcome(error);
  }
}

/**
 * [describe-consent-screen] Describe the form for a transaction: the
 * csrf_token, the client and the scopes this End-User is asked to grant.
 */
export async function describeConsentScreen(
  transaction: AuthTransaction,
): Promise<ConsentScreen> {
  return {
    kind: 'screen',
    csrfToken: transaction.csrfToken,
    scopes: transaction.scope.split(' ').filter(Boolean),
    clientId: transaction.clientId,
  };
}

/**
 * [reject-cross-origin-post] Refuse a consent form POST that the browser says
 * came from anywhere but the OP's own pages (403, never redirected). See
 * isSameOriginFormPost() in store.ts.
 */
export function rejectCrossOriginFormPost(c: any): ConsentError | undefined {
  const sameOrigin = isSameOriginFormPost(
    { origin: c.req.header('Origin') ?? null, secFetchSite: c.req.header('Sec-Fetch-Site') ?? null },
    c.get('config').issuer,
  );
  return sameOrigin ? undefined : { kind: 'error', error: CROSS_ORIGIN_FORM_POST_MESSAGE, statusCode: 403 };
}

/**
 * [validate-csrf-token] The csrf_token says the decision came from the form
 * the OP rendered for exactly this transaction; any other token is refused
 * (403) on the OP's own error page.
 */
export function validateConsentCsrfToken(
  transaction: AuthTransaction,
  csrfToken: string,
): ConsentError | undefined {
  try {
    validateCsrfToken(transaction, csrfToken);
    return undefined;
  } catch (error) {
    return transactionErrorOutcome(error);
  }
}

/**
 * [build-authorization-response] Build the authorization response for the
 * client: its redirect_uri with the parameters, plus RFC 9207 §2 iss so
 * clients can pin the issuer that produced the response.
 */
export function buildConsentRedirect(
  redirectUri: string,
  parameters: Record<string, string | undefined>,
  issuer: string,
): ConsentOutcome {
  const url = new URL(redirectUri);
  for (const [name, value] of Object.entries(parameters)) {
    if (value) url.searchParams.set(name, value);
  }
  url.searchParams.set('iss', issuer);
  return { kind: 'authorization_response', location: url.toString(), cookies: [buildClearedTransactionCookie()] };
}

/**
 * [deny-authorization] The End-User denied the request: finish the transaction
 * and answer access_denied to the client. OIDC Core 1.0 §3.1.2.6
 */
export async function denyAuthorizationRequest(
  c: any,
  transactionId: string,
  transaction: AuthTransaction,
  issuer: string,
): Promise<ConsentOutcome> {
  const transactionStore = c.get('transactionStore') ?? defaultTransactionStore;
  const authSessionStore = c.get('authSessionStore') ?? defaultAuthSessionStore;
  await transactionStore.delete('auth_txn:' + transactionId);
  await authSessionStore.delete(transactionId);
  return buildConsentRedirect(transaction.redirectUri, {
    error: 'access_denied',
    state: transaction.state,
  }, issuer);
}

/**
 * [validate-decision] OIDC Core 1.0 Section 3.1.2.4: "the Authorization Server
 * MUST obtain an authorization decision before releasing information to the
 * Relying Party." The affirmative decision is therefore detected on an
 * allowlist: a missing, empty or unknown 'action' means no decision was
 * obtained, so it must not approve. Deciding by "not deny" would approve every
 * unexpected value instead.
 *
 * 'approve' is the decision value this provider accepts, and it MUST stay in
 * sync with the Approve button in views.tsx consentPage(). Changing it here
 * without changing the button (or the other way round) makes every approval
 * fail with the 400 pages/consent.tsx shows for this outcome.
 *
 * Section 3.1.2.6: access_denied means the End-User denied the request, which
 * is not the same as no decision at all — an unrecognized value stops here on
 * the OP's own error page instead of being redirected back to the client.
 */
export function validateConsentDecision(action: string): ConsentOutcome | undefined {
  return action === 'approve' ? undefined : { kind: 'invalid_decision' };
}

/**
 * [require-authenticated-subject] The subject the login step stored for this
 * transaction (the per-transaction hand-off). Without one the login step was
 * skipped or has expired, and no code may be issued.
 */
export async function requireAuthenticatedSubject(
  c: any,
  transactionId: string,
): Promise<AuthSessionInfo | undefined> {
  const authSessionStore = c.get('authSessionStore') ?? defaultAuthSessionStore;
  return (await authSessionStore.get(transactionId)) ?? undefined;
}

/**
 * [issue-authorization-code] Finish the transaction and issue the
 * authorization code for the granted scope. OIDC Core 1.0 §3.1.2.5 / §3.1.3.1
 * (the code lives config.authorizationCodeTtl seconds, 300 by default).
 *
 * transaction.scope already went through applyOfflineAccessPolicy when the
 * authorization request was validated: whether offline_access may be granted
 * (OIDC Core 1.0 §11 prompt=consent, and refresh_token among the client's
 * registered grant_types) was settled there, so it is not filtered again.
 */
export async function issueConsentedAuthorizationCode(
  c: any,
  transactionId: string,
  transaction: AuthTransaction,
  session: AuthSessionInfo,
): Promise<ConsentedAuthorization> {
  const config = c.get('config');
  const transactionStore = c.get('transactionStore') ?? defaultTransactionStore;
  const authCodeStore = c.get('authCodeStore') ?? defaultAuthCodeStore;
  const responseParams = await completeAuthTransaction(transactionId, transaction, transactionStore);
  const grantedScope = transaction.scope.split(' ').filter(Boolean);
  const authCodeData = await createAuthorizationCode({
    authorizationResponse: { ...responseParams, scope: grantedScope },
    subject: session.subject,
    authTime: session.authTime,
    // Bind the online refresh token to this login session (the sessionId the
    // login step put on the auth session): logging out revokes that token too.
    sessionId: session.sessionId,
    ttlSeconds: config.authorizationCodeTtl,
  });
  await authCodeStore.set(authCodeData.code, authCodeData);
  return { responseParams, authCodeData, grantedScope };
}

/**
 * [record-consent] Record the consent and the grant so a later prompt=none (or
 * non-interactive SSO) request can confirm it without UI, then clear the
 * per-transaction hand-off. Routed through the consentResolver so a custom
 * store can override persistence. Only the hand-off is cleared; the browser
 * (OP) session persists so SSO keeps working. OIDC Core 1.0 §3.1.2.1 / §3.1.2.4
 */
export async function recordConsentDecision(
  c: any,
  transactionId: string,
  transaction: AuthTransaction,
  session: AuthSessionInfo,
  authCodeData: AuthorizationCodeData,
  grantedScope: string[],
): Promise<void> {
  const authSessionStore = c.get('authSessionStore') ?? defaultAuthSessionStore;
  const consentResolver = c.get('consentResolver') ?? defaultConsentResolver;
  await consentResolver.recordConsent?.(session.subject, transaction.clientId, grantedScope);
  await consentResolver.recordGrant?.(
    session.subject,
    transaction.clientId,
    authCodeData.grantId,
  );
  await authSessionStore.delete(transactionId);
}

/**
 * GET /consent: load the transaction this browser's cookie names and describe
 * the form, or the error to show instead when there is none.
 */
export async function prepareConsent(c: any): Promise<ConsentScreen | ConsentError> {
  // [load-transaction]
  const loaded = await loadTransaction(c);
  if ('kind' in loaded) return loaded;
  const { transaction } = loaded;
  // [describe-consent-screen]
  return describeConsentScreen(transaction);
}

/**
 * POST /consent: record the decision and build the authorization response. The
 * steps run in the fixed order the screen needs (the consent endpoint of
 * `maronn-oidc graph --detail steps`).
 */
export async function submitConsent(c: any, input: ConsentSubmission): Promise<ConsentOutcome> {
  const { csrfToken, action } = input;

  // Checked before any decision is acted on: this step mints the authorization
  // code, so neither an approval nor a denial may come from anywhere else.
  // [reject-cross-origin-post] First the browser's own statement of where the
  // form was submitted from (isSameOriginFormPost() in store.ts): independent
  // of the cookie and the csrf_token, so a forged POST is stopped even if both
  // were planted.
  const sameOriginError = rejectCrossOriginFormPost(c);
  if (sameOriginError) return sameOriginError;

  // [load-transaction] The cookie says which transaction this browser is in.
  const loaded = await loadTransaction(c);
  if ('kind' in loaded) return loaded;
  const { transactionId, transaction } = loaded;

  // [validate-csrf-token] The csrf_token says the decision came from the form
  // the OP rendered for exactly that one.
  const csrfError = validateConsentCsrfToken(transaction, csrfToken);
  if (csrfError) return csrfError;

  // RFC 9207 §2: include the issuer identifier on every authorization response
  // (success and error) so clients can pin the issuer that produced the response.
  const issuer: string = c.get('config').issuer;

  // [deny-authorization]
  if (action === 'deny') {
    return denyAuthorizationRequest(c, transactionId, transaction, issuer);
  }

  // [validate-decision]
  const decisionError = validateConsentDecision(action);
  if (decisionError) return decisionError;

  // [require-authenticated-subject]
  const session = await requireAuthenticatedSubject(c, transactionId);
  if (!session) {
    return { kind: 'session_missing' };
  }

  // [issue-authorization-code]
  const { responseParams, authCodeData, grantedScope } = await issueConsentedAuthorizationCode(
    c,
    transactionId,
    transaction,
    session,
  );

  // [record-consent]
  await recordConsentDecision(c, transactionId, transaction, session, authCodeData, grantedScope);

  // [build-authorization-response] Back to the client with the authorization code.
  return buildConsentRedirect(responseParams.redirectUri, {
    code: authCodeData.code,
    state: responseParams.state,
  }, issuer);
}
