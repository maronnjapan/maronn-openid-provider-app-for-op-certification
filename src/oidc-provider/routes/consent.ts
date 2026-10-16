/**
 * Consent step (API layer: logic only).
 *
 * Everything the consent screen has to decide lives here as plain functions:
 * finding the transaction through the transaction cookie, the csrf_token
 * check, the scope policy, the authorization decision, the authorization code,
 * the consent record and the authorization response URL (RFC 6749 §4.1.2 /
 * RFC 9207 iss / JARM). None of them builds a Response — each returns an
 * outcome, and pages/consent.tsx turns that outcome into a screen or a
 * redirect. The UI can therefore be changed without touching this file.
 */
import {
  getAuthTransaction,
  validateCsrfToken,
  completeAuthTransaction,
  createAuthorizationCode,
  AuthTransactionError,
  type AuthTransaction,
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
 * The transaction this browser is in the middle of: the id from the transaction
 * cookie /authorize set (buildTransactionCookie() in store.ts), loaded from the
 * store. Returns the error to show instead when there is none.
 */
async function loadTransaction(
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
 * Refuse a consent form POST that the browser says came from anywhere but the
 * OP's own pages (403, never redirected). See isSameOriginFormPost() in store.ts.
 */
function rejectCrossOriginFormPost(c: any): ConsentError | undefined {
  const sameOrigin = isSameOriginFormPost(
    { origin: c.req.header('Origin') ?? null, secFetchSite: c.req.header('Sec-Fetch-Site') ?? null },
    c.get('config').issuer,
  );
  return sameOrigin ? undefined : { kind: 'error', error: CROSS_ORIGIN_FORM_POST_MESSAGE, statusCode: 403 };
}

/**
 * GET /consent: load the transaction this browser's cookie names and describe
 * the form, or the error to show instead when there is none.
 */
export async function prepareConsent(c: any): Promise<ConsentScreen | ConsentError> {
  const loaded = await loadTransaction(c);
  if ('kind' in loaded) return loaded;
  const { transaction } = loaded;
  return {
    kind: 'screen',
    csrfToken: transaction.csrfToken,
    scopes: transaction.scope.split(' ').filter(Boolean),
    clientId: transaction.clientId,
  };
}

/**
 * POST /consent: record the decision and build the authorization response.
 */
export async function submitConsent(c: any, input: ConsentSubmission): Promise<ConsentOutcome> {
  const { csrfToken, action } = input;

  const transactionStore = c.get('transactionStore') ?? defaultTransactionStore;
  const authCodeStore = c.get('authCodeStore') ?? defaultAuthCodeStore;
  const authSessionStore = c.get('authSessionStore') ?? defaultAuthSessionStore;

  // Checked before any decision is acted on: this step mints the authorization
  // code, so neither an approval nor a denial may come from anywhere else.
  // First the browser's own statement of where the form was submitted from
  // (isSameOriginFormPost() in store.ts): independent of the cookie and the
  // csrf_token, so a forged POST is stopped even if both were planted.
  const sameOriginError = rejectCrossOriginFormPost(c);
  if (sameOriginError) return sameOriginError;

  // The cookie says which transaction this browser is in; the csrf_token says
  // the decision came from the form the OP rendered for exactly that one.
  const loaded = await loadTransaction(c);
  if ('kind' in loaded) return loaded;
  const { transactionId, transaction } = loaded;
  try {
    validateCsrfToken(transaction, csrfToken);
  } catch (error) {
    return transactionErrorOutcome(error);
  }

  // RFC 9207 §2: include the issuer identifier on every authorization response
  // (success and error) so clients can pin the issuer that produced the response.
  const config = c.get('config');
  const issuer = config.issuer;

  if (action === 'deny') {
    const redirectUrl = new URL(transaction.redirectUri);
    redirectUrl.searchParams.set('error', 'access_denied');
    if (transaction.state) {
      redirectUrl.searchParams.set('state', transaction.state);
    }
    redirectUrl.searchParams.set('iss', issuer);
    await transactionStore.delete('auth_txn:' + transactionId);
    await authSessionStore.delete(transactionId);
    return { kind: 'authorization_response', location: redirectUrl.toString(), cookies: [buildClearedTransactionCookie()] };
  }

  // OIDC Core 1.0 Section 3.1.2.4: "the Authorization Server MUST obtain an
  // authorization decision before releasing information to the Relying Party."
  // The affirmative decision is therefore detected on an allowlist: a missing,
  // empty or unknown 'action' means no decision was obtained, so it must not
  // approve. Deciding by "not deny" would approve every unexpected value instead.
  //
  // 'approve' is the decision value this provider accepts, and it MUST stay in
  // sync with the Approve button in views.tsx consentPage(). Changing it here
  // without changing the button (or the other way round) makes every approval
  // fail with the 400 pages/consent.tsx shows for this outcome.
  //
  // Section 3.1.2.6: access_denied means the End-User denied the request, which
  // is not the same as no decision at all — an unrecognized value stops here on
  // the OP's own error page instead of being redirected back to the client.
  if (action !== 'approve') {
    return { kind: 'invalid_decision' };
  }

  const session = await authSessionStore.get(transactionId);
  if (!session) {
    return { kind: 'session_missing' };
  }

  const responseParams = await completeAuthTransaction(
    transactionId,
    transaction,
    transactionStore,
  );

  // transaction.scope は認可リクエスト検証時に applyOfflineAccessPolicy を通した後の値。
  // offline_access の可否（OIDC Core 1.0 §11 の prompt=consent と、クライアント登録
  // grant_types に refresh_token があるか）はそこで確定しているので再フィルタしない。
  const grantedScope = transaction.scope.split(' ').filter(Boolean);

  // Generate authorization code via core helper
  // OIDC Core 1.0 Section 3.1.3.1: TTL is configurable via ProviderConfig
  // (defaults to 300 seconds — 5 minutes).
  const authCodeData = await createAuthorizationCode({
    authorizationResponse: { ...responseParams, scope: grantedScope },
    subject: session.subject,
    authTime: session.authTime,
    // online refresh token をこのログインセッションへ束縛する（login step が
    // authSessionStore へ載せた値）。ログアウトすれば RT も使えなくなる。
    sessionId: session.sessionId,
    ttlSeconds: config.authorizationCodeTtl,
  });
  await authCodeStore.set(authCodeData.code, authCodeData);

  // Record consent so a later prompt=none (or non-interactive SSO) request can
  // confirm it without UI (OIDC Core 1.0 Section 3.1.2.1 / 3.1.2.4). Routed
  // through the consentResolver so a custom store can override persistence.
  // Only the per-transaction handoff is cleared below; the browser (OP) session
  // persists so SSO keeps working.
  const consentResolver = c.get('consentResolver') ?? defaultConsentResolver;
  await consentResolver.recordConsent?.(session.subject, transaction.clientId, grantedScope);
  await consentResolver.recordGrant?.(
    session.subject,
    transaction.clientId,
    authCodeData.grantId,
  );

  await authSessionStore.delete(transactionId);

  // Back to the client with the authorization code
  const redirectUrl = new URL(responseParams.redirectUri);
  redirectUrl.searchParams.set('code', authCodeData.code);
  if (responseParams.state) {
    redirectUrl.searchParams.set('state', responseParams.state);
  }
  redirectUrl.searchParams.set('iss', issuer);
  return { kind: 'authorization_response', location: redirectUrl.toString(), cookies: [buildClearedTransactionCookie()] };
}
