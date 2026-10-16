/**
 * Login step (API layer: logic only).
 *
 * Everything the login screen has to decide lives here as plain functions, one
 * per box of `maronn-oidc graph --detail steps --endpoint login`: finding the
 * transaction through the transaction cookie (loadTransaction), the csrf_token
 * check (validateLoginCsrfToken), the credential check (authenticateEndUser),
 * the lockout (recordLoginFailure), the OP session cookie
 * (establishBrowserSession) and the hand-off to the consent step
 * (handOffToConsent). None of them builds a Response — each returns an
 * outcome, and pages/login.tsx turns that outcome into a screen or a redirect.
 * prepareLogin() (GET) and submitLogin() (POST) run them in the order the
 * screen needs, so the UI can be changed without touching this file.
 */
import {
  getAuthTransaction,
  validateCsrfToken,
  handleLoginFailure,
  generateRandomString,
  AuthTransactionError,
  type AuthTransaction,
} from '@maronn-openid-connect/core';
import {
  transactionStore as defaultTransactionStore,
  authSessionStore as defaultAuthSessionStore,
  browserSessionStore as defaultBrowserSessionStore,
  buildSessionCookie,
  parseSessionId,
  parseTransactionId,
  isSameOriginFormPost,
  CROSS_ORIGIN_FORM_POST_MESSAGE,
  userStore,
} from '../store.js';

/** What the login form needs: prepared for GET /login and again after a failed attempt. */
export interface LoginScreen {
  kind: 'screen';
  /**
   * Must be posted back as the csrf_token field. It is the only value the form
   * carries about the transaction: the transaction itself travels in the
   * transaction cookie, and POST /login accepts the token only for that one.
   */
  csrfToken: string;
  /**
   * OIDC Core 1.0 §3.1.2.1 login_hint: untrusted external value the OP MAY use
   * to pre-fill the login form.
   */
  loginHint?: string;
}

/** A failure the OP shows on its own error page (never redirected to the client). */
export interface LoginError {
  kind: 'error';
  error: string;
  errorDescription?: string;
  statusCode: number;
}

/** What POST /login decided; pages/login.tsx turns it into HTTP. */
export type LoginOutcome =
  | LoginError
  /** handleLoginFailure() locked the transaction: no further attempt is accepted (429). */
  | { kind: 'locked_out' }
  /** Wrong credentials: show the form again with the attempts left. */
  | { kind: 'invalid_credentials'; screen: LoginScreen; remainingAttempts: number }
  /** Signed in: the OP session cookie(s) to set, then continue to the consent step. */
  | { kind: 'authenticated'; cookies: string[] };

/** The fields of the login form. */
export interface LoginSubmission {
  csrfToken: string;
  username: string;
  password: string;
}

/**
 * The OP's own error page for a transaction that cannot continue: unknown,
 * finished or expired (400), or a csrf_token that does not belong to it (403).
 * It is never redirected to the client's redirect_uri: until the transaction
 * and its csrf_token check out, the OP cannot tell whose request this is.
 */
function transactionErrorOutcome(error: unknown): LoginError {
  if (!(error instanceof AuthTransactionError)) throw error;
  return { kind: 'error', error: error.message, statusCode: error.httpStatusCode };
}

/**
 * [load-transaction] The transaction this browser is in the middle of: the id
 * from the transaction cookie /authorize set (buildTransactionCookie() in
 * store.ts), loaded from the store. Returns the error to show instead when
 * there is none. OIDC Core 1.0 §3.1.2.3
 */
export async function loadTransaction(
  c: any,
): Promise<{ transactionId: string; transaction: AuthTransaction } | LoginError> {
  const transactionId = parseTransactionId(c.req.header('Cookie') ?? null);
  if (!transactionId) {
    return {
      kind: 'error',
      error: 'No authorization request is in progress in this browser. Start again from the application.',
      statusCode: 400,
    };
  }
  const loaded = await loadTransactionById(c, transactionId);
  if ('kind' in loaded) return loaded;
  return { transactionId, transaction: loaded.transaction };
}

/**
 * Load the transaction with a known id from the store, or the error to show
 * when it is unknown, finished or expired.
 */
export async function loadTransactionById(
  c: any,
  transactionId: string,
): Promise<{ transaction: AuthTransaction } | LoginError> {
  const transactionStore = c.get('transactionStore') ?? defaultTransactionStore;
  try {
    return { transaction: await getAuthTransaction(transactionId, transactionStore) };
  } catch (error) {
    return transactionErrorOutcome(error);
  }
}

/**
 * [reject-cross-origin-post] Refuse a login form POST that the browser says
 * came from anywhere but the OP's own pages (403, never redirected). See
 * isSameOriginFormPost() in store.ts.
 */
export function rejectCrossOriginFormPost(c: any): LoginError | undefined {
  const sameOrigin = isSameOriginFormPost(
    { origin: c.req.header('Origin') ?? null, secFetchSite: c.req.header('Sec-Fetch-Site') ?? null },
    c.get('config').issuer,
  );
  return sameOrigin ? undefined : { kind: 'error', error: CROSS_ORIGIN_FORM_POST_MESSAGE, statusCode: 403 };
}

/**
 * [validate-csrf-token] The csrf_token says the submission came from the form
 * the OP rendered for exactly this transaction; any other token is refused
 * (403) on the OP's own error page.
 */
export function validateLoginCsrfToken(
  transaction: AuthTransaction,
  csrfToken: string,
): LoginError | undefined {
  try {
    validateCsrfToken(transaction, csrfToken);
    return undefined;
  } catch (error) {
    return transactionErrorOutcome(error);
  }
}

/**
 * [describe-login-screen] Describe the form for a transaction (the shared part
 * of GET and a failed POST). OIDC Core 1.0 §3.1.2.1 (login_hint)
 */
export async function describeLoginScreen(
  transaction: AuthTransaction,
): Promise<LoginScreen> {
  return {
    kind: 'screen',
    csrfToken: transaction.csrfToken,
    loginHint: transaction.loginHint,
  };
}

/**
 * [authenticate-user] Check the credentials against the user store (or the
 * authenticateUser hook applyOidc() put on the request context). Returns the
 * End-User, or undefined when the credentials are wrong.
 */
export async function authenticateEndUser(
  c: any,
  username: string,
  password: string,
): Promise<{ sub: string } | undefined> {
  const authenticateUser =
    c.get('authenticateUser') ??
    ((u: string, p: string) => userStore.authenticate(u, p));
  return (await authenticateUser(username, password)) ?? undefined;
}

/**
 * [record-login-failure] Count the failed attempt on the transaction. Once the
 * attempts are used up the transaction is deleted (canRetry: false) and no
 * further attempt is accepted.
 */
export async function recordLoginFailure(
  c: any,
  transactionId: string,
  transaction: AuthTransaction,
): Promise<{ canRetry: boolean; remainingAttempts: number }> {
  const transactionStore = c.get('transactionStore') ?? defaultTransactionStore;
  const failure = await handleLoginFailure(transactionId, transaction, transactionStore);
  return {
    canRetry: failure.canRetry,
    remainingAttempts: failure.maxAttempts - failure.failedAttempts,
  };
}

/**
 * [discard-session-for-fresh-login] prompt=login (and prompt=select_account)
 * requires fresh authentication: discard any existing transaction hand-off AND
 * browser session before the new one is established. OIDC Core 1.0 §3.1.2.1
 * (prompt is a space-delimited list).
 */
export async function discardSessionForFreshLogin(
  c: any,
  transactionId: string,
  transaction: AuthTransaction,
): Promise<void> {
  const promptValues = transaction.prompt?.trim().split(/\s+/).filter(Boolean) ?? [];
  if (!promptValues.includes('login') && !promptValues.includes('select_account')) return;
  const authSessionStore = c.get('authSessionStore') ?? defaultAuthSessionStore;
  const browserSessionStore = c.get('browserSessionStore') ?? defaultBrowserSessionStore;
  await authSessionStore.delete(transactionId);
  const existingSessionId = parseSessionId(c.req.header('Cookie') ?? null);
  if (existingSessionId) await browserSessionStore.delete(existingSessionId);
}

/**
 * [establish-session] Establish the persistent browser (OP) session for the
 * authenticated subject. Its cookie travels with the answer so SSO,
 * prompt=none and max_age work on later authorization requests.
 * OIDC Core 1.0 §3.1.2.3
 */
export async function establishBrowserSession(
  c: any,
  subject: string,
): Promise<{ sessionId: string; authTime: number }> {
  const browserSessionStore = c.get('browserSessionStore') ?? defaultBrowserSessionStore;
  const authTime = Math.floor(Date.now() / 1000);
  const sessionId = await generateRandomString(32);
  await browserSessionStore.set(sessionId, { subject, authTime });
  return { sessionId, authTime };
}

/**
 * [hand-off-to-consent] Store the authenticated subject for the consent step
 * (the per-transaction hand-off) and answer with the session cookie. The
 * sessionId travels along for the online refresh token: the authorization code
 * the consent step issues inherits this session, so the refresh token stops
 * working at logout.
 */
export async function handOffToConsent(
  c: any,
  transactionId: string,
  subject: string,
  sessionId: string,
  authTime: number,
): Promise<{ kind: 'authenticated'; cookies: string[] }> {
  const authSessionStore = c.get('authSessionStore') ?? defaultAuthSessionStore;
  await authSessionStore.set(transactionId, { subject, authTime, sessionId });
  return { kind: 'authenticated', cookies: [buildSessionCookie(sessionId)] };
}

/**
 * GET /login: load the transaction this browser's cookie names and describe the
 * form, or the error to show instead when there is none.
 */
export async function prepareLogin(c: any): Promise<LoginScreen | LoginError> {
  // [load-transaction]
  const loaded = await loadTransaction(c);
  if ('kind' in loaded) return loaded;
  // [describe-login-screen]
  return describeLoginScreen(loaded.transaction);
}

/**
 * POST /login: check the credentials and, on success, establish the OP session.
 * The steps run in the fixed order the screen needs (the login endpoint of
 * `maronn-oidc graph --detail steps`).
 */
export async function submitLogin(c: any, input: LoginSubmission): Promise<LoginOutcome> {
  const { csrfToken, username, password } = input;

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

  // [validate-csrf-token] The csrf_token says the submission came from the form
  // the OP rendered for exactly that one.
  const csrfError = validateLoginCsrfToken(transaction, csrfToken);
  if (csrfError) return csrfError;

  // [authenticate-user]
  const user = await authenticateEndUser(c, username, password);
  if (!user) {
    // [record-login-failure] Wrong credentials: count the attempt, then either
    // lock the transaction or show the form again with the attempts left.
    const failure = await recordLoginFailure(c, transactionId, transaction);
    if (!failure.canRetry) {
      return { kind: 'locked_out' };
    }
    return {
      kind: 'invalid_credentials',
      screen: await describeLoginScreen(transaction),
      remainingAttempts: failure.remainingAttempts,
    };
  }

  // [discard-session-for-fresh-login]
  await discardSessionForFreshLogin(c, transactionId, transaction);
  // [establish-session]
  const { sessionId, authTime } = await establishBrowserSession(c, user.sub);
  // [hand-off-to-consent]
  return handOffToConsent(c, transactionId, user.sub, sessionId, authTime);
}
