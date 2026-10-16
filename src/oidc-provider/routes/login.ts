/**
 * Login step (API layer: logic only).
 *
 * Everything the login screen has to decide lives here as plain functions:
 * finding the transaction through the transaction cookie, the csrf_token
 * check, the credential check, the lockout, the OP session cookie and the
 * hand-off to the consent step. None of them builds a Response — each returns
 * an outcome, and pages/login.tsx turns that outcome into a screen or a
 * redirect. The UI can therefore be changed without touching this file.
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
 * The transaction this browser is in the middle of: the id from the transaction
 * cookie /authorize set (buildTransactionCookie() in store.ts), loaded from the
 * store. Returns the error to show instead when there is none.
 */
async function loadTransaction(
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
  const transactionStore = c.get('transactionStore') ?? defaultTransactionStore;
  try {
    return { transactionId, transaction: await getAuthTransaction(transactionId, transactionStore) };
  } catch (error) {
    return transactionErrorOutcome(error);
  }
}

/**
 * Refuse a login form POST that the browser says came from anywhere but the
 * OP's own pages (403, never redirected). See isSameOriginFormPost() in store.ts.
 */
function rejectCrossOriginFormPost(c: any): LoginError | undefined {
  const sameOrigin = isSameOriginFormPost(
    { origin: c.req.header('Origin') ?? null, secFetchSite: c.req.header('Sec-Fetch-Site') ?? null },
    c.get('config').issuer,
  );
  return sameOrigin ? undefined : { kind: 'error', error: CROSS_ORIGIN_FORM_POST_MESSAGE, statusCode: 403 };
}

/** Describe the form for a transaction (the shared part of GET and a failed POST). */
async function describeLoginScreen(
  transaction: AuthTransaction,
): Promise<LoginScreen> {
  return {
    kind: 'screen',
    csrfToken: transaction.csrfToken,
    loginHint: transaction.loginHint,
  };
}

/**
 * GET /login: load the transaction this browser's cookie names and describe the
 * form, or the error to show instead when there is none.
 */
export async function prepareLogin(c: any): Promise<LoginScreen | LoginError> {
  const loaded = await loadTransaction(c);
  if ('kind' in loaded) return loaded;
  return describeLoginScreen(loaded.transaction);
}

/**
 * POST /login: check the credentials and, on success, establish the OP session.
 */
export async function submitLogin(c: any, input: LoginSubmission): Promise<LoginOutcome> {
  const { csrfToken, username, password } = input;

  const transactionStore = c.get('transactionStore') ?? defaultTransactionStore;
  const authSessionStore = c.get('authSessionStore') ?? defaultAuthSessionStore;
  const browserSessionStore = c.get('browserSessionStore') ?? defaultBrowserSessionStore;
  const authenticateUser =
    c.get('authenticateUser') ??
    ((u: string, p: string) => userStore.authenticate(u, p));

  // First the browser's own statement of where the form was submitted from
  // (isSameOriginFormPost() in store.ts): independent of the cookie and the
  // csrf_token, so a forged POST is stopped even if both were planted.
  const sameOriginError = rejectCrossOriginFormPost(c);
  if (sameOriginError) return sameOriginError;

  // The cookie says which transaction this browser is in; the csrf_token says
  // the submission came from the form the OP rendered for exactly that one.
  const loaded = await loadTransaction(c);
  if ('kind' in loaded) return loaded;
  const { transactionId, transaction } = loaded;
  try {
    validateCsrfToken(transaction, csrfToken);
  } catch (error) {
    return transactionErrorOutcome(error);
  }

  // Authenticate user
  const user = await authenticateUser(username, password);
  if (!user) {
    const failureResult = await handleLoginFailure(
      transactionId,
      transaction,
      transactionStore,
    );
    if (!failureResult.canRetry) {
      return { kind: 'locked_out' };
    }
    return {
      kind: 'invalid_credentials',
      screen: await describeLoginScreen(transaction),
      remainingAttempts: failureResult.maxAttempts - failureResult.failedAttempts,
    };
  }

  // prompt=login (and prompt=select_account in Phase 1) requires fresh
  // authentication: discard any existing transaction handoff AND browser session.
  // OIDC Core 1.0 Section 3.1.2.1 — prompt is a space-delimited list, use includes()
  const loginPromptValues = transaction.prompt?.trim().split(/\s+/).filter(Boolean) ?? [];
  if (loginPromptValues.includes('login') || loginPromptValues.includes('select_account')) {
    await authSessionStore.delete(transactionId);
    const existingSessionId = parseSessionId(c.req.header('Cookie') ?? null);
    if (existingSessionId) await browserSessionStore.delete(existingSessionId);
  }

  const authTime = Math.floor(Date.now() / 1000);

  // Establish a persistent browser (OP) session; its cookie travels with the
  // answer so SSO / prompt=none / max_age work on subsequent authorization
  // requests (OIDC Core 1.0 Section 3.1.2.3).
  const sessionId = await generateRandomString(32);
  await browserSessionStore.set(sessionId, { subject: user.sub, authTime });

  // Store authenticated subject for the consent step (per-transaction handoff).
  // sessionId も渡すのは online refresh token のため。consent 経由で発行する認可
  // コードにこのセッションを引き継ぎ、ログアウトで使えなくなる RT を作る。
  await authSessionStore.set(transactionId, {
    subject: user.sub,
    authTime,
    sessionId,
  });

  return { kind: 'authenticated', cookies: [buildSessionCookie(sessionId)] };
}
