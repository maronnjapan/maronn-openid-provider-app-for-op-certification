/** @jsxImportSource hono/jsx */
/**
 * Login screen (screen routing layer).
 *
 * GET /login renders the form and POST /login submits it. Neither handler
 * holds OIDC logic: prepareLogin() and submitLogin() in routes/login.ts find
 * the transaction through the transaction cookie, check the csrf_token, verify
 * the credentials and mint the OP session, and report what happened as an
 * outcome. Neither the URL nor the form names the transaction: the form only
 * embeds csrf_token, which is accepted together with the cookie. This file turns
 * each outcome into a screen or a redirect. To customize the login UI, edit
 * this file or the loginPage view in views.tsx; routes/login.ts never has to
 * change.
 */
import { Hono } from 'hono';
import { defaultProviderConfig } from '../config.js';
import { prepareLogin, submitLogin, type LoginScreen } from '../routes/login.js';
import { defaultViews, renderView, type LoginPageParams, type Views } from '../views.js';
import { renderErrorPage } from './errors.js';
import { redirectWithCookies } from './respond.js';

export const loginPage = new Hono<{ Variables: Record<string, any> }>();

/**
 * Render the login form. Swap the view, return a framework-rendered Response,
 * or redirect to a UI of your own — here only.
 */
export function renderLoginPage(c: any, params: LoginPageParams): Response {
  const views: Views = c.get('views') ?? defaultViews;
  return renderView(<views.loginPage {...params} />);
}

/**
 * Map what the logic prepared for the form onto the view's parameters. Extend
 * this when your login view needs more than the defaults.
 */
function loginPageParams(screen: LoginScreen): LoginPageParams {
  return {
    csrfToken: screen.csrfToken,
    // OIDC Core 1.0 §3.1.2.1: pre-fill the login form with login_hint (RECOMMENDED).
    loginHint: screen.loginHint,
  };
}

/**
 * Where a signed-in End-User continues: the consent screen, which finds the
 * transaction through the same cookie. Built on config.issuer, not the request
 * URL — some runtimes derive the request URL from the Host header, which would
 * let the sender pick the redirect origin (OIDC Discovery 1.0 §3 / RFC 9700
 * §2.1).
 */
function consentScreenUrl(c: any): string {
  const config = c.get('config') ?? defaultProviderConfig;
  return new URL('/consent', config.issuer).toString();
}

/**
 * Login Page - GET
 * Displays the login form for the transaction in this browser's cookie.
 */
loginPage.get('/', async (c) => {
  const screen = await prepareLogin(c);
  if (screen.kind === 'error') return renderErrorPage(c, screen);
  return renderLoginPage(c, loginPageParams(screen));
});

/**
 * Login Handler - POST
 * Submits the login form and shows the next screen.
 */
loginPage.post('/', async (c) => {
  const body = await c.req.parseBody();
  const outcome = await submitLogin(c, {
    csrfToken: String(body['csrf_token'] ?? ''),
    username: String(body['username'] ?? ''),
    password: String(body['password'] ?? ''),
  });

  if (outcome.kind === 'error') return renderErrorPage(c, outcome);
  if (outcome.kind === 'locked_out') {
    return renderErrorPage(c, {
      error: 'Too many login attempts',
      statusCode: 429,
    });
  }
  if (outcome.kind === 'invalid_credentials') {
    // The same form again, with the failure shown.
    return renderLoginPage(c, {
      ...loginPageParams(outcome.screen),
      error: 'Invalid credentials',
      remainingAttempts: outcome.remainingAttempts,
    });
  }
  // Signed in: set the OP session cookie and continue to the consent step.
  return redirectWithCookies(consentScreenUrl(c), outcome.cookies);
});
