/** @jsxImportSource hono/jsx */
/**
 * Consent screen (screen routing layer).
 *
 * GET /consent renders the approve / deny form and POST /consent submits it.
 * Neither handler holds OIDC logic: prepareConsent() and submitConsent() in
 * routes/consent.ts find the transaction through the transaction cookie, check
 * the csrf_token, record the decision, mint the authorization code and build
 * the authorization response URL, and report what happened as an outcome. This file turns each
 * outcome into a screen or a redirect. To customize the consent UI, edit this
 * file or the consentPage view in views.tsx; routes/consent.ts never has to
 * change. Keep the two button values ('approve' / 'deny') as they are: the
 * logic accepts exactly those.
 */
import { Hono } from 'hono';
import { prepareConsent, submitConsent } from '../routes/consent.js';
import { defaultViews, renderView, type ConsentPageParams, type Views } from '../views.js';
import { renderErrorPage } from './errors.js';
import { redirectWithCookies } from './respond.js';

export const consentPage = new Hono<{ Variables: Record<string, any> }>();

/**
 * Render the consent form. Swap the view, return a framework-rendered Response,
 * or redirect to a UI of your own — here only.
 */
export function renderConsentPage(c: any, params: ConsentPageParams): Response {
  const views: Views = c.get('views') ?? defaultViews;
  return renderView(<views.consentPage {...params} />);
}

/**
 * Consent Page - GET
 * Displays the consent form for the transaction in this browser's cookie.
 */
consentPage.get('/', async (c) => {
  const screen = await prepareConsent(c);
  if (screen.kind === 'error') return renderErrorPage(c, screen);
  return renderConsentPage(c, {
    csrfToken: screen.csrfToken,
    scopes: screen.scopes,
    clientId: screen.clientId,
  });
});

/**
 * Consent Handler - POST
 * Submits the consent decision and sends the browser on.
 */
consentPage.post('/', async (c) => {
  const body = await c.req.parseBody();
  const outcome = await submitConsent(c, {
    csrfToken: String(body['csrf_token'] ?? ''),
    action: String(body['action'] ?? ''),
  });

  if (outcome.kind === 'error') return renderErrorPage(c, outcome);
  if (outcome.kind === 'invalid_decision') {
    // OIDC Core 1.0 Section 3.1.2.4 / 3.1.2.6: no decision was obtained, which
    // is not the same as the End-User denying — so the browser stays on the OP's
    // own error page instead of being sent back to the client. 'approve' and
    // 'deny' are the values the logic accepts; the buttons in views.tsx
    // consentPage() must keep sending exactly those.
    return renderErrorPage(c, {
      error: 'Invalid consent decision. Please use the Approve or Deny button.',
      statusCode: 400,
    });
  }
  if (outcome.kind === 'session_missing') {
    return renderErrorPage(c, {
      error: 'Authentication session not found. Please restart login.',
      statusCode: 400,
    });
  }
  // Approved or denied: the authorization response is already in the URL.
  return redirectWithCookies(outcome.location, outcome.cookies);
});
