/** @jsxImportSource hono/jsx */
/**
 * Error screen (screen routing layer).
 *
 * Whenever a page has to stop the browser on the OP's own error page it calls
 * renderErrorPage() here. Customize the error UI in views.tsx (errorPage), or
 * change how it is delivered in this file — for example by redirecting to a
 * page of your own.
 */
import { defaultViews, renderView, type ErrorPageParams, type Views } from '../views.js';

/**
 * Render the OP's error page.
 *
 * params.statusCode is both the HTTP status of the response and the value the
 * view receives, so a custom view can show it and the status never diverges
 * from the message (a 429 lockout page answers 429, a 403 binding failure 403).
 */
export function renderErrorPage(c: any, params: ErrorPageParams): Response {
  const views: Views = c.get('views') ?? defaultViews;
  return renderView(<views.errorPage {...params} />, { status: params.statusCode });
}

/**
 * Deliver a non-redirectable authorization error (OIDC Core 1.0 §3.1.2.2) to
 * the browser.
 *
 * An unknown client_id, an unregistered redirect_uri or a redirect_uri with a
 * fragment leaves the OP without a redirect target it may trust, so the error
 * MUST stay on the OP (RFC 6749 §4.1.2.1): the error view is answered as an
 * HTML 400 response.
 */
export function renderAuthorizationErrorPage(
  c: any,
  params: { error: string; errorDescription?: string },
): Response {
  return renderErrorPage(c, {
    error: params.error,
    errorDescription: params.errorDescription,
    statusCode: 400,
  });
}
