/**
 * Authorization endpoint (screen routing layer).
 *
 * GET|POST /authorize is the browser's entry into the flow, and every answer it
 * gives is a redirect or a screen: back to the client with the authorization
 * response, on to /login or /consent, or the OP's own error page. Deciding
 * WHICH of those applies — the whole OIDC Core 1.0 §3.1.2 validation pipeline,
 * SSO, prompt=none — is processAuthorizationRequest() in routes/authorize.ts;
 * this file only turns its outcome into HTTP.
 */
import { Hono } from 'hono';
import { defaultProviderConfig } from '../config.js';
import {
  processAuthorizationRequest,
  type AuthorizationOutcome,
} from '../routes/authorize.js';
import { renderAuthorizationErrorPage } from './errors.js';
import { redirectWithCookies } from './respond.js';

export const authorizePage = new Hono<{ Variables: Record<string, any> }>();

/**
 * URL of one of the OP's own screens. It carries no query: the transaction
 * travels in the transaction cookie the outcome sets (buildTransactionCookie()
 * in store.ts), so it never shows up in history, logs or a shared screen.
 *
 * Built on config.issuer, never on the request URL: some runtimes derive the
 * request URL from the Host header, which would let the sender pick the
 * redirect origin (RFC 9700 §2.1: redirect only to trusted URIs). OIDC
 * Discovery 1.0 §3 makes the advertised issuer the source of truth for URLs
 * that point at the OP itself. A subpath issuer contributes only its origin —
 * the screen paths are absolute — so subpath mounting is not supported by the
 * generated routes.
 */
function screenUrl(c: any, path: '/login' | '/consent'): string {
  const config = c.get('config') ?? defaultProviderConfig;
  return new URL(path, config.issuer).toString();
}

/** Turn the outcome of the authorization request into the HTTP response. */
function respond(c: any, outcome: AuthorizationOutcome): Response {
  if (outcome.kind === 'bad_request') {
    // Malformed transport (wrong POST Content-Type, repeated parameter, no
    // client_id): OAuth error JSON — there is no transaction to show a screen for.
    return c.json({ error: outcome.error, error_description: outcome.errorDescription }, 400);
  }
  if (outcome.kind === 'authorization_response') {
    // Back to the client: the authorization code, a redirectable error, or
    // (EXPERIMENTAL JARM) the signed response JWT — all already in the URL.
    return c.redirect(outcome.location);
  }
  if (outcome.kind === 'login') {
    return redirectWithCookies(screenUrl(c, '/login'), outcome.cookies);
  }
  if (outcome.kind === 'consent') {
    return redirectWithCookies(screenUrl(c, '/consent'), outcome.cookies);
  }
  if (outcome.kind === 'error') {
    // OIDC Core 1.0 §3.1.2.2: an error that cannot be redirected (unknown
    // client_id, unregistered redirect_uri, redirect_uri with a fragment, a
    // request_uri that does not resolve) stays on the OP. Programmatic callers
    // that ask for JSON via the Accept header get the OAuth error JSON; browsers
    // get the OP's error page (the OIDF Conformance Suite screenshots it for
    // oidcc-ensure-registered-redirect-uri).
    const acceptsJson = (c.req.header('Accept') ?? '').includes('application/json');
    if (acceptsJson) {
      return c.json({ error: outcome.error, error_description: outcome.errorDescription }, 400);
    }
    return renderAuthorizationErrorPage(c, outcome);
  }
  return c.json({ error: 'server_error' }, 500);
}

const handleAuthorizationRequest = async (c: any): Promise<Response> =>
  respond(c, await processAuthorizationRequest(c));

// OIDC Core 1.0 Section 3.1.2.1: Authorization Endpoint must support both GET and POST.
authorizePage.get('/', handleAuthorizationRequest);
authorizePage.post('/', handleAuthorizationRequest);
