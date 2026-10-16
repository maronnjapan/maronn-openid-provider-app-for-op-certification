/**
 * The OpenID Provider for the OpenID Foundation certification tests
 * (Basic OP / Config OP, static clients): the generated provider code
 * (src/oidc-provider) wired to Cloudflare.
 *
 *   D1             clients, users, authorization transactions, codes, tokens,
 *                  sessions and consent (src/oidc-provider/db, --db sql)
 *   Worker secret  SIGNING_KEY, the private key that signs the tokens
 */
import { Hono } from 'hono';
import type { Env } from './env.js';
import { createSigningKeyProvider } from './keys/signing-key.js';
import { applyOidc } from './oidc-provider/apply.js';

function readIssuer(value: string | undefined): string {
  if (!value) {
    throw new Error('ISSUER is not set');
  }
  const url = new URL(value);
  if (url.search || url.hash) {
    throw new Error('ISSUER must not contain a query or fragment (OIDC Discovery 1.0 §3)');
  }
  return value.replace(/\/+$/, '');
}

export function createOidcProviderApp(env: Env): Hono<{ Bindings: Env; Variables: Record<string, any> }> {
  const app = new Hono<{ Bindings: Env; Variables: Record<string, any> }>();

  app.get('/', (c) => c.text('maronn OpenID Provider (for OpenID certification)'));

  // Clients, users and every store come from D1 through src/oidc-provider/db
  // (createDatabase() in db/instance.ts), the default of the generated code.
  applyOidc(app, {
    config: {
      issuer: readIssuer(env.ISSUER),
      // PKCE is optional. The certification suite sends no PKCE except in
      // oidcc-ensure-request-with-valid-pkce-succeeds, so a confidential client
      // may leave it out. When code_challenge is sent it is still validated, and
      // the token endpoint then requires the matching code_verifier.
      allowNonPkceAuthorizationCodeFlow: true,
      // OIDC Core 1.0 §6.1: the suite sends unsigned (alg: none) Request
      // Objects. Accepting them advertises "none" in
      // request_object_signing_alg_values_supported, without which the Request
      // Object modules of the Basic OP plan are skipped instead of run.
      allowUnsignedRequestObject: true,
    },
    signingKeyProvider: createSigningKeyProvider(env.SIGNING_KEY),
  });

  app.onError((error, c) => {
    console.error(error);
    return c.json({ error: 'server_error' }, 500);
  });

  return app;
}
