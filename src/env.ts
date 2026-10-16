/**
 * Bindings and variables of the Worker (see wrangler.jsonc).
 */
export interface Env {
  /** D1: clients, users, authorization transactions, codes, tokens, sessions and consent. */
  DB: D1Database;
  /** Public URL of this OP. Every URL the OP hands out is built on it. */
  ISSUER: string;
  /**
   * Worker secret: the private JWK (RS256) that signs ID Tokens, access tokens
   * and UserInfo responses. scripts/deploy.ts creates it on the first deploy,
   * scripts/deploy.ts --local writes it to .dev.vars.
   */
  SIGNING_KEY?: string;
}
