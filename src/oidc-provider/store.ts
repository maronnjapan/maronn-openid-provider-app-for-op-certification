import type {
  AuthTransaction,
  AuthTransactionStore,
  AuthorizationCodeInfo,
  AccessTokenInfo,
  RefreshTokenInfo,
  UserClaims,
} from '@maronn-openid-connect/core';

/**
 * In-memory Authorization Transaction Store.
 * In production, replace with a persistent store (e.g., Redis, database).
 */
export class InMemoryTransactionStore implements AuthTransactionStore {
  private store = new Map<string, { value: AuthTransaction; expiresAt: number }>();

  async get(key: string): Promise<AuthTransaction | null> {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }

  async put(key: string, value: AuthTransaction, ttlSeconds: number): Promise<void> {
    this.store.set(key, { value, expiresAt: Date.now() + (ttlSeconds * 1000) });
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }
}

/**
 * In-memory Authorization Code Store.
 * Stores issued authorization codes and their associated data.
 */
export class AuthorizationCodeStore {
  private codes = new Map<string, AuthorizationCodeInfo>();

  set(code: string, info: AuthorizationCodeInfo): void {
    this.codes.set(code, info);
  }

  get(code: string): AuthorizationCodeInfo | undefined {
    const entry = this.codes.get(code);
    if (!entry) return undefined;
    const now = Math.floor(Date.now() / 1000);
    if (entry.expiresAt <= now) {
      this.codes.delete(code);
      return undefined;
    }
    return entry;
  }

  // Mark the authorization code as used (do NOT physically delete it).
  // OAuth 2.1 §4.1.2 / RFC 9700 §4.13: a replayed code must still be findable as
  // used:true so revokeAuthorizationCode can detect reuse and revoke the grant's
  // tokens. The resolver path uses consume(); see delete() for physical removal.
  consume(code: string): void {
    const entry = this.codes.get(code);
    if (entry) {
      entry.used = true;
    }
  }

  // Physically remove the entry. Use only where physical deletion is correct
  // (e.g. expired-entry eviction), never as the resolver's "code used" path —
  // that must be consume() so reuse detection keeps working.
  delete(code: string): void {
    this.codes.delete(code);
  }
}

/**
 * In-memory Access Token Store.
 * Stores issued access tokens for UserInfo endpoint validation.
 */
export class AccessTokenStore {
  private tokens = new Map<string, AccessTokenInfo>();

  set(token: string, info: AccessTokenInfo): void {
    this.tokens.set(token, info);
  }

  get(token: string): AccessTokenInfo | undefined {
    const entry = this.tokens.get(token);
    if (!entry) return undefined;
    // Lazy eviction (RFC 6819 §5.1.5.3 / RFC 9700 §4.14): drop expired entries on
    // read so an idle in-memory store does not grow unbounded. Correctness is already
    // guaranteed by the core expiry check; this only bounds retention.
    const now = Math.floor(Date.now() / 1000);
    if (entry.expiresAt <= now) {
      this.tokens.delete(token);
      return undefined;
    }
    return entry;
  }

  delete(token: string): void {
    this.tokens.delete(token);
  }

  // OAuth 2.1 Section 4.1.2: revoke all access tokens issued under a given grant
  // when the originating authorization code is reused.
  revokeByGrantId(grantId: string): void {
    for (const [token, info] of this.tokens) {
      if (info.grantId === grantId) {
        this.tokens.delete(token);
      }
    }
  }

  /** Revoke a single access token. Used by RFC 7009 revocation endpoint. */
  revoke(token: string): void {
    this.tokens.delete(token);
  }
}

/**
 * In-memory Refresh Token Store.
 * Stores issued refresh tokens for token rotation.
 * OAuth 2.1 Section 4.3
 */
export class RefreshTokenStore {
  private tokens = new Map<string, RefreshTokenInfo>();

  set(token: string, info: RefreshTokenInfo): void {
    this.tokens.set(token, info);
  }

  get(token: string): RefreshTokenInfo | undefined {
    const entry = this.tokens.get(token);
    if (!entry) return undefined;
    // Lazy eviction only past the absolute lifetime (expiresAt). A used=true but
    // still-in-lifetime entry MUST remain so rotation-reuse detection (revokeByGrantId)
    // keeps firing (OAuth 2.1 4.3.1 / RFC 9700 4.13). Eviction never keys on the used flag.
    const now = Math.floor(Date.now() / 1000);
    if (entry.expiresAt <= now) {
      this.tokens.delete(token);
      return undefined;
    }
    return entry;
  }

  // Mark the rotated refresh token as used (do NOT physically delete it).
  // OAuth 2.1 §4.3.1 / RFC 9700 §4.13: a replayed (already-rotated) refresh token
  // must remain findable as used:true so reuse detection can revoke the grant.
  // The resolver path uses consume(); see delete() for physical removal.
  consume(token: string): void {
    const entry = this.tokens.get(token);
    if (entry) {
      entry.used = true;
    }
  }

  // Physically remove the entry. Use only where physical deletion is correct
  // (e.g. revocation / grant cascade / expired-entry eviction), never as the
  // resolver's "rotated" path — that must be consume() to keep reuse detection.
  delete(token: string): void {
    this.tokens.delete(token);
  }

  // OAuth 2.1 Section 4.1.2: revoke all refresh tokens (including rotated ones)
  // sharing the given grantId when the originating authorization code is reused.
  revokeByGrantId(grantId: string): void {
    for (const [token, info] of this.tokens) {
      if (info.grantId === grantId) {
        this.tokens.delete(token);
      }
    }
  }

  /** Revoke a single refresh token. Used by RFC 7009 revocation endpoint. */
  revoke(token: string): void {
    this.tokens.delete(token);
  }
}

/**
 * In-memory authenticated session store.
 * Keeps login results between login and consent steps.
 */
export interface AuthSessionInfo {
  subject: string;
  authTime: number;
  /**
   * このログインで確立（または再利用）したブラウザセッションの識別子。
   * consent 画面を経て発行する認可コードへ引き継ぎ、online refresh token を
   * そのセッションへ束縛するために使う。
   */
  sessionId?: string;
}

export class AuthSessionStore {
  private sessions = new Map<string, AuthSessionInfo>();

  set(transactionId: string, info: AuthSessionInfo): void {
    this.sessions.set(transactionId, info);
  }

  get(transactionId: string): AuthSessionInfo | undefined {
    return this.sessions.get(transactionId);
  }

  delete(transactionId: string): void {
    this.sessions.delete(transactionId);
  }
}

/**
 * Browser (OP) session store - OIDC Core 1.0 Section 3.1.2.3.
 * Unlike AuthSessionStore (a per-transaction login -> consent handoff), this
 * persists across authorization requests, keyed by an opaque session_id carried
 * in an HttpOnly cookie. It is what makes SSO, prompt=none and max_age work.
 * In production, replace with a persistent store (e.g., KV, database).
 */
export const SESSION_COOKIE_NAME = 'session_id';

export interface BrowserSessionInfo {
  subject: string;
  authTime: number;
}

export class BrowserSessionStore {
  private sessions = new Map<string, BrowserSessionInfo>();

  set(sessionId: string, info: BrowserSessionInfo): void {
    this.sessions.set(sessionId, info);
  }

  get(sessionId: string): BrowserSessionInfo | undefined {
    return this.sessions.get(sessionId);
  }

  delete(sessionId: string): void {
    this.sessions.delete(sessionId);
  }
}

/**
 * Extract the session_id value from a Cookie request header.
 * Returns undefined when the header is missing or the cookie is absent.
 */
export function parseSessionId(cookieHeader: string | null): string | undefined {
  if (!cookieHeader) return undefined;
  for (const part of cookieHeader.split(';')) {
    const trimmed = part.trim();
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    if (trimmed.slice(0, eq) === SESSION_COOKIE_NAME) {
      return trimmed.slice(eq + 1);
    }
  }
  return undefined;
}

/**
 * Build the Set-Cookie value for the browser session.
 * Security attributes: HttpOnly (no JS access), Secure (HTTPS only),
 * SameSite=Lax. SameSite=Strict
 * would drop the cookie on the cross-site authorization redirect return and
 * break the flow, so Lax is required.
 */
export function buildSessionCookie(sessionId: string): string {
  return SESSION_COOKIE_NAME + '=' + sessionId + '; HttpOnly; Secure; SameSite=Lax; Path=/';
}

/**
 * Auth transaction cookie - which authorization request this browser is in the
 * middle of (OIDC Core 1.0 Section 3.1.2.3 / 3.1.2.4).
 *
 * /authorize hands the transaction id to the browser in this HttpOnly cookie
 * and nowhere else: the /login and /consent URLs carry no query, and their
 * forms embed only csrf_token. Every login / consent step reads the transaction
 * out of this cookie and accepts a submission only when the posted csrf_token
 * belongs to that transaction, so the cookie and the HTML have to come
 * together.
 *
 * Why not the URL: an id in the URL leaks through browser history, access logs
 * or a shared screen. Whoever picks it up could open the consent page, read
 * csrf_token off it and finish the flow; worse, an attacker could start a flow
 * with their OWN client and lure the victim to it, so that the victim's
 * authorization code is delivered to the attacker's client - a case the RP's
 * state check cannot catch. Neither works when the id only ever lives in a
 * cookie that page scripts cannot read and other sites cannot set.
 *
 * One cookie per browser: a second /authorize (another tab) replaces it, and a
 * form still open in the first tab is then refused - its csrf_token belongs to
 * the replaced transaction - instead of completing the wrong request.
 *
 * The '__Host-' prefix makes the browser refuse this cookie unless it comes
 * from this exact host with Secure, Path=/ and no Domain. Without it a sibling
 * subdomain (evil.example.com next to op.example.com) could plant its own
 * transaction in the victim's browser ("cookie tossing") - and the csrf_token
 * of that planted transaction is one the attacker already knows. Browsers
 * accept the prefix on http://localhost as well, so local development works.
 */
export const TRANSACTION_COOKIE_NAME = '__Host-oidc_txn';

/**
 * Build the Set-Cookie value that hands a transaction to this browser.
 * Same attributes as the session cookie: HttpOnly (no JS access), Secure
 * (HTTPS only; http://localhost is treated as trustworthy by browsers) and
 * SameSite=Lax, because SameSite=Strict would drop the cookie on the
 * cross-site navigation that starts the flow. Secure and Path=/ (and no
 * Domain) are also what the '__Host-' prefix requires. Max-Age matches the
 * transaction TTL so an abandoned flow does not leave the cookie behind.
 */
export function buildTransactionCookie(transactionId: string, ttlSeconds: number): string {
  return (
    TRANSACTION_COOKIE_NAME + '=' + transactionId +
    '; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=' + String(ttlSeconds)
  );
}

/**
 * Build the Set-Cookie value that removes the transaction cookie once the
 * transaction is finished (code issued or access denied). It repeats Secure
 * and Path=/: the browser ignores a '__Host-' cookie write without them, the
 * removal included.
 */
export function buildClearedTransactionCookie(): string {
  return TRANSACTION_COOKIE_NAME + '=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0';
}

/**
 * Extract the transaction id from a Cookie request header.
 * Returns undefined when the header is missing or the cookie is absent.
 */
export function parseTransactionId(cookieHeader: string | null): string | undefined {
  if (!cookieHeader) return undefined;
  for (const part of cookieHeader.split(';')) {
    const trimmed = part.trim();
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    if (trimmed.slice(0, eq) === TRANSACTION_COOKIE_NAME) {
      return trimmed.slice(eq + 1) || undefined;
    }
  }
  return undefined;
}

/**
 * Whether a form POST to /login or /consent was sent from the OP's own pages.
 *
 * A check that depends on neither the transaction cookie nor the csrf_token:
 * the browser itself states where the request came from, and no page script
 * can override these headers. It still holds when a sibling subdomain managed
 * to plant a transaction cookie and therefore knows its csrf_token, and it is
 * the only check SameSite=Lax leaves to a same-site (sibling subdomain) POST.
 *
 * - Sec-Fetch-Site (Fetch Metadata): only 'same-origin' passes, plus 'none' -
 *   a user-initiated request such as a reload, which no other site can
 *   trigger. 'same-site' (a sibling subdomain) and 'cross-site' do not.
 * - Without Fetch Metadata, the Origin header a browser sends on every POST
 *   must be the issuer's origin. 'null' (an opaque origin) never matches.
 * - With neither header the request did not come from a browser page (curl, an
 *   HTTP client) or from a very old browser; the transaction cookie and the
 *   csrf_token still apply.
 *
 * The comparison uses config.issuer, never the request URL: some runtimes
 * derive the request URL from the Host header, which the sender controls.
 */
export function isSameOriginFormPost(
  headers: { origin: string | null; secFetchSite: string | null },
  issuer: string,
): boolean {
  if (headers.secFetchSite !== null) {
    return headers.secFetchSite === 'same-origin' || headers.secFetchSite === 'none';
  }
  if (headers.origin !== null) {
    return headers.origin === new URL(issuer).origin;
  }
  return true;
}

/** The message the OP shows when isSameOriginFormPost() refuses a form POST. */
export const CROSS_ORIGIN_FORM_POST_MESSAGE =
  'This form can only be submitted from the authorization server itself.';

/**
 * In-memory consent store. Records that a user granted a set of scopes to a
 * client so prompt=none can confirm consent without showing UI
 * (OIDC Core 1.0 Section 3.1.2.1).
 */
export class ConsentStore {
  private grants = new Map<string, Map<string, Set<string>>>();
  // One consent can authorize multiple code flows. Keep every resulting grantId
  // indexed by subject + client so a user-initiated "remove access" operation
  // can revoke the complete AT/RT families without touching another client.
  private grantIds = new Map<string, Map<string, Set<string>>>();

  grant(subject: string, clientId: string, scopes: string[]): void {
    let byClient = this.grants.get(subject);
    if (!byClient) {
      byClient = new Map<string, Set<string>>();
      this.grants.set(subject, byClient);
    }
    const granted = byClient.get(clientId) ?? new Set<string>();
    for (const s of scopes) granted.add(s);
    byClient.set(clientId, granted);
  }

  hasConsent(subject: string, clientId: string, scopes: string[]): boolean {
    const granted = this.grants.get(subject)?.get(clientId);
    if (!granted) return false;
    return scopes.every((s) => granted.has(s));
  }

  recordGrant(subject: string, clientId: string, grantId: string): void {
    let byClient = this.grantIds.get(subject);
    if (!byClient) {
      byClient = new Map<string, Set<string>>();
      this.grantIds.set(subject, byClient);
    }
    const ids = byClient.get(clientId) ?? new Set<string>();
    ids.add(grantId);
    byClient.set(clientId, ids);
  }

  // Revoke all consent the subject granted to a client (e.g. "remove access")
  // and atomically detach the grant ids that the caller must cascade-revoke.
  revoke(subject: string, clientId: string): string[] {
    const ids = [...(this.grantIds.get(subject)?.get(clientId) ?? [])];
    this.grants.get(subject)?.delete(clientId);
    this.grantIds.get(subject)?.delete(clientId);
    return ids;
  }
}

/**
 * In-memory User Store.
 * Stores user profiles for authentication and UserInfo responses.
 * In production, replace with a database-backed user store.
 */
export class UserStore {
  private users = new Map<string, UserClaims & { password: string }>();

  constructor() {
    // Example user for development.
    // Carries the standard claims for every scope advertised in Discovery
    // (profile / email / address / phone — OIDC Core 1.0 §5.4) so the OIDF
    // Conformance Suite's VerifyScopesReturnedInUserInfoClaims finds a value for
    // each requested scope. filterClaimsByScope still gates what is returned per
    // scope; populating the fixture is the resolver's responsibility.
    this.users.set('testuser', {
      sub: 'testuser',
      // profile scope
      name: 'Test User',
      family_name: 'User',
      given_name: 'Test',
      middle_name: 'Q',
      nickname: 'testy',
      preferred_username: 'testuser',
      profile: 'https://op.example.com/users/testuser',
      picture: 'https://op.example.com/users/testuser/avatar.png',
      website: 'https://testuser.example.com',
      gender: 'unspecified',
      birthdate: '1990-01-01',
      zoneinfo: 'Asia/Tokyo',
      locale: 'en-US',
      updated_at: 1700000000,
      // email scope
      email: 'test@example.com',
      email_verified: true,
      // address scope
      address: {
        formatted: '100 Test Street, Test City, TS 10000, JP',
        street_address: '100 Test Street',
        locality: 'Test City',
        region: 'TS',
        postal_code: '10000',
        country: 'JP',
      },
      // phone scope
      phone_number: '+81-3-0000-0000',
      phone_number_verified: true,
      password: 'password',
    });

    // A second fixture makes subject-isolation and id_token_hint/session mismatch
    // flows reproducible with real signed tokens. It is development-only example
    // data, not a multi-account policy for production integrations.
    this.users.set('otheruser', {
      sub: 'otheruser',
      name: 'Other User',
      preferred_username: 'otheruser',
      email: 'other@example.com',
      email_verified: true,
      password: 'password',
    });
  }

  authenticate(username: string, password: string): (UserClaims & { password: string }) | undefined {
    const user = this.users.get(username);
    if (user && user.password === password) {
      return user;
    }
    return undefined;
  }

  getClaims(sub: string): UserClaims | undefined {
    const user = this.users.get(sub);
    if (!user) return undefined;
    const { password: _, ...claims } = user;
    return claims;
  }
}

export type Awaitable<T> = T | Promise<T>;

export interface JsonStoreEntry<T> {
  key: string;
  value: T;
}

/**
 * Minimal JSON key/value contract used by generated persistent stores.
 * Implement it with D1, SQLite, Redis, KV, or another deployment-native store.
 * list() must return only live entries whose keys start with prefix.
 */
export interface JsonStoreBackend {
  get<T>(key: string): Promise<T | null>;
  put<T>(key: string, value: T, ttlSeconds?: number): Promise<void>;
  delete(key: string): Promise<void>;
  list<T>(prefix: string): Promise<Array<JsonStoreEntry<T>>>;
}

export interface AuthorizationCodeStorage {
  set(code: string, info: AuthorizationCodeInfo): Awaitable<void>;
  get(code: string): Awaitable<AuthorizationCodeInfo | undefined>;
  consume(code: string): Awaitable<void>;
  delete(code: string): Awaitable<void>;
}

export interface AccessTokenStorage {
  set(token: string, info: AccessTokenInfo): Awaitable<void>;
  get(token: string): Awaitable<AccessTokenInfo | undefined>;
  delete(token: string): Awaitable<void>;
  revokeByGrantId(grantId: string): Awaitable<void>;
  revoke(token: string): Awaitable<void>;
}

export interface RefreshTokenStorage {
  set(token: string, info: RefreshTokenInfo): Awaitable<void>;
  get(token: string): Awaitable<RefreshTokenInfo | undefined>;
  consume(token: string): Awaitable<void>;
  delete(token: string): Awaitable<void>;
  revokeByGrantId(grantId: string): Awaitable<void>;
  revoke(token: string): Awaitable<void>;
}

export interface AuthSessionStorage {
  set(transactionId: string, info: AuthSessionInfo): Awaitable<void>;
  get(transactionId: string): Awaitable<AuthSessionInfo | undefined>;
  delete(transactionId: string): Awaitable<void>;
}

export interface BrowserSessionStorage {
  set(sessionId: string, info: BrowserSessionInfo): Awaitable<void>;
  get(sessionId: string): Awaitable<BrowserSessionInfo | undefined>;
  delete(sessionId: string): Awaitable<void>;
}

export interface ConsentStorage {
  grant(subject: string, clientId: string, scopes: string[]): Awaitable<void>;
  hasConsent(subject: string, clientId: string, scopes: string[]): Awaitable<boolean>;
  recordGrant(subject: string, clientId: string, grantId: string): Awaitable<void>;
  revoke(subject: string, clientId: string): Awaitable<string[]>;
}

export interface UserStorage {
  authenticate(
    username: string,
    password: string,
  ): Awaitable<(UserClaims & { password: string }) | undefined>;
  getClaims(sub: string): Awaitable<UserClaims | undefined>;
}

export interface ProviderStores {
  transactionStore: AuthTransactionStore;
  authCodeStore: AuthorizationCodeStorage;
  accessTokenStore: AccessTokenStorage;
  refreshTokenStore: RefreshTokenStorage;
  authSessionStore: AuthSessionStorage;
  browserSessionStore: BrowserSessionStorage;
  consentStore: ConsentStorage;
  userStore: UserStorage;
}

export type ProviderStoresFactory = (
  context: any,
) => Awaitable<ProviderStores>;

const TRANSACTION_PREFIX = 'transaction:';
const AUTHORIZATION_CODE_PREFIX = 'authorization-code:';
const ACCESS_TOKEN_PREFIX = 'access-token:';
const REFRESH_TOKEN_PREFIX = 'refresh-token:';
const AUTH_SESSION_PREFIX = 'auth-session:';
const BROWSER_SESSION_PREFIX = 'browser-session:';
const CONSENT_PREFIX = 'consent:';
const USER_PREFIX = 'user:';

class JsonTransactionStore implements AuthTransactionStore {
  constructor(private readonly backend: JsonStoreBackend) {}

  async get(key: string): Promise<AuthTransaction | null> {
    return this.backend.get<AuthTransaction>(TRANSACTION_PREFIX + key);
  }

  async put(key: string, value: AuthTransaction, ttlSeconds: number): Promise<void> {
    await this.backend.put(TRANSACTION_PREFIX + key, value, ttlSeconds);
  }

  async delete(key: string): Promise<void> {
    await this.backend.delete(TRANSACTION_PREFIX + key);
  }
}

class JsonAuthorizationCodeStore implements AuthorizationCodeStorage {
  constructor(private readonly backend: JsonStoreBackend) {}

  async set(code: string, info: AuthorizationCodeInfo): Promise<void> {
    await this.backend.put(
      AUTHORIZATION_CODE_PREFIX + code,
      info,
      ttlUntil(info.expiresAt),
    );
  }

  async get(code: string): Promise<AuthorizationCodeInfo | undefined> {
    const entry = await this.backend.get<AuthorizationCodeInfo>(AUTHORIZATION_CODE_PREFIX + code);
    if (!entry) return undefined;
    if (entry.expiresAt <= epochSeconds()) {
      await this.delete(code);
      return undefined;
    }
    return entry;
  }

  async consume(code: string): Promise<void> {
    const entry = await this.get(code);
    if (!entry) return;
    await this.set(code, { ...entry, used: true });
  }

  async delete(code: string): Promise<void> {
    await this.backend.delete(AUTHORIZATION_CODE_PREFIX + code);
  }
}

class JsonAccessTokenStore implements AccessTokenStorage {
  constructor(private readonly backend: JsonStoreBackend) {}

  async set(token: string, info: AccessTokenInfo): Promise<void> {
    await this.backend.put(ACCESS_TOKEN_PREFIX + token, info, ttlUntil(info.expiresAt));
  }

  async get(token: string): Promise<AccessTokenInfo | undefined> {
    const entry = await this.backend.get<AccessTokenInfo>(ACCESS_TOKEN_PREFIX + token);
    if (!entry) return undefined;
    if (entry.expiresAt <= epochSeconds()) {
      await this.delete(token);
      return undefined;
    }
    return entry;
  }

  async delete(token: string): Promise<void> {
    await this.backend.delete(ACCESS_TOKEN_PREFIX + token);
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    const entries = await this.backend.list<AccessTokenInfo>(ACCESS_TOKEN_PREFIX);
    await Promise.all(
      entries
        .filter((entry) => entry.value.grantId === grantId)
        .map((entry) => this.backend.delete(entry.key)),
    );
  }

  async revoke(token: string): Promise<void> {
    await this.delete(token);
  }
}

class JsonRefreshTokenStore implements RefreshTokenStorage {
  constructor(private readonly backend: JsonStoreBackend) {}

  async set(token: string, info: RefreshTokenInfo): Promise<void> {
    await this.backend.put(REFRESH_TOKEN_PREFIX + token, info, ttlUntil(info.expiresAt));
  }

  async get(token: string): Promise<RefreshTokenInfo | undefined> {
    const entry = await this.backend.get<RefreshTokenInfo>(REFRESH_TOKEN_PREFIX + token);
    if (!entry) return undefined;
    if (entry.expiresAt <= epochSeconds()) {
      await this.delete(token);
      return undefined;
    }
    return entry;
  }

  async consume(token: string): Promise<void> {
    const entry = await this.get(token);
    if (!entry) return;
    await this.set(token, { ...entry, used: true });
  }

  async delete(token: string): Promise<void> {
    await this.backend.delete(REFRESH_TOKEN_PREFIX + token);
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    const entries = await this.backend.list<RefreshTokenInfo>(REFRESH_TOKEN_PREFIX);
    await Promise.all(
      entries
        .filter((entry) => entry.value.grantId === grantId)
        .map((entry) => this.backend.delete(entry.key)),
    );
  }

  async revoke(token: string): Promise<void> {
    await this.delete(token);
  }
}

class JsonAuthSessionStore implements AuthSessionStorage {
  constructor(private readonly backend: JsonStoreBackend) {}

  async set(transactionId: string, info: AuthSessionInfo): Promise<void> {
    await this.backend.put(AUTH_SESSION_PREFIX + transactionId, info);
  }

  async get(transactionId: string): Promise<AuthSessionInfo | undefined> {
    return (await this.backend.get<AuthSessionInfo>(AUTH_SESSION_PREFIX + transactionId)) ?? undefined;
  }

  async delete(transactionId: string): Promise<void> {
    await this.backend.delete(AUTH_SESSION_PREFIX + transactionId);
  }
}

class JsonBrowserSessionStore implements BrowserSessionStorage {
  constructor(private readonly backend: JsonStoreBackend) {}

  async set(sessionId: string, info: BrowserSessionInfo): Promise<void> {
    await this.backend.put(BROWSER_SESSION_PREFIX + sessionId, info);
  }

  async get(sessionId: string): Promise<BrowserSessionInfo | undefined> {
    return (await this.backend.get<BrowserSessionInfo>(BROWSER_SESSION_PREFIX + sessionId)) ?? undefined;
  }

  async delete(sessionId: string): Promise<void> {
    await this.backend.delete(BROWSER_SESSION_PREFIX + sessionId);
  }
}

interface StoredConsent {
  scopes: string[];
  grantIds: string[];
}

class JsonConsentStore implements ConsentStorage {
  constructor(private readonly backend: JsonStoreBackend) {}

  async grant(subject: string, clientId: string, scopes: string[]): Promise<void> {
    const key = consentKey(subject, clientId);
    const current = await this.read(key);
    await this.backend.put(key, {
      scopes: [...new Set([...current.scopes, ...scopes])],
      grantIds: current.grantIds,
    });
  }

  async hasConsent(subject: string, clientId: string, scopes: string[]): Promise<boolean> {
    const current = await this.read(consentKey(subject, clientId));
    return scopes.every((scope) => current.scopes.includes(scope));
  }

  async recordGrant(subject: string, clientId: string, grantId: string): Promise<void> {
    const key = consentKey(subject, clientId);
    const current = await this.read(key);
    await this.backend.put(key, {
      scopes: current.scopes,
      grantIds: [...new Set([...current.grantIds, grantId])],
    });
  }

  async revoke(subject: string, clientId: string): Promise<string[]> {
    const key = consentKey(subject, clientId);
    const current = await this.read(key);
    await this.backend.delete(key);
    return current.grantIds;
  }

  private async read(key: string): Promise<StoredConsent> {
    return (await this.backend.get<StoredConsent>(key)) ?? { scopes: [], grantIds: [] };
  }
}

type StoredUser = UserClaims & { password: string };

class JsonUserStore implements UserStorage {
  constructor(private readonly backend: JsonStoreBackend) {}

  async authenticate(username: string, password: string): Promise<StoredUser | undefined> {
    const user = await this.findOrSeed(username);
    return user?.password === password ? user : undefined;
  }

  async getClaims(sub: string): Promise<UserClaims | undefined> {
    const user = await this.findOrSeed(sub);
    if (!user) return undefined;
    const { password: _, ...claims } = user;
    return claims;
  }

  private async findOrSeed(username: string): Promise<StoredUser | undefined> {
    const key = USER_PREFIX + username;
    const stored = await this.backend.get<StoredUser>(key);
    if (stored) return stored;
    const fixture = defaultUserFixture(username);
    if (!fixture) return undefined;
    await this.backend.put(key, fixture);
    return fixture;
  }
}

/** Create all OP stores over one deployment-native JSON backend. */
export function createJsonProviderStores(backend: JsonStoreBackend): ProviderStores {
  return {
    transactionStore: new JsonTransactionStore(backend),
    authCodeStore: new JsonAuthorizationCodeStore(backend),
    accessTokenStore: new JsonAccessTokenStore(backend),
    refreshTokenStore: new JsonRefreshTokenStore(backend),
    authSessionStore: new JsonAuthSessionStore(backend),
    browserSessionStore: new JsonBrowserSessionStore(backend),
    consentStore: new JsonConsentStore(backend),
    userStore: new JsonUserStore(backend),
  };
}

function epochSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function ttlUntil(expiresAt: number): number {
  return Math.max(1, expiresAt - epochSeconds());
}

function consentKey(subject: string, clientId: string): string {
  return CONSENT_PREFIX + encodeURIComponent(subject) + ':' + encodeURIComponent(clientId);
}

function defaultUserFixture(username: string): StoredUser | undefined {
  if (username === 'testuser') {
    return {
      sub: 'testuser',
      name: 'Test User',
      family_name: 'User',
      given_name: 'Test',
      middle_name: 'Q',
      nickname: 'testy',
      preferred_username: 'testuser',
      profile: 'https://op.example.com/users/testuser',
      picture: 'https://op.example.com/users/testuser/avatar.png',
      website: 'https://testuser.example.com',
      gender: 'unspecified',
      birthdate: '1990-01-01',
      zoneinfo: 'Asia/Tokyo',
      locale: 'en-US',
      updated_at: 1700000000,
      email: 'test@example.com',
      email_verified: true,
      address: {
        formatted: '100 Test Street, Test City, TS 10000, JP',
        street_address: '100 Test Street',
        locality: 'Test City',
        region: 'TS',
        postal_code: '10000',
        country: 'JP',
      },
      phone_number: '+81-3-0000-0000',
      phone_number_verified: true,
      password: 'password',
    };
  }
  if (username === 'otheruser') {
    return {
      sub: 'otheruser',
      name: 'Other User',
      preferred_username: 'otheruser',
      email: 'other@example.com',
      email_verified: true,
      password: 'password',
    };
  }
  return undefined;
}

// Singleton store instances.
//
// Backed by globalThis so a single instance is shared process-wide. This is
// required on Next.js, where Server Components / Server Actions and Route
// Handlers are instantiated in separate module layers: a plain
// `new Store()` module export would produce a different instance per layer, so
// state written by the login/consent pages (transactions, sessions, consent)
// would be invisible to the /authorize and /token route handlers and vice
// versa. It also survives dev-mode hot reloads. Harmless for single-layer
// runtimes (Node / Hono / Express / Fastify), which always see one instance.
const storeRegistry = globalThis as typeof globalThis & {
  __oidcProviderStores?: ProviderStores;
};

export const defaultProviderStores = (storeRegistry.__oidcProviderStores ??= {
  transactionStore: new InMemoryTransactionStore(),
  authCodeStore: new AuthorizationCodeStore(),
  accessTokenStore: new AccessTokenStore(),
  refreshTokenStore: new RefreshTokenStore(),
  authSessionStore: new AuthSessionStore(),
  browserSessionStore: new BrowserSessionStore(),
  consentStore: new ConsentStore(),
  userStore: new UserStore(),
});

export const transactionStore = defaultProviderStores.transactionStore;
export const authCodeStore = defaultProviderStores.authCodeStore;
export const accessTokenStore = defaultProviderStores.accessTokenStore;
export const refreshTokenStore = defaultProviderStores.refreshTokenStore;
export const authSessionStore = defaultProviderStores.authSessionStore;
export const browserSessionStore = defaultProviderStores.browserSessionStore;
export const consentStore = defaultProviderStores.consentStore;
export const userStore = defaultProviderStores.userStore;
