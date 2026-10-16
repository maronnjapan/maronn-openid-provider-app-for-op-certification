/**
 * ProviderStores (store.ts) on the tables of db/schema.sql: the stores the OP
 * uses when no other storage is passed in. Every SQL statement runs through
 * the SqlDatabase that db/instance.ts creates. An operation that touches two
 * tables (a transaction and its request, a code and the status of its
 * transaction) runs its statements one after another.
 *
 * Rewriting this file for another driver or an ORM is fine, but keep these
 * behaviors - routes/ and resolvers.ts rely on them:
 *
 * 1. Keep the ProviderStores types (method names, parameters, return values).
 * 2. authCodeStore.consume and refreshTokenStore.consume flip is_used from
 *    FALSE to TRUE in ONE conditional UPDATE, and throw TokenError
 *    (invalid_grant) when it changed no row. A SELECT followed by an UPDATE
 *    lets two concurrent requests both see an unused code and both receive
 *    tokens (OAuth 2.1 §4.1.2).
 * 3. consume never deletes the row. A used code or a rotated refresh token has
 *    to stay readable, so a replay is detected and the grant's tokens revoked.
 * 4. get never returns an expired row, and does return used ones.
 * 5. revokeByGrantId also removes the rotated (used) refresh tokens of the grant.
 * 6. hasConsent is true only when every requested scope was granted.
 * 7. Codes and tokens are stored and looked up by their SHA-256 hash; the raw
 *    value is never written to the database.
 * 8. transactionStore.get returns a transaction only while it is in progress
 *    (requested, upstream_pending, authenticated), and delete ends it instead
 *    of removing the row: its status becomes failed, then code_issued if a code
 *    is issued from it, and token_issued once that code is exchanged.
 */
import {
  TokenError,
  TokenErrorCode,
  type AccessTokenInfo,
  type AuthTransaction,
  type AuthTransactionStore,
  type AuthorizationCodeData,
  type AuthorizationCodeInfo,
  type RefreshTokenInfo,
  type UserClaims,
} from '@maronn-openid-connect/core';
import {
  type AccessTokenStorage,
  type AuthSessionInfo,
  type AuthSessionStorage,
  type AuthorizationCodeStorage,
  type BrowserSessionStorage,
  type ConsentStorage,
  type ProviderStores,
  type RefreshTokenStorage,
  type UserStorage,
} from '../store.js';
import type { SqlDatabase } from './database.js';
import { verifyPassword } from './users.js';

/** core prefixes the id of every AuthTransactionStore key with this. */
const TRANSACTION_KEY_PREFIX = 'auth_txn:';

/** The statuses of a transaction in progress. */
const IN_PROGRESS = "('requested', 'upstream_pending', 'authenticated')";

export function createSqlProviderStores(db: SqlDatabase): ProviderStores {
  // Transaction + Authentication_request: what the authorization request asked
  // for goes to authentication_requests, the state of the flow to transactions.
  const transactionStore: AuthTransactionStore = {
    async get(key) {
      const [row] = await db.all<TransactionRow>({
        sql:
          'SELECT t.created_at, t.expired_at, t.payload AS transaction_payload, r.client_id, ' +
          'r.redirect_uri, r.state, r.nonce, r.code_challenge, r.code_challenge_method, ' +
          'r.response_type, r.scope, r.payload AS request_payload FROM transactions t ' +
          'JOIN authentication_requests r ON r.transaction_id = t.transaction_id ' +
          'WHERE t.transaction_id = ? AND t.status IN ' + IN_PROGRESS + ' AND t.expired_at > ?',
        params: [withoutPrefix(key, TRANSACTION_KEY_PREFIX), nowSeconds()],
      });
      if (!row) return null;
      const transaction: AuthTransaction = {
        ...(JSON.parse(row.request_payload) as OtherRequestParameters),
        ...(JSON.parse(row.transaction_payload) as TransactionPayload),
        clientId: row.client_id,
        redirectUri: row.redirect_uri,
        responseType: row.response_type,
        scope: row.scope ?? '',
        createdAt: Number(row.created_at) * 1000,
        expiresAt: Number(row.expired_at) * 1000,
      };
      if (row.state !== null) transaction.state = row.state;
      if (row.nonce !== null) transaction.nonce = row.nonce;
      if (row.code_challenge !== null) transaction.codeChallenge = row.code_challenge;
      if (row.code_challenge_method !== null) {
        transaction.codeChallengeMethod = row.code_challenge_method as 'S256';
      }
      return transaction;
    },
    // The expiry is the transaction's own expiresAt (milliseconds, rounded up
    // to seconds), which the ttlSeconds core passes is computed from.
    async put(key, value, _ttlSeconds) {
      const transactionId = withoutPrefix(key, TRANSACTION_KEY_PREFIX);
      const {
        clientId,
        redirectUri,
        state,
        nonce,
        codeChallenge,
        codeChallengeMethod,
        responseType,
        scope,
        createdAt,
        expiresAt,
        csrfToken,
        failedAttempts,
        bindingHash,
        ...otherParameters
      } = value;
      // A new transaction starts as requested. Saving it again (a failed login
      // attempt) keeps its status.
      await db.run({
        sql:
          'INSERT INTO transactions (transaction_id, status, created_at, expired_at, payload) ' +
          "VALUES (?, 'requested', ?, ?, ?) " +
          'ON CONFLICT (transaction_id) DO UPDATE SET expired_at = excluded.expired_at, payload = excluded.payload',
        params: [
          transactionId,
          Math.floor(createdAt / 1000),
          Math.ceil(expiresAt / 1000),
          JSON.stringify({ csrfToken, failedAttempts, bindingHash }),
        ],
      });
      await db.run({
        sql:
          'INSERT INTO authentication_requests (transaction_id, client_id, redirect_uri, state, nonce, ' +
          'code_challenge, code_challenge_method, response_type, scope, payload) ' +
          'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
          'ON CONFLICT (transaction_id) DO UPDATE SET client_id = excluded.client_id, ' +
          'redirect_uri = excluded.redirect_uri, state = excluded.state, nonce = excluded.nonce, ' +
          'code_challenge = excluded.code_challenge, code_challenge_method = excluded.code_challenge_method, ' +
          'response_type = excluded.response_type, scope = excluded.scope, payload = excluded.payload',
        params: [
          transactionId,
          clientId,
          redirectUri,
          state ?? null,
          nonce ?? null,
          codeChallenge ?? null,
          codeChallengeMethod ?? null,
          responseType,
          scope,
          JSON.stringify(otherParameters),
        ],
      });
    },
    // One-time use: the transaction is no longer in progress, and its row stays.
    async delete(key) {
      await db.run({
        sql: "UPDATE transactions SET status = 'failed' WHERE transaction_id = ? AND status IN " + IN_PROGRESS,
        params: [withoutPrefix(key, TRANSACTION_KEY_PREFIX)],
      });
    },
  };

  const authCodeStore: AuthorizationCodeStorage = {
    async set(code, info) {
      // The routes pass core's AuthorizationCodeData, which names the
      // transaction the code was issued from. Neither the raw code nor a value
      // with its own column goes into payload.
      const { code: _code, used, expiresAt, grantId, transactionId, ...payload } =
        info as AuthorizationCodeInfo & Pick<AuthorizationCodeData, 'transactionId'>;
      await db.run({
        sql:
          'INSERT INTO codes (id, transaction_id, expired_at, is_used, grant_id, payload) ' +
          'VALUES (?, ?, ?, ' + sqlBoolean(used) + ', ?, ?)',
        params: [await hashKey(code), transactionId ?? null, expiresAt, grantId, JSON.stringify(payload)],
      });
      if (transactionId !== undefined) {
        await db.run({
          sql: "UPDATE transactions SET status = 'code_issued' WHERE transaction_id = ?",
          params: [transactionId],
        });
      }
    },
    async get(code) {
      const [row] = await db.all<CodeRow>({
        sql: 'SELECT expired_at, is_used, grant_id, payload FROM codes WHERE id = ? AND expired_at > ?',
        params: [await hashKey(code), nowSeconds()],
      });
      if (!row) return undefined;
      const payload = JSON.parse(row.payload) as Omit<
        AuthorizationCodeInfo,
        'code' | 'used' | 'expiresAt' | 'grantId'
      >;
      return {
        ...payload,
        code,
        grantId: row.grant_id,
        expiresAt: Number(row.expired_at),
        used: toBoolean(row.is_used),
      };
    },
    // Only one of two concurrent requests changes the row; the other one finds
    // the code already used and must not receive tokens.
    async consume(code) {
      const { changes } = await db.run({
        sql: 'UPDATE codes SET is_used = TRUE WHERE id = ? AND is_used = FALSE',
        params: [await hashKey(code)],
      });
      if (changes === 0) {
        throw new TokenError(TokenErrorCode.InvalidGrant, 'Authorization code has already been used');
      }
    },
    async delete(code) {
      await db.run({ sql: 'DELETE FROM codes WHERE id = ?', params: [await hashKey(code)] });
    },
  };

  const deleteAccessToken = async (token: string): Promise<void> => {
    await db.run({
      sql: 'DELETE FROM access_tokens WHERE token_hash = ?',
      params: [await hashKey(token)],
    });
  };

  const accessTokenStore: AccessTokenStorage = {
    async set(token, info) {
      const { sub, scope, clientId, expiresAt, iat, issuer, jti, grantId, acr, ...payload } = info;
      const tokenHash = await hashKey(token);
      await db.run({
        sql:
          'INSERT INTO access_tokens (id, sub, exp, iat, iss, client_id, scope, acr, transaction_id, ' +
          'token_hash, grant_id, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ' +
          // The transaction of the code the grant came from. A grant without a
          // code (the device flow, CIBA) has none.
          '(SELECT transaction_id FROM codes WHERE grant_id = ? LIMIT 1), ?, ?, ?)',
        params: [
          // A token issued without a jti is kept under its hash.
          jti ?? tokenHash,
          sub,
          expiresAt,
          iat ?? null,
          issuer ?? null,
          clientId,
          joinScope(scope),
          acr ?? null,
          grantId ?? null,
          tokenHash,
          grantId ?? null,
          JSON.stringify(payload),
        ],
      });
      if (grantId !== undefined) {
        await db.run({
          sql:
            "UPDATE transactions SET status = 'token_issued' WHERE status = 'code_issued' " +
            'AND transaction_id = (SELECT transaction_id FROM codes WHERE grant_id = ? LIMIT 1)',
          params: [grantId],
        });
      }
    },
    async get(token) {
      const tokenHash = await hashKey(token);
      const [row] = await db.all<AccessTokenRow>({
        sql:
          'SELECT id, sub, exp, iat, iss, client_id, scope, acr, grant_id, payload FROM access_tokens ' +
          'WHERE token_hash = ? AND exp > ?',
        params: [tokenHash, nowSeconds()],
      });
      if (!row) return undefined;
      const info: AccessTokenInfo = {
        ...(JSON.parse(row.payload) as Omit<AccessTokenInfo, AccessTokenColumn>),
        sub: row.sub,
        clientId: row.client_id,
        scope: splitScope(row.scope),
        expiresAt: Number(row.exp),
      };
      if (row.id !== tokenHash) info.jti = row.id;
      if (row.iat !== null) info.iat = Number(row.iat);
      if (row.iss !== null) info.issuer = row.iss;
      if (row.acr !== null) info.acr = row.acr;
      if (row.grant_id !== null) info.grantId = row.grant_id;
      return info;
    },
    delete: deleteAccessToken,
    revoke: deleteAccessToken,
    async revokeByGrantId(grantId) {
      await db.run({ sql: 'DELETE FROM access_tokens WHERE grant_id = ?', params: [grantId] });
    },
  };

  const deleteRefreshToken = async (token: string): Promise<void> => {
    await db.run({ sql: 'DELETE FROM refresh_tokens WHERE id = ?', params: [await hashKey(token)] });
  };

  const refreshTokenStore: RefreshTokenStorage = {
    async set(token, info) {
      const { used, expiresAt, iat, grantId, ...payload } = info;
      await db.run({
        sql:
          'INSERT INTO refresh_tokens (id, access_token_id, exp, iat, is_used, grant_id, payload) VALUES (?, ' +
          // The access token of the same token response: the token endpoint
          // stores it just before, with the same grant and iat, and no refresh
          // token links it yet.
          '(SELECT a.id FROM access_tokens a WHERE a.grant_id = ? AND a.iat = ? ' +
          'AND NOT EXISTS (SELECT 1 FROM refresh_tokens r WHERE r.access_token_id = a.id) ' +
          'ORDER BY a.id LIMIT 1), ?, ?, ' + sqlBoolean(used) + ', ?, ?)',
        params: [
          await hashKey(token),
          grantId,
          iat ?? null,
          expiresAt,
          iat ?? null,
          grantId,
          JSON.stringify(payload),
        ],
      });
    },
    async get(token) {
      const [row] = await db.all<RefreshTokenRow>({
        sql: 'SELECT exp, iat, is_used, grant_id, payload FROM refresh_tokens WHERE id = ? AND exp > ?',
        params: [await hashKey(token), nowSeconds()],
      });
      if (!row) return undefined;
      const info: RefreshTokenInfo = {
        ...(JSON.parse(row.payload) as Omit<RefreshTokenInfo, 'used' | 'expiresAt' | 'iat' | 'grantId'>),
        grantId: row.grant_id,
        expiresAt: Number(row.exp),
        used: toBoolean(row.is_used),
      };
      if (row.iat !== null) info.iat = Number(row.iat);
      return info;
    },
    // Rotation: like authCodeStore.consume, exactly one request wins.
    async consume(token) {
      const { changes } = await db.run({
        sql: 'UPDATE refresh_tokens SET is_used = TRUE WHERE id = ? AND is_used = FALSE',
        params: [await hashKey(token)],
      });
      if (changes === 0) {
        throw new TokenError(TokenErrorCode.InvalidGrant, 'Refresh token has already been used');
      }
    },
    delete: deleteRefreshToken,
    revoke: deleteRefreshToken,
    // Rotated (used) refresh tokens share the grant_id, so they go too.
    async revokeByGrantId(grantId) {
      await db.run({ sql: 'DELETE FROM refresh_tokens WHERE grant_id = ?', params: [grantId] });
    },
  };

  // Auth_user: the sign-in handed from /login to /consent, per transaction.
  const authSessionStore: AuthSessionStorage = {
    async set(transactionId, info) {
      await db.run({
        sql:
          'INSERT INTO auth_users (transaction_id, user_id, auth_type, auth_time, session_id) ' +
          'VALUES (?, ?, ?, ?, ?) ' +
          'ON CONFLICT (transaction_id) DO UPDATE SET user_id = excluded.user_id, ' +
          'auth_type = excluded.auth_type, auth_time = excluded.auth_time, session_id = excluded.session_id',
        params: [transactionId, info.subject, 'password', info.authTime, info.sessionId ?? null],
      });
      await db.run({
        sql:
          "UPDATE transactions SET status = 'authenticated' " +
          "WHERE transaction_id = ? AND status IN ('requested', 'upstream_pending')",
        params: [transactionId],
      });
    },
    async get(transactionId) {
      const [row] = await db.all<{ user_id: string; auth_time: number | string; session_id: string | null }>({
        sql: 'SELECT user_id, auth_time, session_id FROM auth_users WHERE transaction_id = ?',
        params: [transactionId],
      });
      if (!row) return undefined;
      const info: AuthSessionInfo = { subject: row.user_id, authTime: Number(row.auth_time) };
      if (row.session_id !== null) info.sessionId = row.session_id;
      return info;
    },
    async delete(transactionId) {
      await db.run({ sql: 'DELETE FROM auth_users WHERE transaction_id = ?', params: [transactionId] });
    },
  };

  const browserSessionStore: BrowserSessionStorage = {
    async set(sessionId, info) {
      await db.run({
        sql:
          'INSERT INTO browser_sessions (session_id, subject, auth_time) VALUES (?, ?, ?) ' +
          'ON CONFLICT (session_id) DO UPDATE SET subject = excluded.subject, auth_time = excluded.auth_time',
        params: [sessionId, info.subject, info.authTime],
      });
    },
    async get(sessionId) {
      const [row] = await db.all<{ subject: string; auth_time: number | string }>({
        sql: 'SELECT subject, auth_time FROM browser_sessions WHERE session_id = ?',
        params: [sessionId],
      });
      return row ? { subject: row.subject, authTime: Number(row.auth_time) } : undefined;
    },
    async delete(sessionId) {
      await db.run({ sql: 'DELETE FROM browser_sessions WHERE session_id = ?', params: [sessionId] });
    },
  };

  const consentStore: ConsentStorage = {
    async grant(subject, clientId, scopes) {
      const unique = [...new Set(scopes)];
      if (unique.length === 0) return;
      // Scopes granted before are skipped by ON CONFLICT DO NOTHING; new ones are added.
      await db.run({
        sql:
          'INSERT INTO consent_scopes (subject, client_id, scope) VALUES ' +
          unique.map(() => '(?, ?, ?)').join(', ') +
          ' ON CONFLICT DO NOTHING',
        params: unique.flatMap((scope) => [subject, clientId, scope]),
      });
    },
    async hasConsent(subject, clientId, scopes) {
      const unique = [...new Set(scopes)];
      // An empty request is never treated as consented (and IN () is not valid SQL).
      if (unique.length === 0) return false;
      const [row] = await db.all<{ granted: number | string }>({
        sql:
          'SELECT COUNT(*) AS granted FROM consent_scopes ' +
          'WHERE subject = ? AND client_id = ? AND scope IN (' +
          unique.map(() => '?').join(', ') +
          ')',
        params: [subject, clientId, ...unique],
      });
      // A partially granted request counts fewer rows than it asked for.
      return Number(row?.granted ?? 0) === unique.length;
    },
    async recordGrant(subject, clientId, grantId) {
      await db.run({
        sql:
          'INSERT INTO consent_grants (subject, client_id, grant_id) VALUES (?, ?, ?) ' +
          'ON CONFLICT DO NOTHING',
        params: [subject, clientId, grantId],
      });
    },
    async revoke(subject, clientId) {
      await db.run({
        sql: 'DELETE FROM consent_scopes WHERE subject = ? AND client_id = ?',
        params: [subject, clientId],
      });
      // DELETE ... RETURNING hands back every grant it removed, in the same
      // statement, so the caller revokes the tokens of each one.
      const rows = await db.all<{ grant_id: string }>({
        sql: 'DELETE FROM consent_grants WHERE subject = ? AND client_id = ? RETURNING grant_id',
        params: [subject, clientId],
      });
      return rows.map((row) => row.grant_id);
    },
  };


  // User: the users table. Put users there with registerUser() (users.ts).
  const userStore: UserStorage = {
    // The password form checks users.id as the username. Look the row up by
    // email instead to sign in with an email address.
    async authenticate(username, password) {
      const [row] = await db.all<UserRow & { password_hash: string | null }>({
        sql: 'SELECT email, is_verified, password_hash, claims FROM users WHERE id = ?',
        params: [username],
      });
      // verifyPassword() takes as long without a hash, so the response time does
      // not tell whether the user exists. A user without a password (such as one
      // created by Sign in with Google) cannot sign in with the form.
      const passwordHash = row?.password_hash ?? null;
      if (!(await verifyPassword(password, passwordHash)) || !row || passwordHash === null) {
        return undefined;
      }
      return { ...userClaims(username, row), password: passwordHash };
    },
    async getClaims(sub) {
      const [row] = await db.all<UserRow>({
        sql: 'SELECT email, is_verified, claims FROM users WHERE id = ?',
        params: [sub],
      });
      return row ? userClaims(sub, row) : undefined;
    },
  };

  return {
    transactionStore,
    authCodeStore,
    accessTokenStore,
    refreshTokenStore,
    authSessionStore,
    browserSessionStore,
    consentStore,
    userStore,
  };
}

/** The values of an AuthTransaction kept in transactions.payload. */
type TransactionPayload = Pick<AuthTransaction, 'csrfToken' | 'failedAttempts' | 'bindingHash'>;

/** The values of an AuthTransaction kept in authentication_requests.payload. */
type OtherRequestParameters = Omit<
  AuthTransaction,
  | keyof TransactionPayload
  | 'clientId'
  | 'redirectUri'
  | 'state'
  | 'nonce'
  | 'codeChallenge'
  | 'codeChallengeMethod'
  | 'responseType'
  | 'scope'
  | 'createdAt'
  | 'expiresAt'
>;

/** The values of an AccessTokenInfo with a column of their own in access_tokens. */
type AccessTokenColumn =
  | 'sub'
  | 'scope'
  | 'clientId'
  | 'expiresAt'
  | 'iat'
  | 'issuer'
  | 'jti'
  | 'grantId'
  | 'acr';

// Rows as the drivers return them: a BIGINT may come back as a string (pg) and
// a BOOLEAN as 1 / 0 (SQLite), so they are read with Number() and toBoolean().

interface TransactionRow {
  created_at: number | string;
  expired_at: number | string;
  transaction_payload: string;
  client_id: string;
  redirect_uri: string;
  state: string | null;
  nonce: string | null;
  code_challenge: string | null;
  code_challenge_method: string | null;
  response_type: string;
  scope: string | null;
  request_payload: string;
}

interface CodeRow {
  expired_at: number | string;
  is_used: unknown;
  grant_id: string;
  payload: string;
}

interface AccessTokenRow {
  id: string;
  sub: string;
  exp: number | string;
  iat: number | string | null;
  iss: string | null;
  client_id: string;
  scope: string | null;
  acr: string | null;
  grant_id: string | null;
  payload: string;
}

interface RefreshTokenRow {
  exp: number | string;
  iat: number | string | null;
  is_used: unknown;
  grant_id: string;
  payload: string;
}

interface UserRow {
  email: string | null;
  is_verified: unknown;
  claims: string | null;
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/** The claims of a users row: email and email_verified from their columns, the rest from claims. */
function userClaims(sub: string, row: UserRow): UserClaims {
  const claims: UserClaims = {
    ...(row.claims ? (JSON.parse(row.claims) as Partial<UserClaims>) : {}),
    sub,
  };
  if (row.email !== null) {
    claims.email = row.email;
    claims.email_verified = toBoolean(row.is_verified);
  }
  return claims;
}

function withoutPrefix(key: string, prefix: string): string {
  return key.startsWith(prefix) ? key.slice(prefix.length) : key;
}

/** The scope column: space-separated, NULL when there is none. */
function joinScope(scope: string[]): string | null {
  return scope.length > 0 ? scope.join(' ') : null;
}

function splitScope(scope: string | null): string[] {
  return scope ? scope.split(' ') : [];
}

/**
 * A boolean as SQL text. TRUE / FALSE work on SQLite, D1 and PostgreSQL alike,
 * while a bound number is not a BOOLEAN to every PostgreSQL driver.
 */
function sqlBoolean(value: boolean): 'TRUE' | 'FALSE' {
  return value ? 'TRUE' : 'FALSE';
}

/** A BOOLEAN column as read back: true / false from PostgreSQL, 1 / 0 from SQLite. */
function toBoolean(value: unknown): boolean {
  return value === true || Number(value) === 1;
}

/** The key a code or token is stored under: its SHA-256 hash, base64url-encoded. */
async function hashKey(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  let binary = '';
  for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
