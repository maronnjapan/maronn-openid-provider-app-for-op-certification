/**
 * Users in the users table of db/schema.sql: registerUser() to put a user
 * there, and the password hashing that authenticate() (stores.ts) checks the
 * login form against.
 *
 * Passwords are hashed with PBKDF2-HMAC-SHA256 of the Web Crypto API, which
 * every runtime of the generated OP has. A stored hash records its own
 * iteration count and salt ('pbkdf2-sha256$<iterations>$<salt>$<hash>'), so
 * raising PASSWORD_HASH_ITERATIONS later keeps the existing hashes valid.
 */
import type { UserClaims } from '@maronn-openid-connect/core';
import type { SqlDatabase } from './database.js';

const PASSWORD_HASH_ALGORITHM = 'pbkdf2-sha256';
/**
 * OWASP recommends 600,000 iterations for PBKDF2-HMAC-SHA256, but Cloudflare
 * Workers accept at most 100,000, so the generated code uses that. Raise it
 * where the runtime allows more.
 */
const PASSWORD_HASH_ITERATIONS = 100_000;
const PASSWORD_SALT_BYTES = 16;
const PASSWORD_HASH_BYTES = 32;

/**
 * Put a user into the users table, replacing an earlier registration with the
 * same id (sub). email and email_verified go to their columns, the other
 * claims to the claims column, and password (when given) is saved as its hash.
 * Without a password the user cannot use the login form of the OP.
 *
 *   await registerUser(db, { sub: 'alice', email: 'alice@example.com', email_verified: true, password: '...' });
 */
export async function registerUser(
  db: SqlDatabase,
  user: UserClaims & { password?: string },
): Promise<void> {
  const { sub, email, email_verified, password, ...otherClaims } = user;
  const now = Math.floor(Date.now() / 1000);
  await db.run({
    sql:
      'INSERT INTO users (id, email, is_verified, password_hash, created_at, updated_at, claims) ' +
      'VALUES (?, ?, ' + (email_verified === true ? 'TRUE' : 'FALSE') + ', ?, ?, ?, ?) ' +
      'ON CONFLICT (id) DO UPDATE SET email = excluded.email, is_verified = excluded.is_verified, ' +
      'password_hash = excluded.password_hash, updated_at = excluded.updated_at, claims = excluded.claims',
    params: [
      sub,
      email ?? null,
      password === undefined ? null : await hashPassword(password),
      now,
      now,
      JSON.stringify(otherClaims),
    ],
  });
}

/** The value of users.password_hash for a password, with a new random salt. */
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(PASSWORD_SALT_BYTES));
  const hash = await derivePasswordHash(password, salt, PASSWORD_HASH_ITERATIONS);
  return [PASSWORD_HASH_ALGORITHM, PASSWORD_HASH_ITERATIONS, toBase64Url(salt), toBase64Url(hash)].join('$');
}

/**
 * Whether a password matches users.password_hash. Without a hash (null, or a
 * value in another format) it still derives a key before answering false, so
 * the time taken does not tell whether the user exists or has a password.
 */
export async function verifyPassword(password: string, passwordHash: string | null): Promise<boolean> {
  const stored = passwordHash === null ? undefined : parsePasswordHash(passwordHash);
  const derived = await derivePasswordHash(
    password,
    stored?.salt ?? new Uint8Array(PASSWORD_SALT_BYTES),
    stored?.iterations ?? PASSWORD_HASH_ITERATIONS,
  );
  return stored !== undefined && constantTimeEqual(derived, stored.hash);
}

async function derivePasswordHash(password: string, salt: ArrayLike<number>, iterations: number) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: new Uint8Array(salt), iterations },
    key,
    PASSWORD_HASH_BYTES * 8,
  );
  return new Uint8Array(bits);
}

function parsePasswordHash(value: string) {
  const [algorithm, iterations, salt, hash, ...rest] = value.split('$');
  const iterationCount = Number(iterations);
  if (
    algorithm !== PASSWORD_HASH_ALGORITHM ||
    rest.length > 0 ||
    !Number.isInteger(iterationCount) ||
    iterationCount < 1 ||
    !salt ||
    !hash
  ) {
    return undefined;
  }
  return { iterations: iterationCount, salt: fromBase64Url(salt), hash: fromBase64Url(hash) };
}

/** Compares in time that does not depend on where the values differ. */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index++) {
    difference |= (a[index] ?? 0) ^ (b[index] ?? 0);
  }
  return difference === 0;
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(value: string) {
  const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
  return bytes;
}
