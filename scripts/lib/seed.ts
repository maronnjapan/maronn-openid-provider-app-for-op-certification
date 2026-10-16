/**
 * Seeder: registers what the certification tests need in D1.
 *
 * - Three static clients, one for each client entry of the test plan
 *   configuration (client, client2 and client_secret_post).
 * - One test user with every standard claim, so the scope tests (profile,
 *   email, address, phone) find a value for each claim they ask for.
 *
 * The rows are written by the generated registerClient() / registerUser()
 * (src/oidc-provider/db), so they are exactly what the OP reads. Their
 * statements are collected here and run with wrangler d1 execute.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { UserClaims } from '@maronn-openid-connect/core';
import type { RegisteredClient } from '../../src/oidc-provider/config.js';
import { registerClient } from '../../src/oidc-provider/db/clients.js';
import type { SqlDatabase, SqlStatement, SqlValue } from '../../src/oidc-provider/db/database.js';
import { registerUser } from '../../src/oidc-provider/db/users.js';
import { parseJson, wranglerOrFail } from './wrangler.js';

export interface SeedTarget {
  local: boolean;
  /** Wrangler configuration that binds the database. */
  config: string;
  databaseName: string;
}

/** A client of the test plan configuration. */
export interface SeedClient {
  /** Key of the client entry in the test plan configuration JSON. */
  configKey: 'client' | 'client2' | 'client_secret_post';
  id: string;
  name: string;
  authMethod: 'client_secret_basic' | 'client_secret_post';
}

export const SEED_CLIENTS: readonly SeedClient[] = [
  { configKey: 'client', id: 'conformance-client', name: 'Conformance Suite (client)', authMethod: 'client_secret_basic' },
  { configKey: 'client2', id: 'conformance-client2', name: 'Conformance Suite (client2)', authMethod: 'client_secret_basic' },
  {
    configKey: 'client_secret_post',
    id: 'conformance-client-secret-post',
    name: 'Conformance Suite (client_secret_post)',
    authMethod: 'client_secret_post',
  },
];

// oidcc-refresh-token exchanges a refresh token.
const GRANT_TYPES = ['authorization_code', 'refresh_token'];

/** The claims of the test user, besides sub. */
function testUserClaims(sub: string): UserClaims {
  return {
    sub,
    name: 'Test User',
    given_name: 'Test',
    family_name: 'User',
    middle_name: 'Conformance',
    nickname: 'tester',
    preferred_username: sub,
    profile: 'https://example.com/users/test-user',
    picture: 'https://example.com/users/test-user.png',
    website: 'https://example.com',
    gender: 'other',
    birthdate: '2000-01-01',
    zoneinfo: 'Asia/Tokyo',
    locale: 'ja-JP',
    updated_at: 1767225600,
    email: 'test-user@example.com',
    email_verified: true,
    address: {
      formatted: '1-1 Chiyoda, Chiyoda-ku, Tokyo 100-0001, Japan',
      street_address: '1-1 Chiyoda',
      locality: 'Chiyoda-ku',
      region: 'Tokyo',
      postal_code: '100-0001',
      country: 'JP',
    },
    phone_number: '+81 3-0000-0000',
    phone_number_verified: true,
  };
}

export interface SeedInputs {
  redirectUris: string[];
  userId: string;
  /** Password to set for the test user. Without it a new user gets a generated one. */
  userPassword?: string;
}

export interface SeedOptions {
  /** Issue new secrets for clients that already have one. */
  rotateClientSecrets: boolean;
  /** Generate a new password for a test user that already exists. */
  resetUserPassword: boolean;
}

export interface SeedResult {
  /** The secret of each client that got a new one in this run, by client id. */
  clientSecrets: Map<string, string>;
  /** Whether the test user was registered for the first time. */
  userCreated: boolean;
  /** The test user's password, when this run set it. */
  userPassword?: string;
}

function databaseScope(target: SeedTarget): string[] {
  return [target.local ? '--local' : '--remote', '--config', target.config];
}

function literal(value: SqlValue | undefined): string {
  if (value === undefined) throw new Error('A statement has more placeholders than values');
  if (value === null) return 'NULL';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error(`Cannot write ${value} as SQL`);
    return String(value);
  }
  return `'${value.replaceAll("'", "''")}'`;
}

/** The statement with its values written in place of the ? placeholders. */
function inline(statement: SqlStatement): string {
  let index = 0;
  // The generated SQL never has a ? inside a literal (db/database.ts).
  const sql = statement.sql.replace(/\?/g, () => literal(statement.params[index++]));
  if (index !== statement.params.length) throw new Error('A statement has more values than placeholders');
  return sql + ';';
}

/**
 * A SqlDatabase that only collects the statements registerClient() and
 * registerUser() run. Both only write, so reading is not supported.
 */
function createStatementRecorder(): { db: SqlDatabase; statements: string[] } {
  const statements: string[] = [];
  return {
    statements,
    db: {
      async all() {
        throw new Error('The seeder does not read through registerClient() / registerUser()');
      },
      async run(statement) {
        statements.push(inline(statement));
        return { changes: 0 };
      },
    },
  };
}

function query<Row>(target: SeedTarget, sql: string): Row[] {
  const result = wranglerOrFail([
    'd1', 'execute', target.databaseName, '--json', ...databaseScope(target), '--command', sql,
  ]);
  return parseJson<Array<{ results: Row[] }>>(result.stdout)[0]?.results ?? [];
}

/** The stored secret hash of each registered client, by client id. */
function findClientSecretHashes(target: SeedTarget): Map<string, string> {
  const rows = query<{ client_id: string; secret: string | null }>(
    target,
    'SELECT a.client_id, s.secret FROM client_auths a JOIN client_secrets s ON s.id = a.id ' +
      `WHERE a.client_id IN (${SEED_CLIENTS.map((client) => literal(client.id)).join(', ')})`,
  );
  return new Map(rows.flatMap((row) => (row.secret === null ? [] : [[row.client_id, row.secret]])));
}

function userHasPassword(target: SeedTarget, userId: string): boolean {
  return (
    query<{ id: string }>(
      target,
      `SELECT id FROM users WHERE id = ${literal(userId)} AND password_hash IS NOT NULL`,
    ).length > 0
  );
}

function randomSecret(): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url');
}

/**
 * Register the clients and the test user, or bring them in line with the
 * given values. A client keeps its secret, and the user their password, unless
 * a new one is asked for: only their hashes are stored, so they could not be
 * shown again.
 */
export async function seed(target: SeedTarget, inputs: SeedInputs, options: SeedOptions): Promise<SeedResult> {
  const existingHashes = findClientSecretHashes(target);
  const recorder = createStatementRecorder();
  const clientSecrets = new Map<string, string>();

  for (const client of SEED_CLIENTS) {
    const registered: RegisteredClient & { name: string } = {
      clientId: client.id,
      name: client.name,
      clientType: 'confidential',
      redirectUris: inputs.redirectUris,
      grantTypes: GRANT_TYPES,
      tokenEndpointAuthMethod: client.authMethod,
    };
    const existingHash = existingHashes.get(client.id);
    if (existingHash && !options.rotateClientSecrets) {
      registered.clientSecretHash = existingHash;
    } else {
      const secret = randomSecret();
      registered.clientSecret = secret;
      clientSecrets.set(client.id, secret);
    }
    await registerClient(recorder.db, registered);
  }

  const userExists = userHasPassword(target, inputs.userId);
  let userPassword: string | undefined;
  if (inputs.userPassword || !userExists || options.resetUserPassword) {
    userPassword = inputs.userPassword || randomSecret();
    await registerUser(recorder.db, { ...testUserClaims(inputs.userId), password: userPassword });
  }

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'oidc-seed-'));
  try {
    const file = path.join(directory, 'seed.sql');
    fs.writeFileSync(file, recorder.statements.join('\n') + '\n', { mode: 0o600 });
    wranglerOrFail(['d1', 'execute', target.databaseName, '--file', file, '--yes', ...databaseScope(target)]);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
  return { clientSecrets, userCreated: !userExists, userPassword };
}
