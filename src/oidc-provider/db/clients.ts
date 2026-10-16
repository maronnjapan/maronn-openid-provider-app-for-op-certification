/**
 * Registered clients on the client tables of db/schema.sql: the ClientResolver
 * the OP uses when no other one is passed in, and registerClient() to put a
 * client into those tables.
 *
 * How the tables become a RegisteredClient (config.ts):
 *
 * - clients.client_type public: no client authentication ('none').
 * - client_auths and client_secrets: token_endpoint_auth_method
 *   (client_secret_basic / client_secret_post), and the clientSecretHash the
 *   presented secret is checked against. More than one row per client is a
 *   configuration error, because a client has one registered method.
 * - client_redirect_uris, client_grant_types and client_scopes: redirectUris,
 *   grantTypes and scope. A request for a scope outside scope is rejected with
 *   invalid_scope (validateClientScope() in core). A client without
 *   client_scopes rows may request every scope the OP accepts.
 * - Metadata without a column (response_types, default_max_age, jwks, the ID
 *   Token and UserInfo signing algs) keeps its default.
 */
import {
  hashClientSecret,
  type ClientResolver,
  type TokenClientResolver,
} from '@maronn-openid-connect/core';
import type { RegisteredClient } from '../config.js';
import type { SqlDatabase } from './database.js';

export function createSqlClientResolver(db: SqlDatabase): ClientResolver & TokenClientResolver {
  return {
    async findClient(clientId: string): Promise<RegisteredClient | null> {
      const [client] = await db.all<{ id: string; client_type: string }>({
        sql: 'SELECT id, client_type FROM clients WHERE id = ? AND is_deleted = FALSE',
        params: [clientId],
      });
      if (!client) return null;
      const auths = await db.all<{ client_auth_type: string; secret: string | null }>({
        sql:
          'SELECT a.client_auth_type, s.secret FROM client_auths a ' +
          'LEFT JOIN client_secrets s ON s.id = a.id WHERE a.client_id = ? ORDER BY a.id',
        params: [clientId],
      });
      const redirectUris = await db.all<{ value: string }>({
        sql: 'SELECT value FROM client_redirect_uris WHERE client_id = ? ORDER BY id',
        params: [clientId],
      });
      const grantTypes = await db.all<{ grant_type: string }>({
        sql: 'SELECT grant_type FROM client_grant_types WHERE client_id = ? ORDER BY id',
        params: [clientId],
      });
      const scopes = await db.all<{ value: string }>({
        sql: 'SELECT value FROM client_scopes WHERE client_id = ? ORDER BY id',
        params: [clientId],
      });

      const registered: RegisteredClient = {
        clientId: client.id,
        clientType: client.client_type === 'public' ? 'public' : 'confidential',
        redirectUris: redirectUris.map((row) => row.value),
      };
      if (grantTypes.length > 0) registered.grantTypes = grantTypes.map((row) => row.grant_type);
      if (scopes.length > 0) registered.scope = scopes.map((row) => row.value);

      if (registered.clientType === 'public') {
        registered.tokenEndpointAuthMethod = 'none';
      } else if (auths.length > 1) {
        throw new Error('Client ' + clientId + ' has more than one row in client_auths');
      } else if (auths[0]) {
        registered.tokenEndpointAuthMethod = auths[0].client_auth_type as
          | 'client_secret_basic'
          | 'client_secret_post';
        if (auths[0].secret !== null) registered.clientSecretHash = auths[0].secret;
      }
      // A confidential client without a client_auths row keeps the default
      // client_secret_basic with no secret, so it cannot authenticate.
      return registered;
    },
  };
}

/**
 * Put a client into the client tables, replacing the rows of an earlier
 * registration with the same client_id. Call it from a setup script or at
 * startup, for example for the clients of config.ts:
 *
 *   for (const client of defaultRegisteredClients.values()) {
 *     await registerClient(db, client);
 *   }
 *
 * Registering a client again with the same values leaves its rows as they
 * are, so every instance of the OP may register its clients at startup, even
 * at the same moment: each row's id comes from the values it holds, so two
 * registrations write the same rows instead of adding copies. When the values
 * change, the new redirect URIs, grant types and scopes go in before the old
 * ones are removed, so requests in between still find the client.
 *
 * clientSecret is saved as its hash (hashClientSecret()). The statements run
 * one at a time (SqlDatabase has no transactions), so run it again if it stops
 * halfway.
 */
export async function registerClient(
  db: SqlDatabase,
  client: RegisteredClient & { name?: string },
): Promise<void> {
  const clientType =
    client.clientType ?? (client.tokenEndpointAuthMethod === 'none' ? 'public' : 'confidential');
  await db.run({
    sql:
      'INSERT INTO clients (id, name, client_type, is_deleted) VALUES (?, ?, ?, FALSE) ' +
      'ON CONFLICT (id) DO UPDATE SET name = excluded.name, client_type = excluded.client_type, ' +
      'is_deleted = FALSE',
    params: [client.clientId, client.name ?? null, clientType],
  });

  const secretHash =
    client.clientSecretHash ??
    (client.clientSecret !== undefined ? await hashClientSecret(client.clientSecret) : undefined);
  const authMethod = client.tokenEndpointAuthMethod ?? 'client_secret_basic';
  const auth =
    clientType === 'confidential' && authMethod !== 'none' && secretHash !== undefined
      ? { id: await childRowId(client.clientId, 'client_auths', authMethod), secretHash }
      : undefined;
  const authIds = auth ? [auth.id] : [];
  // The rows of another method go first, so the client never has two
  // client_auths rows. Secrets go before their client_auths rows: they
  // reference them, and SQLite cascades only with foreign keys on.
  await db.run({
    sql: exceptIds('DELETE FROM client_secrets WHERE id IN (SELECT id FROM client_auths WHERE client_id = ?)', authIds),
    params: [client.clientId, ...authIds],
  });
  await db.run({
    sql: exceptIds('DELETE FROM client_auths WHERE client_id = ?', authIds),
    params: [client.clientId, ...authIds],
  });
  if (auth) {
    await db.run({
      sql: 'INSERT INTO client_auths (id, client_id, client_auth_type) VALUES (?, ?, ?) ON CONFLICT (id) DO NOTHING',
      params: [auth.id, client.clientId, authMethod],
    });
    await db.run({
      sql:
        'INSERT INTO client_secrets (id, client_auth_type, secret) VALUES (?, ?, ?) ' +
        'ON CONFLICT (id) DO UPDATE SET secret = excluded.secret',
      params: [auth.id, authMethod, auth.secretHash],
    });
  }

  const childValues: Array<[table: string, column: string, values: readonly string[]]> = [
    ['client_redirect_uris', 'value', client.redirectUris],
    ['client_grant_types', 'grant_type', client.grantTypes ?? []],
    ['client_scopes', 'value', client.scope ?? []],
  ];
  for (const [table, column, values] of childValues) {
    const ids: string[] = [];
    for (const value of values) {
      const id = await childRowId(client.clientId, table, value);
      ids.push(id);
      await db.run({
        sql: 'INSERT INTO ' + table + ' (id, client_id, ' + column + ') VALUES (?, ?, ?) ON CONFLICT (id) DO NOTHING',
        params: [id, client.clientId, value],
      });
    }
    await db.run({
      sql: exceptIds('DELETE FROM ' + table + ' WHERE client_id = ?', ids),
      params: [client.clientId, ...ids],
    });
  }
}

/**
 * The id of a row under a client: the SHA-256 (hex) of the client_id, the
 * table and the value the row holds, so the same value always maps to the
 * same row.
 */
async function childRowId(clientId: string, table: string, value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(JSON.stringify([clientId, table, value])),
  );
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** A DELETE of a client's rows, narrowed to the rows whose id is not in keep. */
function exceptIds(sql: string, keep: readonly string[]): string {
  return keep.length === 0 ? sql : sql + ' AND id NOT IN (' + keep.map(() => '?').join(', ') + ')';
}
