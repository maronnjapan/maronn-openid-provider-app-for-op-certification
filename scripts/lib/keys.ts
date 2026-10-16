/**
 * The signing key of the OP: an RS256 private JWK in the SIGNING_KEY Worker
 * secret (src/keys/signing-key.ts). The OP publishes its public part at the
 * JWKS endpoint itself, so the key exists in full only in the secret.
 *
 * A Worker secret cannot be read back, so a key is generated only when the
 * Worker has none; later runs leave it as it is.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ScriptError } from './log.js';
import { DEPLOY_CONFIG } from './project.js';
import { ROOT_DIR, parseJson, wrangler } from './wrangler.js';

export const SIGNING_KEY_SECRET = 'SIGNING_KEY';

const DEV_VARS_FILE = path.join(ROOT_DIR, '.dev.vars');

/** A new RS256 key pair as the JSON of its private JWK (the value of SIGNING_KEY). */
export async function generateSigningKey(): Promise<{ kid: string; privateJwk: string }> {
  const pair = (await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  const { kty, n, e, d, p, q, dp, dq, qi } = (await crypto.subtle.exportKey(
    'jwk',
    pair.privateKey,
  )) as JsonWebKey;
  if (!kty || !n || !e || !d) throw new Error('Failed to export the generated key');

  // signing-key-20261016T131232Z
  const kid = `signing-key-${new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z')}`;
  return {
    kid,
    privateJwk: JSON.stringify({ kty, n, e, d, p, q, dp, dq, qi, alg: 'RS256', use: 'sig', kid }),
  };
}

/** Whether the deployed Worker already has SIGNING_KEY. A Worker not deployed yet has none. */
export function hasDeployedSigningKey(): boolean {
  const result = wrangler(['secret', 'list', '--format', 'json', '--config', DEPLOY_CONFIG]);
  if (!result.ok) {
    if (/does not exist|not found|\[code: 10007\]/i.test(result.output)) return false;
    throw new ScriptError(`Worker のシークレット一覧を取得できませんでした。\n${result.output.trim()}`);
  }
  return parseJson<Array<{ name: string }>>(result.stdout).some(
    (secret) => secret.name === SIGNING_KEY_SECRET,
  );
}

/**
 * Run use() with a secrets file (wrangler deploy --secrets-file) that holds
 * the given secrets. The file is readable by the current user only and is
 * removed afterwards.
 */
export async function withSecretsFile<T>(
  secrets: Record<string, string>,
  use: (file: string) => Promise<T>,
): Promise<T> {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'oidc-secrets-'));
  try {
    const file = path.join(directory, 'secrets.json');
    fs.writeFileSync(file, JSON.stringify(secrets), { mode: 0o600 });
    return await use(file);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

/**
 * Make sure .dev.vars holds SIGNING_KEY for wrangler dev, keeping whatever
 * else the file holds. Returns the kid of a newly written key, or undefined
 * when the file already had one.
 */
export async function ensureLocalSigningKey(): Promise<string | undefined> {
  const lines = fs.existsSync(DEV_VARS_FILE)
    ? fs.readFileSync(DEV_VARS_FILE, 'utf8').split('\n').filter((line) => line.trim() !== '')
    : [];
  if (lines.some((line) => line.startsWith(`${SIGNING_KEY_SECRET}=`))) return undefined;

  const key = await generateSigningKey();
  // Single quotes keep the JSON as it is: .dev.vars is read as a dotenv file,
  // which does not unescape \" inside double quotes.
  lines.push(`${SIGNING_KEY_SECRET}='${key.privateJwk}'`);
  fs.writeFileSync(DEV_VARS_FILE, lines.join('\n') + '\n', { mode: 0o600 });
  return key.kid;
}
