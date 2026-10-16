import { env } from 'cloudflare:workers';
import { createOidcProviderApp } from './app.js';
import type { Env } from './env.js';

export default createOidcProviderApp(env as unknown as Env);
