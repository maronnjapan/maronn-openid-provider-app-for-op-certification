import type {
  ClientResolver,
  TokenClientResolver,
  AuthorizationCodeResolver,
  AuthorizationCodeInfo,
  AccessTokenResolver,
  AccessTokenInfo,
  RefreshTokenResolver,
  RefreshTokenInfo,
  AuthenticationSessionResolver,
  AuthenticationSessionInfo,
  UserClaimsResolver,
  UserClaims,
  IntrospectionAccessTokenResolver,
  IntrospectionRefreshTokenResolver,
  RevocationTokenResolvers,
  SessionResolver,
  SessionInfo,
  ConsentResolver,
} from '@maronn-openid-connect/core';
import { createInMemoryClientResolver } from './config.js';
import {
  defaultProviderStores,
  parseSessionId,
  type ProviderStores,
} from './store.js';

/**
 * Default in-memory client resolver for quick local testing.
 * Project integrations should inject a D1/KV/env-backed resolver through Hono context.
 */
export const clientResolver: ClientResolver & TokenClientResolver =
  createInMemoryClientResolver();

export const tokenClientResolver: TokenClientResolver = clientResolver;

/**
 * Build the resolver suite over one coherent store set. A request must never
 * mix resolvers from one backend with direct stores from another backend.
 */
export type GrantAwareConsentResolver = ConsentResolver & {
  recordGrant(subject: string, clientId: string, grantId: string): Promise<void>;
};

export function createStoreResolvers(stores: ProviderStores) {
  const {
    authCodeStore,
    accessTokenStore,
    refreshTokenStore,
    userStore,
    browserSessionStore,
    consentStore,
  } = stores;

  const authorizationCodeResolver: AuthorizationCodeResolver = {
    async findAuthorizationCode(code: string): Promise<AuthorizationCodeInfo | null> {
      return (await authCodeStore.get(code)) ?? null;
    },
    async revokeAuthorizationCode(code: string): Promise<void> {
      await authCodeStore.consume(code);
    },
    async revokeTokensByGrantId(grantId: string): Promise<void> {
      await accessTokenStore.revokeByGrantId(grantId);
      await refreshTokenStore.revokeByGrantId(grantId);
    },
  };

  const accessTokenResolver: AccessTokenResolver = {
    async findAccessToken(token: string): Promise<AccessTokenInfo | null> {
      return (await accessTokenStore.get(token)) ?? null;
    },
  };

  const refreshTokenResolver: RefreshTokenResolver = {
    async resolve(token: string): Promise<RefreshTokenInfo | null> {
      return (await refreshTokenStore.get(token)) ?? null;
    },
    async revokeRefreshToken(token: string): Promise<void> {
      await refreshTokenStore.consume(token);
    },
    async revokeTokensByGrantId(grantId: string): Promise<void> {
      await accessTokenStore.revokeByGrantId(grantId);
      await refreshTokenStore.revokeByGrantId(grantId);
    },
  };

  const userClaimsResolver: UserClaimsResolver = {
    async findUserClaims(sub: string): Promise<UserClaims | null> {
      return (await userStore.getClaims(sub)) ?? null;
    },
  };

  const introspectionAccessTokenResolver: IntrospectionAccessTokenResolver = {
    async findAccessToken(token) {
      return (await accessTokenStore.get(token)) ?? null;
    },
  };

  const introspectionRefreshTokenResolver: IntrospectionRefreshTokenResolver = {
    async resolve(token) {
      return (await refreshTokenStore.get(token)) ?? null;
    },
  };

  const revocationResolvers: RevocationTokenResolvers = {
    async findAccessToken(token) {
      return (await accessTokenStore.get(token)) ?? null;
    },
    async revokeAccessToken(token) {
      await accessTokenStore.revoke(token);
    },
    async findRefreshToken(token) {
      return (await refreshTokenStore.get(token)) ?? null;
    },
    async revokeRefreshToken(token) {
      await refreshTokenStore.revoke(token);
    },
    async revokeAccessTokensByGrantId(grantId) {
      await accessTokenStore.revokeByGrantId(grantId);
    },
  };

  const sessionResolver: SessionResolver = {
    async resolve(request: Request): Promise<SessionInfo | null> {
      const sessionId = parseSessionId(request.headers.get('Cookie'));
      if (!sessionId) return null;
      const session = await browserSessionStore.get(sessionId);
      if (!session) return null;
      // sessionId まで返すのは online refresh token のため。認可コードへ引き継ぎ、
      // トークンエンドポイントが Refresh Token をこのセッションへ束縛する。
      return { subject: session.subject, authTime: session.authTime, sessionId };
    },
  };

  // online refresh token の束縛先セッションを sessionId から引く。sessionResolver は
  // Cookie を持つブラウザリクエストから引く入口で、トークンエンドポイントには End-User の
  // Cookie が届かないため、保存された sessionId から直接引くこちらが要る。
  // 終了したセッションでは必ず null を返すこと。返し続けると online refresh token が
  // ログアウト後も使えてしまう。
  const authenticationSessionResolver: AuthenticationSessionResolver = {
    async findSession(sessionId: string): Promise<AuthenticationSessionInfo | null> {
      const session = await browserSessionStore.get(sessionId);
      if (!session) return null;
      return { subject: session.subject, authTime: session.authTime };
    },
  };

  const revokeConsentAndTokens = async (subject: string, clientId: string): Promise<void> => {
    const grantIds = await consentStore.revoke(subject, clientId);
    for (const grantId of grantIds) {
      await authorizationCodeResolver.revokeTokensByGrantId?.(grantId);
    }
  };

  const consentResolver: GrantAwareConsentResolver = {
    async hasConsent(subject: string, clientId: string, scopes: string[]): Promise<boolean> {
      return consentStore.hasConsent(subject, clientId, scopes);
    },
    async recordConsent(subject: string, clientId: string, scopes: string[]): Promise<void> {
      await consentStore.grant(subject, clientId, scopes);
    },
    async recordGrant(subject: string, clientId: string, grantId: string): Promise<void> {
      await consentStore.recordGrant(subject, clientId, grantId);
    },
    async revokeConsent(subject: string, clientId: string): Promise<void> {
      await revokeConsentAndTokens(subject, clientId);
    },
  };

  return {
    authorizationCodeResolver,
    accessTokenResolver,
    refreshTokenResolver,
    authenticationSessionResolver,
    userClaimsResolver,
    introspectionAccessTokenResolver,
    introspectionRefreshTokenResolver,
    revocationResolvers,
    sessionResolver,
    consentResolver,
    revokeConsentAndTokens,
  };
}

const defaultStoreResolvers = createStoreResolvers(defaultProviderStores);

export const authorizationCodeResolver = defaultStoreResolvers.authorizationCodeResolver;
export const accessTokenResolver = defaultStoreResolvers.accessTokenResolver;
export const refreshTokenResolver = defaultStoreResolvers.refreshTokenResolver;
export const authenticationSessionResolver =
  defaultStoreResolvers.authenticationSessionResolver;
export const userClaimsResolver = defaultStoreResolvers.userClaimsResolver;
export const introspectionAccessTokenResolver =
  defaultStoreResolvers.introspectionAccessTokenResolver;
export const introspectionRefreshTokenResolver =
  defaultStoreResolvers.introspectionRefreshTokenResolver;
export const revocationResolvers = defaultStoreResolvers.revocationResolvers;
export const sessionResolver = defaultStoreResolvers.sessionResolver;
export const consentResolver = defaultStoreResolvers.consentResolver;

export async function revokeConsentAndTokens(subject: string, clientId: string): Promise<void> {
  await defaultStoreResolvers.revokeConsentAndTokens(subject, clientId);
}
