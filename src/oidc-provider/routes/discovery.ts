import { Hono } from 'hono';
import { buildProviderMetadata, getJwaAlgorithm, type SigningKey } from '@maronn-openid-connect/core';
import { defaultProviderConfig } from '../config.js';

export const discoveryApp = new Hono<{ Variables: Record<string, any> }>();

/**
 * OpenID Connect Discovery Endpoint
 * OIDC Discovery 1.0 Section 4
 */
discoveryApp.get('/', (c) => {
  const config = c.get('config') ?? defaultProviderConfig;
  const issuer = config.issuer;

  // Derive id_token_signing_alg_values_supported from the actual key set
  // (OIDC Core 1.0 §15.1 — RS256 presence is enforced by buildProviderMetadata).
  // T-022: 全 registered ID Token 鍵の alg を集約することで RS256+ES256 など
  // 混在鍵セットも正しく advertise できる。
  const idTokenSigningKeyArr = (c.get('idTokenSigningKeys') as SigningKey[] | undefined) ?? [];
  const idTokenSigningKeys: CryptoKey[] = idTokenSigningKeyArr.map((k) => k.privateKey);

  // OIDC Core 1.0 §5.3.2 / §3 discovery: advertise the UserInfo signing algs the OP
  // can actually sign with, derived from the registered UserInfo key set (RS256,
  // ES256, ...), so userinfo_signed_response_alg clients can rely on metadata.
  const userinfoSigningKeyArr = (c.get('userinfoSigningKeys') as SigningKey[] | undefined) ?? [];
  const userinfoSigningAlgValues = [
    ...new Set(userinfoSigningKeyArr.map((k) => getJwaAlgorithm(k.privateKey))),
  ];

  const metadata = buildProviderMetadata({
    issuer,
    authorizationEndpoint: `${issuer}/authorize`,
    tokenEndpoint: `${issuer}/token`,
    jwksUri: `${issuer}/.well-known/jwks.json`,
    responseTypesSupported: ['code'],
    // OAuth 2.0 Multiple Response Type Encoding Practices §2 / OIDC Discovery 1.0 §3:
    // the OP only implements the authorization code flow, whose authorization
    // response is returned via query, so response_modes_supported is pinned to
    // ['query']. Extend this list when form_post (or other modes) are added.
    responseModesSupported: ['query'],
    subjectTypesSupported: ['public'],
    idTokenSigningKeys,
    userinfoEndpoint: `${issuer}/userinfo`,
    // OIDC Core 1.0 §11: offline_access is advertised so relying parties (and the
    // OIDF Conformance Suite's oidcc-refresh-token module) know they may request
    // refresh tokens via 'scope=openid offline_access' with prompt=consent.
    // It is a refresh-token request scope, not a claim scope, so no matching
    // entry is added to claimsSupported.
    scopesSupported: ['openid', 'profile', 'email', 'address', 'phone', 'offline_access'],
    // OIDC Discovery 1.0 §3 / Core 1.0 §5.6: this OP produces Normal Claims only
    // (no _claim_names / _claim_sources), so advertise ['normal'] explicitly to make
    // the lack of Aggregated/Distributed support machine-readable.
    claimTypesSupported: ['normal'],
    claimsSupported: [
      'sub',
      'iss',
      'aud',
      'exp',
      'iat',
      // OIDC Core 1.0 §2 / §3.1.3.6: ID Token protocol claims the OP issues
      // (id-token.ts). auth_time/nonce/acr/amr are set from the auth context,
      // azp for multi-audience tokens, at_hash for code flow access tokens.
      // c_hash is intentionally omitted (Hybrid flow is not implemented).
      'auth_time',
      'nonce',
      'acr',
      'amr',
      'azp',
      'at_hash',
      'name',
      'family_name',
      'given_name',
      'middle_name',
      'nickname',
      'preferred_username',
      'profile',
      'picture',
      'website',
      'gender',
      'birthdate',
      'zoneinfo',
      'locale',
      'updated_at',
      'email',
      'email_verified',
      'address',
      'phone_number',
      'phone_number_verified',
    ],
    grantTypesSupported: ['authorization_code', 'refresh_token'],
    // RFC 6749 §2.1 / OAuth 2.1 §2.4: 'none' advertises that public clients
    // (no client_secret) are accepted at the token endpoint.
    tokenEndpointAuthMethodsSupported: [
      'client_secret_basic',
      'client_secret_post',
      'none',
    ],
    // Required when any client uses userinfo_signed_response_alg
    // (OIDC Core 1.0 Section 5.3.2). Derived from the registered UserInfo key set so
    // ES256 (and other) algs are advertised once a matching key is configured.
    userinfoSigningAlgValuesSupported: userinfoSigningAlgValues,
    // OIDC Core 1.0 §6.1 / OIDC Discovery 1.0 §3: signed Request Object by value is
    // supported (verified against the client's registered JWKS). request_uri (§6.2)
    // is not supported, so it is explicitly advertised as false (Discovery defaults
    // request_uri_parameter_supported to true when omitted). RS256 is the required
    // signing alg; 'none' is added only when unsigned objects are accepted for
    // Basic OP conformance compatibility.
    requestParameterSupported: true,
    requestUriParameterSupported: false,
    requestObjectSigningAlgValuesSupported: config.allowUnsignedRequestObject
      ? ['RS256', 'none']
      : ['RS256'],
    // OIDC Discovery 1.0 §3 / Core 1.0 §5.5: the 'claims' request parameter is
    // implemented for both the ID Token and UserInfo paths, so it is advertised
    // as supported. Without this (defaults to false) spec-compliant RPs would
    // never send the 'claims' parameter.
    claimsParameterSupported: true,
    // RFC 9207 §3: authorize endpoint adds iss to all authorization responses.
    authorizationResponseIssParameterSupported: true,
    // RFC 8414 — both endpoints require confidential client authentication.
    introspectionEndpoint: `${issuer}/introspect`,
    introspectionEndpointAuthMethodsSupported: [
      'client_secret_basic',
      'client_secret_post',
    ],
    revocationEndpoint: `${issuer}/revoke`,
    revocationEndpointAuthMethodsSupported: [
      'client_secret_basic',
      'client_secret_post',
    ],
  });

  // RFC 8414 §3.2 / RFC 9111 §5.2: Discovery metadata is cacheable. Advertise a
  // 3600s freshness lifetime, symmetric with the JWKS endpoint (jwks.ts), so
  // client libraries reuse the metadata deterministically.
  c.header('Cache-Control', 'public, max-age=3600');
  // code_challenge_methods_supported is defined in OAuth 2.1 / PKCE spec,
  // not in OIDC Discovery, so it is added separately.
  return c.json({
    ...metadata,
    code_challenge_methods_supported: ['S256'],
  });
});
