# OIDC identity-provider configuration

This service is an OAuth 2.0 resource server: a caller obtains an **access token** from an identity provider and presents it as a bearer token. PACA does not perform interactive user login or exchange user passwords. It verifies access-token signatures using the configured JWKS endpoint and checks issuer, audience, time claims, and required claims.

The runtime configuration is explicit: `PACA_JWT_ISSUER`, `PACA_JWT_AUDIENCE`, and `PACA_JWT_JWKS_URL`. The bootstrap does not currently discover or dynamically replace these three settings. Obtain the values from the provider's OpenID Connect discovery document, review them, and pin the expected values in deployment configuration.

## 1. Discover and configure a real provider

For a Keycloak realm named `paca`, request:

```text
https://YOUR-KEYCLOAK-HOST/realms/paca/.well-known/openid-configuration
```

From the returned JSON, copy the `issuer` and `jwks_uri` values **verbatim**. Do not derive the issuer by guessing URL path or trailing-slash rules. Configure:

```dotenv
PACA_JWT_ISSUER=<exact issuer value from discovery>
PACA_JWT_AUDIENCE=paca-api
PACA_JWT_JWKS_URL=<exact jwks_uri value from discovery>
PACA_JWT_TIMEOUT_SECONDS=5
```

The angle-bracket values above are instructions, not valid dotenv values; replace them with values from your own identity-provider environment. Keep all production identity endpoints HTTPS. An external issuer using a different audience or token shape will be rejected, intentionally.

## 2. Required and optional access-token claims

The authenticator pins the signature algorithm to **RS256**. It requires `sub`, `iss`, `aud`, `exp`, `iat`, and `tenant_id`, and verifies issuer, audience, expiry, and issue time before using the identity. It reads:
- `tenant_id`: a non-empty trusted string identifying the tenant.
- `roles`: optional list of strings, such as `["admin"]`.
- `tools`: optional list of strings identifying tools available to the principal.
- `scopes`: preferably a list of strings; otherwise the standard `scope` string is split on spaces.

For the checked-in Rego policy, `file.read` requires `file:read`, `file.create` requires `file:create`, and document operations use their corresponding document scopes. The `admin` role bypasses resource-owner matching in the current policy, so grant it only through an administrator-controlled role assignment and a trusted top-level `roles` claim. Never let users self-assign tenant IDs, application scopes, roles, or tools from profile fields.

## 3. Keycloak mapper design for an organization

Configure the **API audience** as `paca-api` and ensure it is present in the access token's `aud` claim; the verified `azp` claim alone does not satisfy this service's audience check. Configure a user-attribute mapper for `tenant_id` with access-token inclusion enabled. Map only trusted administrator-provisioned tenant membership.

Map application permissions to the claim contract used by the API and Rego policy. Suitable designs include:
- client scopes/roles assigned and controlled by administrators, emitted into a space-delimited `scope` claim; or
- an explicitly configured mapper that emits a top-level `scopes` array.

If the policy uses administrative privileges, map only approved server-side realm/client roles into the top-level `roles` list. Keycloak's default nested `realm_access.roles` object is not automatically interpreted by this application; either configure a mapper to the documented top-level claim or change and test the application/policy contract deliberately. Map `tools` only if the selected action needs the tool registry, and treat that mapping as authorization data.

For an interactive application, use Authorization Code with PKCE and have that client obtain an access token intended for `paca-api`. Do not use the committed test realm's direct password grant or hard-coded scope values in production. Prefer the organization's normal authentication, MFA, user lifecycle, client scope, and role-assignment controls.

## 4. Signing-key rotation and JWKS caching

The service uses PyJWT's `PyJWKClient` with a 300-second JWKS-set cache. The regression test exercises the real PyJWT client against a changing JWKS response: it first accepts a token signed by `key-1`, then publishes `key-2` and confirms that a token carrying the new `kid` triggers a JWKS refresh and is accepted.

For an identity-provider key rotation:
1. Publish the new public signing key with a **new, unique `kid`**. Do not replace key material while reusing an existing `kid`.
2. Verify the provider's JWKS endpoint actually publishes the new key and issue a test access token signed by it.
3. Roll the change through staging and confirm that the service accepts the new-key token and still enforces issuer, audience, expiry, tenant, and authorization claims.
4. Retire the old key only after the provider's intended overlap period and token lifetime have been considered.

A token with an unknown `kid` causes PyJWT to refresh the JWKS set. The cached JWKS may continue to supply a previously known key for up to the configured cache lifespan (300 seconds); this is an explicit rotation/revocation latency to include in the deployment threat model. Do not treat removal of a key from the provider as immediate revocation of all tokens already verifiable with a cached key. For emergency key compromise, follow a tested provider-and-service incident procedure that accounts for cache lifetime, outstanding access-token lifetime, and any process/cache restart needed. The automated test simulates JWKS rotation; it does not rotate keys in your external organization’s identity tenant or prove its operational procedures.

## 5. What the live integration test proves

The CI integration does not generate an RSA key and sign a token in the test process. It starts the versioned Keycloak server with the test-only realm export at `tests/identity/keycloak-realm.json`, calls the live OIDC discovery endpoint, obtains signed access tokens from the live token endpoint, and validates them against the live JWKS URI through the production `JWTAuthenticator`. It then uses the actual FastAPI routes, OPA HTTP client/policy, least-privilege PostgreSQL runtime store, and sandboxed filesystem adapter.

The expected behaviors include:
1. correct issuer/audience/tenant claims authenticate, and a token from a client with the wrong audience is rejected;
2. a valid token obtains a permit and executes a read through PostgreSQL and OPA;
3. the resulting execution status is accessible to the same identity;
4. a second tenant cannot discover or inspect the first tenant's resource/execution;
5. a same-tenant user who is not the resource owner is denied by the real OPA policy.

The focused authenticator tests additionally verify rejection of missing or malformed subject, tenant, role, tool, and scope claims, and exercise JWKS refresh when the provider publishes a new signing-key ID.

The test realm's HTTP endpoint, test-only password, and demonstration scope mapper are intentionally not production-safe configuration. The test does not create or configure an external identity-provider tenant on your behalf. Production must use your actual HTTPS issuer, audience, JWKS endpoint, identity lifecycle and claim-mapping setup.

## References

- [Keycloak: Get started with Docker](https://www.keycloak.org/getting-started/getting-started-docker)
- [Keycloak: OIDC protocol mappers](https://www.keycloak.org/admin-api/protocol-mappers)
