# Remote OPA authentication and audience enforcement

The PACA service's `OPAClient` sends its service credential in an HTTP Bearer header. That header alone does **not** authenticate a remote caller: the OPA server must enable token authentication and API authorization, and its `system.authz` policy must validate the token and restrict the API surface.

## Required OPA-side controls

Deploy `remote_auth/system_authz.rego` in the same OPA bundle as `policies/authz.rego`. Start remote OPA with:

```sh
opa run --server \
  --addr=https://0.0.0.0:8181 \
  --tls-cert-file=/run/opa/tls/server.crt \
  --tls-private-key-file=/run/opa/tls/server.key \
  --authentication=token \
  --authorization=basic \
  /srv/opa/bundle
```

Do not expose a parallel unauthenticated HTTP listener. OPA's `system.authz` policy validates the token extracted by OPA into `input.identity`: signature, RS256 algorithm, exact issuer and audience, `exp`/ `nbf` time validity, access-token type, client identity, subject and the `opa.decide` scope. It permits only `POST /v1/data/paca/authz/decision`. All other APIs are denied by default. OPA's authorization hook receives the authenticated bearer token in `input.identity`; it does not accept a JWT found only in the JSON request body.

The bundle's `data.json` must include:

```json
{
  "paca_opa_auth": {
    "issuer": "https://identity.example.org/",
    "audience": "https://opa.example.org/",
    "client_id": "paca-opa-client",
    "required_scope": "opa.decide",
    "jwks": { "keys": [] }
  }
}
```

Use the identity provider's public signing JWKS, not private keys. Distribute and rotate the JWKS through the normal reviewed OPA bundle process. Keep the issuer, audience, client ID and JWKS under administrator control, never in model-visible input.

## PACA service configuration

For OAuth client-credentials mode, configure the dedicated OPA service identity:

```dotenv
PACA_OPA_URL=https://opa.example.org
PACA_OPA_OAUTH_TOKEN_URL=https://identity.example.org/oauth/token
PACA_OPA_OAUTH_CLIENT_ID=paca-opa-client
PACA_OPA_OAUTH_CLIENT_SECRET=<injected-from-secret-manager>
PACA_OPA_OAUTH_SCOPE=opa.decide
PACA_OPA_OAUTH_RESOURCE=https://opa.example.org/
```

The OAuth client sends the RFC 8707 `resource` parameter to the token endpoint. The authorization server must be configured to issue a JWT access token whose `aud` matches the resource indicator; the OPA policy validates the actual signed token claims rather than trusting the request parameter. Configure a separate client ID, client secret, scope and resource indicator for downstream APIs (`PACA_API_OAUTH_*`).

Use one resource indicator per token. This example expects an RFC 9068-style JWT access token with `typ=at+JWT` (or `application/at+JWT`), RS256, issuer, audience, `client_id`, `sub`, `iat`, `exp` and a space-delimited `scope` claim. Opaque access tokens and providers that do not issue this profile need a separately reviewed introspection-based policy; do not silently decode an unverified JWT or accept a missing audience.

This example does not implement token introspection/revocation, DPoP, mTLS-bound OAuth tokens or automatic JWKS retrieval. TLS protects the OPA endpoint; the OAuth/JWT policy authenticates the caller. A static `PACA_OPA_BEARER_TOKEN` requires a separate administrator-managed static-token policy and is not validated by this JWT profile example.

## Tests

```sh
opa test --bundle production_service/opa/remote_auth -v
pytest production_service/tests/test_service_tokens.py production_service/tests/test_config.py -q
```

The production-service CI starts a real OPA server with `--authentication=token --authorization=basic` over verified HTTPS. It exercises signed JWT acceptance, wrong-audience/client/scope rejection, default-deny API path restrictions and the PACA `OPAClient` over its actual HTTP endpoint. The token endpoint is a deterministic test fixture; the customer's identity provider and production OPA deployment still require deployment-specific configuration and verification.
