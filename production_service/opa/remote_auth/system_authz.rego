package system.authz

import rego.v1

# OPA's administrative API authorization hook. Deny everything unless the request
# is the single PACA decision endpoint and the presented access token is verified.
default allow := false

verified_claims := claims if {
    is_string(input.identity)
    [valid, header, claims] := io.jwt.decode_verify(input.identity, {
        "cert": data.paca_opa_auth.jwks,
        "alg": "RS256",
        "iss": data.paca_opa_auth.issuer,
        "aud": data.paca_opa_auth.audience,
    })
    valid == true
    header.typ in {"at+JWT", "application/at+JWT"}
}

allow if {
    input.method == "POST"
    input.path == ["v1", "data", "paca", "authz", "decision"]
    claims := verified_claims
    claims.client_id == data.paca_opa_auth.client_id
    data.paca_opa_auth.required_scope in split(claims.scope, " ")
}
