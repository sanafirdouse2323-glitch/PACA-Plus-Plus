package system.authz

import rego.v1

# OPA's administrative API authorization hook. Default-deny every API request.
# input.identity is populated by OPA's --authentication=token handler.
default allow := false

verified_claims := claims if {
    is_string(input.identity)
    [valid, header, claims] := io.jwt.decode_verify(input.identity, {
        "cert": json.marshal(data.paca_opa_auth.jwks),
        "alg": "RS256",
        "iss": data.paca_opa_auth.issuer,
        "aud": data.paca_opa_auth.audience,
        "time": time.now_ns(),
    })
    valid == true
    header.alg == "RS256"
    header.typ in {"at+JWT", "application/at+JWT"}
    is_number(claims.iat)
    claims.iat <= (time.now_ns() / 1000000000)
    is_number(claims.exp)
}

allow if {
    input.method == "POST"
    input.path == ["v1", "data", "paca", "authz", "decision"]
    claims := verified_claims
    claims.aud == data.paca_opa_auth.audience
    claims.client_id == data.paca_opa_auth.client_id
    claims.sub == data.paca_opa_auth.client_id
    is_string(claims.scope)
    data.paca_opa_auth.required_scope in split(claims.scope, " ")
}
