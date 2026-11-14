package system.authz_test

import rego.v1
import data.system.authz as authz

mock_decode_verify(token, constraints) := [true, {"typ": "at+JWT", "alg": "RS256"}, {
    "client_id": "paca-opa-client",
    "sub": "paca-opa-client",
    "aud": "https://opa.example.org/",
    "scope": "opa.decide",
    "iat": 2000000000,
    "exp": 2100000000,
}] if {
    token == "valid-token"
    constraints.alg == "RS256"
    constraints.iss == "https://identity.example.org/"
    constraints.aud == "https://opa.example.org/"
    is_string(constraints.cert)
    is_number(constraints.time)
}

mock_decode_verify(token, constraints) := [true, {"typ": "at+JWT", "alg": "RS256"}, {
    "client_id": "unapproved-client",
    "sub": "unapproved-client",
    "aud": "https://opa.example.org/",
    "scope": "opa.decide",
    "iat": 2000000000,
    "exp": 2100000000,
}] if {
    token == "wrong-client-token"
    constraints.alg == "RS256"
}

mock_decode_verify(token, constraints) := [true, {"typ": "at+JWT", "alg": "RS256"}, {
    "client_id": "paca-opa-client",
    "sub": "paca-opa-client",
    "aud": "https://opa.example.org/",
    "scope": "documents.write",
    "iat": 2000000000,
    "exp": 2100000000,
}] if {
    token == "wrong-scope-token"
    constraints.alg == "RS256"
}

mock_decode_verify(token, _) := [false, {}, {}] if token == "wrong-audience-token"

mock_decode_verify(_, _) := [false, {}, {}]

authz_data := {
    "jwks": {"keys": []},
    "issuer": "https://identity.example.org/",
    "audience": "https://opa.example.org/",
    "client_id": "paca-opa-client",
    "required_scope": "opa.decide",
}

test_allows_only_valid_jwt_for_decision_endpoint if {
    authz.allow
        with input as {
            "identity": "valid-token",
            "method": "POST",
            "path": ["v1", "data", "paca", "authz", "decision"],
        }
        with data.paca_opa_auth as authz_data
        with time.now_ns as mock_now_ns
        with io.jwt.decode_verify as mock_decode_verify
}

test_denies_wrong_client_even_with_valid_signature if {
    not authz.allow
        with input as {
            "identity": "wrong-client-token",
            "method": "POST",
            "path": ["v1", "data", "paca", "authz", "decision"],
        }
        with data.paca_opa_auth as authz_data
        with time.now_ns as mock_now_ns
        with io.jwt.decode_verify as mock_decode_verify
}

test_denies_wrong_scope_even_with_valid_signature if {
    not authz.allow
        with input as {
            "identity": "wrong-scope-token",
            "method": "POST",
            "path": ["v1", "data", "paca", "authz", "decision"],
        }
        with data.paca_opa_auth as authz_data
        with time.now_ns as mock_now_ns
        with io.jwt.decode_verify as mock_decode_verify
}

test_denies_wrong_method_and_path_by_default if {
    not authz.allow
        with input as {
            "identity": "valid-token",
            "method": "GET",
            "path": ["v1", "policies"],
        }
        with data.paca_opa_auth as authz_data
        with time.now_ns as mock_now_ns
        with io.jwt.decode_verify as mock_decode_verify
}



test_denies_wrong_audience_even_when_presented_as_bearer_token if {
    not authz.allow
        with input as {
            "identity": "wrong-audience-token",
            "method": "POST",
            "path": ["v1", "data", "paca", "authz", "decision"],
        }
        with data.paca_opa_auth as authz_data
        with time.now_ns as mock_now_ns
        with io.jwt.decode_verify as mock_decode_verify
}

mock_now_ns() := 2050000000000000000
