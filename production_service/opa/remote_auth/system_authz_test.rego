package system.authz_test

import rego.v1
import data.system.authz as authz

mock_verify(token, constraints) := [true, {"typ": "at+JWT"}, {
    "client_id": "paca-opa-client",
    "scope": "opa.decide",
}] if {
    token == "valid-token"
    constraints.alg == "RS256"
    constraints.iss == "https://identity.example.org/"
    constraints.aud == "https://opa.example.org/"
}

mock_verify(_, _) := [false, {}, {}]

test_allows_only_valid_jwt_for_decision_endpoint if {
    authz.allow
        with input as {
            "identity": "valid-token",
            "method": "POST",
            "path": ["v1", "data", "paca", "authz", "decision"],
        }
        with data.paca_opa_auth as {
            "jwks": {"keys": []},
            "issuer": "https://identity.example.org/",
            "audience": "https://opa.example.org/",
            "client_id": "paca-opa-client",
            "required_scope": "opa.decide",
        }
        with io.jwt.decode_verify as mock_verify
}

test_denies_wrong_method_by_default if {
    not system.authz.allow
        with input as {
            "identity": "valid-token",
            "method": "GET",
            "path": ["v1", "data", "paca", "authz", "decision"],
        }
        with data.paca_opa_auth as {
            "jwks": {"keys": []},
            "issuer": "https://identity.example.org/",
            "audience": "https://opa.example.org/",
            "client_id": "paca-opa-client",
            "required_scope": "opa.decide",
        }
        with io.jwt.decode_verify as mock_verify
}

test_denies_other_opa_paths_by_default if {
    not system.authz.allow
        with input as {
            "identity": "valid-token",
            "method": "POST",
            "path": ["v1", "policies"],
        }
        with data.paca_opa_auth as {
            "jwks": {"keys": []},
            "issuer": "https://identity.example.org/",
            "audience": "https://opa.example.org/",
            "client_id": "paca-opa-client",
            "required_scope": "opa.decide",
        }
        with io.jwt.decode_verify as mock_verify
}
