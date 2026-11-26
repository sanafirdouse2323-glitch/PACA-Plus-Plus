import base64
import hashlib
import json
import time
from typing import Any
import jwt
from jwt.algorithms import RSAAlgorithm, ECAlgorithm

class DPoPVerificationError(ValueError):
    """Raised when a DPoP proof fails RFC 9449 validation."""

class DPoPValidator:
    """Validates DPoP (Demonstrating Proof-of-Possession) proofs according to RFC 9449.
    
    Binds the caller's access token cryptographically to an ephemeral client public key,
    preventing stolen bearer token replay.
    """
    
    def __init__(self, max_clock_skew_seconds: float = 60.0):
        self.max_clock_skew_seconds = max_clock_skew_seconds

    def compute_ath(self, access_token: str) -> str:
        """Computes the base64url-encoded SHA-256 hash of the access token."""
        digest = hashlib.sha256(access_token.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")

    def verify_dpop_proof(
        self,
        dpop_header: str,
        http_method: str,
        http_url: str,
        access_token: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(dpop_header, str) or not dpop_header.strip():
            raise DPoPVerificationError("missing_dpop_proof")

        # 1. Inspect unverified header for jwk and typ
        try:
            unverified_header = jwt.get_unverified_header(dpop_header)
        except Exception as exc:
            raise DPoPVerificationError("malformed_dpop_jwt") from exc

        if unverified_header.get("typ") != "dpop+jwt":
            raise DPoPVerificationError("invalid_dpop_typ")

        alg = unverified_header.get("alg")
        if not alg or alg == "none":
            raise DPoPVerificationError("dpop_alg_none_forbidden")

        jwk = unverified_header.get("jwk")
        if not isinstance(jwk, dict) or not jwk.get("kty"):
            raise DPoPVerificationError("missing_dpop_jwk")

        # 2. Extract public key from JWK
        try:
            if jwk.get("kty") == "RSA":
                public_key = RSAAlgorithm.from_jwk(json.dumps(jwk))
            elif jwk.get("kty") == "EC":
                public_key = ECAlgorithm.from_jwk(json.dumps(jwk))
            else:
                raise DPoPVerificationError(f"unsupported_jwk_kty_{jwk.get('kty')}")
        except Exception as exc:
            raise DPoPVerificationError("invalid_dpop_public_key") from exc

        # 3. Verify signature and claims
        try:
            payload = jwt.decode(
                dpop_header,
                public_key,
                algorithms=[alg],
                options={"verify_signature": True, "verify_exp": False},
            )
        except Exception as exc:
            raise DPoPVerificationError("dpop_signature_invalid") from exc

        # 4. Check iat (freshness)
        iat = payload.get("iat")
        if not isinstance(iat, (int, float)):
            raise DPoPVerificationError("missing_dpop_iat")
        now = time.time()
        if abs(now - iat) > self.max_clock_skew_seconds:
            raise DPoPVerificationError("dpop_proof_expired_or_future")

        # 5. Check htm (HTTP Method)
        htm = payload.get("htm")
        if not isinstance(htm, str) or htm.upper() != http_method.upper():
            raise DPoPVerificationError("dpop_htm_mismatch")

        # 6. Check htu (HTTP URI normalized)
        htu = payload.get("htu")
        if not isinstance(htu, str) or not htu.strip():
            raise DPoPVerificationError("dpop_missing_htu")
            
        normalized_target = http_url.split("?")[0].split("#")[0].rstrip("/")
        normalized_claim = htu.split("?")[0].split("#")[0].rstrip("/")
        if normalized_claim != normalized_target:
            raise DPoPVerificationError("dpop_htu_mismatch")

        # 7. Check ath (Access Token Hash) if access token provided
        if access_token:
            ath = payload.get("ath")
            expected_ath = self.compute_ath(access_token)
            if not ath or ath != expected_ath:
                raise DPoPVerificationError("dpop_ath_mismatch")

        # 8. Check jti exists
        if not payload.get("jti") or not isinstance(payload.get("jti"), str):
            raise DPoPVerificationError("missing_dpop_jti")

        return payload
