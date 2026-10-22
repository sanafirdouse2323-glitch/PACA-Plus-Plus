"""PACA++ authorization research package."""
from .engine import AuthorizationEngine, Decision, Policy, PolicyError, Rule, AuthorizationError
from .opa import OPADecision, OPAError, OPAPolicyDecisionPoint
from .identity import (
    AuthenticationError,
    AuthenticatedPrincipal,
    AuthorizationContextProvider,
    CallbackContextProvider,
    ContextRetrievalError,
    JWTAuthenticator,
    TrustedAuthorizationContext,
)
from .durable import (
    FernetResponseProtector,
    IdempotencyConflict,
    OperationOutcomeUnknown,
    OperationRecord,
    OperationStateError,
    PostgresOperationStore,
    SQLiteOperationStore,
    StoreError,
)
from .gateway import (
    ActionRequest,
    AuthorizationDenied,
    ContextChanged,
    GatewayResult,
    HTTPJsonActionAdapter,
    OperationOutcomeUnresolved,
    PolicyEvaluationFailed,
    ProtectedToolGateway,
    RemoteToolError,
)

__all__ = [
    "AuthorizationEngine", "Decision", "Policy", "PolicyError", "Rule", "AuthorizationError",
    "OPADecision", "OPAError", "OPAPolicyDecisionPoint",
    "AuthenticationError", "AuthenticatedPrincipal", "AuthorizationContextProvider",
    "CallbackContextProvider", "ContextRetrievalError", "JWTAuthenticator",
    "TrustedAuthorizationContext",
    "FernetResponseProtector", "IdempotencyConflict", "OperationOutcomeUnknown", "OperationRecord", "OperationStateError",
    "PostgresOperationStore", "SQLiteOperationStore", "StoreError",
    "ActionRequest", "AuthorizationDenied", "ContextChanged", "GatewayResult",
    "HTTPJsonActionAdapter", "OperationOutcomeUnresolved", "PolicyEvaluationFailed",
    "ProtectedToolGateway", "RemoteToolError",
]
