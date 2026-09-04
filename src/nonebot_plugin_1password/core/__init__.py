"""Stable core contracts independent of NoneBot and the 1Password SDK."""

from .action_policies import (
    ActionPolicyEffect,
    ActionPolicySnapshot,
    ActionPolicyValidationError,
    ActionPolicyViolation,
)
from .actions import (
    ActionContext,
    ActionContractError,
    ActionContractViolation,
    ActionGrantSnapshot,
    ActionResult,
)
from .approvals import (
    ApprovalAttestation,
    ApprovalAttestationError,
    ApprovalAttestationViolation,
)
from .models import (
    BackendState,
    BackendStatus,
    CatalogResource,
    HealthStatus,
    PrincipalContext,
    ResourceSummary,
    SecretName,
    SecretReference,
)
from .request_inputs import (
    UnsafeRequestInputError,
    normalize_optional_request_text,
)
from .secrets import (
    SecretBackend,
    SecretBackendError,
    SecretValue,
    SecretValueExposureError,
)

__all__ = [
    "ActionContext",
    "ActionContractError",
    "ActionContractViolation",
    "ActionGrantSnapshot",
    "ActionPolicyEffect",
    "ActionPolicySnapshot",
    "ActionPolicyValidationError",
    "ActionPolicyViolation",
    "ActionResult",
    "ApprovalAttestation",
    "ApprovalAttestationError",
    "ApprovalAttestationViolation",
    "BackendState",
    "BackendStatus",
    "CatalogResource",
    "HealthStatus",
    "PrincipalContext",
    "ResourceSummary",
    "SecretBackend",
    "SecretBackendError",
    "SecretName",
    "SecretReference",
    "SecretValue",
    "SecretValueExposureError",
    "UnsafeRequestInputError",
    "normalize_optional_request_text",
]
