"""Framework and infrastructure ports consumed by application services."""

from .actions import (
    ActionExecutionCode,
    ActionExecutionError,
    ActionExecutor,
    ActionGrantSource,
    ActionReconciliationDeferredError,
    ApprovedActionInvocation,
    RecoverableActionExecutor,
)
from .clock import Clock, SystemClock
from .identifiers import IdentifierGenerator, SecureIdentifierGenerator
from .messaging import (
    ApprovalAction,
    MessageDeliveryError,
    MessageGateway,
    NotificationTarget,
    SafeMessage,
    UnsafeMessageError,
)
from .permissions import PermissionGateway, collect_granted_permissions
from .repositories import (
    ApprovalRepository,
    AuditRepository,
    ExecutionAttemptClaim,
    ExecutionAttemptConflictError,
    ExecutionAttemptRepository,
    OutboxItem,
    OutboxRepository,
    PersistenceConfigurationError,
    PersistenceError,
    PersistenceIntegrityError,
    PersistenceUnavailableError,
    RepositoryUnitOfWork,
    RequestRepository,
    UnitOfWorkFactory,
)

__all__ = [
    "ActionExecutionCode",
    "ActionExecutionError",
    "ActionExecutor",
    "ActionGrantSource",
    "ActionReconciliationDeferredError",
    "ApprovalAction",
    "ApprovalRepository",
    "ApprovedActionInvocation",
    "AuditRepository",
    "Clock",
    "ExecutionAttemptClaim",
    "ExecutionAttemptConflictError",
    "ExecutionAttemptRepository",
    "IdentifierGenerator",
    "MessageDeliveryError",
    "MessageGateway",
    "NotificationTarget",
    "OutboxItem",
    "OutboxRepository",
    "PermissionGateway",
    "PersistenceConfigurationError",
    "PersistenceError",
    "PersistenceIntegrityError",
    "PersistenceUnavailableError",
    "RecoverableActionExecutor",
    "RepositoryUnitOfWork",
    "RequestRepository",
    "SafeMessage",
    "SecureIdentifierGenerator",
    "SystemClock",
    "UnitOfWorkFactory",
    "UnsafeMessageError",
    "collect_granted_permissions",
]
