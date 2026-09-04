"""Submit, list, and cancel persistent access requests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING

from nonebot_plugin_1password.core import ActionGrantSnapshot, ActionPolicyEffect
from nonebot_plugin_1password.domain.enums import AuditEventType, RequestStatus
from nonebot_plugin_1password.domain.errors import (
    ConcurrencyConflictError,
    PolicyDeniedError,
    RequestNotFoundError,
)
from nonebot_plugin_1password.domain.ids import (
    ActionName,
    CorrelationId,
    PrincipalId,
    RequestId,
    ResourceAlias,
)
from nonebot_plugin_1password.domain.models import (
    AccessRequest,
    ApprovalRequestedAuditEvidence,
    PolicyEvaluationAuditEvidence,
    RequestTransitionAuditEvidence,
)
from nonebot_plugin_1password.domain.policies import (
    PolicyEngine,
    PolicyEvaluation,
    PolicyEvaluationInput,
)
from nonebot_plugin_1password.domain.state_machine import (
    expire_request,
    transition_request,
)
from nonebot_plugin_1password.ports.permissions import collect_granted_permissions

from .audit import AuditRecord
from .dto import (
    RequestDTO,
    RequestRequirements,
    RequestSubmission,
    request_to_dto,
)
from .notifications import (
    ApprovalNotification,
    RequestNotification,
    enqueue_approval_notification,
    enqueue_request_notification,
)

_MINE_RESULT_LIMIT = 100

if TYPE_CHECKING:
    from nonebot_plugin_1password.application.action_policy_catalog import (
        ActionPolicyCatalog,
    )
    from nonebot_plugin_1password.application.approval_route_catalog import (
        ApprovalRouteCatalog,
    )
    from nonebot_plugin_1password.application.audit import AuditService
    from nonebot_plugin_1password.application.resource_catalog import ResourceCatalog
    from nonebot_plugin_1password.core import ActionPolicySnapshot, PrincipalContext
    from nonebot_plugin_1password.ports.actions import ActionGrantSource
    from nonebot_plugin_1password.ports.clock import Clock
    from nonebot_plugin_1password.ports.identifiers import IdentifierGenerator
    from nonebot_plugin_1password.ports.messaging import NotificationTarget
    from nonebot_plugin_1password.ports.permissions import PermissionGateway
    from nonebot_plugin_1password.ports.repositories import UnitOfWorkFactory


class RequestTargetUnavailableError(LookupError):
    """A resource or action policy is absent or invisible to the principal."""

    def __init__(self) -> None:
        """Build one non-enumerating error without retaining lookup input."""
        super().__init__("request target is unavailable")


@dataclass(frozen=True, slots=True)
class RequestServiceDependencies:
    """Explicit non-Secret dependencies for request application operations."""

    resources: ResourceCatalog
    action_policies: ActionPolicyCatalog
    approval_routes: ApprovalRouteCatalog
    action_grants: ActionGrantSource
    policy_engine: PolicyEngine
    permissions: PermissionGateway
    unit_of_work: UnitOfWorkFactory
    clock: Clock
    identifiers: IdentifierGenerator
    audit: AuditService


class RequestService:
    """Apply visibility, permission, policy, and persistence invariants."""

    __slots__ = (
        "_action_grants",
        "_action_policies",
        "_approval_routes",
        "_audit",
        "_clock",
        "_identifiers",
        "_permissions",
        "_policy_engine",
        "_resources",
        "_unit_of_work",
    )

    def __init__(self, dependencies: RequestServiceDependencies) -> None:
        """Retain explicit ports without any Secret-capable dependency."""
        self._resources = dependencies.resources
        self._action_policies = dependencies.action_policies
        self._approval_routes = dependencies.approval_routes
        self._action_grants = dependencies.action_grants
        self._policy_engine = dependencies.policy_engine
        self._permissions = dependencies.permissions
        self._unit_of_work = dependencies.unit_of_work
        self._clock = dependencies.clock
        self._identifiers = dependencies.identifiers
        self._audit = dependencies.audit

    def plan(
        self,
        principal: PrincipalContext,
        alias: str,
        action: str,
    ) -> RequestRequirements:
        """Return Waiter needs only after visibility and policy binding checks."""
        policy = self._policy_for(principal, alias, action)
        self._approval_target_for(policy)
        return RequestRequirements(
            require_reason=policy.require_reason,
            require_confirmation=policy.require_confirmation,
            require_incident=policy.require_incident,
        )

    async def submit(
        self,
        principal: PrincipalContext,
        submission: RequestSubmission,
    ) -> RequestDTO:
        """Evaluate final policy and atomically persist an allowed request."""
        policy = self._policy_for(
            principal,
            submission.alias,
            submission.action,
        )
        approval_target = self._approval_target_for(policy)

        granted_permissions = await collect_granted_permissions(
            self._permissions,
            principal=principal,
            candidates=policy.requester_permissions,
        )
        now = self._clock.now()
        evaluation = self._policy_engine.evaluate(
            PolicyEvaluationInput(
                principal=principal,
                policy=policy,
                evaluated_at=now,
                granted_permissions=granted_permissions,
                reason=submission.reason,
                confirmed=submission.confirmed,
                incident_id=submission.incident_id,
            )
        )
        correlation_id = self._identifiers.correlation_id()
        principal_id = PrincipalId(principal.principal_id)
        if not evaluation.granted:
            await self._record_denial(
                self._policy_audit_record(
                    request_id=None,
                    principal_id=principal_id,
                    correlation_id=correlation_id,
                    evaluation=evaluation,
                )
            )
            raise PolicyDeniedError(evaluation.evidence.denial_reasons)

        grant = self._grant_for(policy)
        request_id = self._identifiers.request_id()
        policy_record = self._policy_audit_record(
            request_id=request_id,
            principal_id=principal_id,
            correlation_id=correlation_id,
            evaluation=evaluation,
        )
        status = (
            RequestStatus.PENDING
            if evaluation.requires_approval
            else RequestStatus.APPROVED
        )
        request = AccessRequest(
            id=request_id,
            requester=principal,
            resource_alias=ResourceAlias(policy.resource_alias),
            action_name=ActionName(policy.action_name),
            reason=submission.reason,
            incident_id=submission.incident_id,
            status=status,
            policy=policy,
            grant=grant,
            evaluation_evidence=evaluation.evidence,
            created_at=now,
            expires_at=now + timedelta(seconds=policy.request_ttl_seconds),
            updated_at=now,
        )
        async with self._unit_of_work() as unit_of_work:
            await unit_of_work.requests.add(request)
            await self._audit.add_to(unit_of_work.audits, policy_record)
            created_event = await self._audit.add_to(
                unit_of_work.audits,
                AuditRecord(
                    request_id=request.id,
                    actor_principal_id=principal_id,
                    event_type=AuditEventType.REQUEST_CREATED,
                    evidence=RequestTransitionAuditEvidence(
                        previous_status=None,
                        current_status=request.status,
                    ),
                    correlation_id=correlation_id,
                ),
            )
            await enqueue_request_notification(
                unit_of_work,
                RequestNotification(
                    event_id=created_event.event_id,
                    principal=request.requester,
                    text=f"Request {request.id} is {request.status.value}.",
                    created_at=created_event.occurred_at,
                ),
            )
            if approval_target is not None:
                approval_event = await self._audit.add_to(
                    unit_of_work.audits,
                    AuditRecord(
                        request_id=request.id,
                        actor_principal_id=principal_id,
                        event_type=AuditEventType.APPROVAL_REQUESTED,
                        evidence=ApprovalRequestedAuditEvidence(
                            policy_id=policy.policy_id,
                            policy_version=policy.policy_version,
                            quorum=policy.quorum,
                        ),
                        correlation_id=correlation_id,
                    ),
                )
                await enqueue_approval_notification(
                    unit_of_work,
                    ApprovalNotification(
                        event_id=approval_event.event_id,
                        request_id=request.id,
                        target=approval_target,
                        text=f"Request {request.id} is {request.status.value}.",
                        created_at=approval_event.occurred_at,
                    ),
                )
            await unit_of_work.commit()
        return request_to_dto(request)

    async def mine(
        self,
        principal: PrincipalContext,
        status: RequestStatus | None = None,
    ) -> tuple[RequestDTO, ...]:
        """List only requests owned by the stable principal identity."""
        principal_id = PrincipalId(principal.principal_id)
        await self._expire_owned_pending(principal_id)
        async with self._unit_of_work() as unit_of_work:
            requests = await unit_of_work.requests.list_for_principal(
                principal_id,
                status=status,
                limit=_MINE_RESULT_LIMIT,
            )
        return tuple(request_to_dto(request) for request in requests)

    async def cancel(
        self,
        principal: PrincipalContext,
        request_id: str,
    ) -> RequestDTO:
        """Conditionally cancel one pending request owned by the principal."""
        typed_request_id = RequestId(request_id.strip())
        principal_id = PrincipalId(principal.principal_id)
        correlation_id = self._identifiers.correlation_id()
        async with self._unit_of_work() as unit_of_work:
            request = await unit_of_work.requests.get(typed_request_id)
            if request is None or request.requester_principal_id != principal_id:
                raise RequestNotFoundError(typed_request_id)
            if request.status in {RequestStatus.CANCELLED, RequestStatus.EXPIRED}:
                return request_to_dto(request)
            now = self._clock.now()
            candidate = expire_request(request, now=now)
            if candidate is request:
                candidate = transition_request(
                    request,
                    RequestStatus.CANCELLED,
                    now=now,
                )
            saved = await unit_of_work.requests.transition(
                candidate,
                expected_status=request.status,
                expected_version=request.version,
            )
            if not saved:
                raise ConcurrencyConflictError
            event = await self._audit.add_to(
                unit_of_work.audits,
                AuditRecord(
                    request_id=request.id,
                    actor_principal_id=principal_id,
                    event_type=AuditEventType.REQUEST_STATUS_CHANGED,
                    evidence=RequestTransitionAuditEvidence(
                        previous_status=request.status,
                        current_status=candidate.status,
                    ),
                    correlation_id=correlation_id,
                ),
            )
            await enqueue_request_notification(
                unit_of_work,
                RequestNotification(
                    event_id=event.event_id,
                    principal=request.requester,
                    text=f"Request {request.id} is {candidate.status.value}.",
                    created_at=event.occurred_at,
                ),
            )
            await unit_of_work.commit()
        return request_to_dto(candidate)

    async def _expire_owned_pending(self, principal_id: PrincipalId) -> None:
        now = self._clock.now()
        async with self._unit_of_work() as unit_of_work:
            pending = await unit_of_work.requests.list_for_principal(
                principal_id,
                status=RequestStatus.PENDING,
                limit=_MINE_RESULT_LIMIT,
            )
            changed = False
            for request in pending:
                expired = expire_request(request, now=now)
                if expired is request:
                    continue
                saved = await unit_of_work.requests.transition(
                    expired,
                    expected_status=request.status,
                    expected_version=request.version,
                )
                if not saved:
                    continue
                changed = True
                event = await self._audit.add_to(
                    unit_of_work.audits,
                    AuditRecord(
                        request_id=request.id,
                        actor_principal_id=principal_id,
                        event_type=AuditEventType.REQUEST_STATUS_CHANGED,
                        evidence=RequestTransitionAuditEvidence(
                            previous_status=request.status,
                            current_status=expired.status,
                        ),
                        correlation_id=self._identifiers.correlation_id(),
                    ),
                )
                await enqueue_request_notification(
                    unit_of_work,
                    RequestNotification(
                        event_id=event.event_id,
                        principal=request.requester,
                        text=f"Request {request.id} is expired.",
                        created_at=event.occurred_at,
                    ),
                )
            if changed:
                await unit_of_work.commit()

    async def _record_denial(self, record: AuditRecord) -> None:
        async with self._unit_of_work() as unit_of_work:
            await self._audit.add_to(unit_of_work.audits, record)
            await unit_of_work.commit()

    def _policy_for(
        self,
        principal: PrincipalContext,
        alias: str,
        action: str,
    ) -> ActionPolicySnapshot:
        resource = self._resources.get_summary(principal, alias)
        if resource is None:
            raise RequestTargetUnavailableError
        policy = self._action_policies.get(
            resource_alias=resource.alias,
            action_name=action,
        )
        if policy is None:
            raise RequestTargetUnavailableError
        return policy

    def _grant_for(self, policy: ActionPolicySnapshot) -> ActionGrantSnapshot:
        grant = self._action_grants.grant_for(
            resource_alias=policy.resource_alias,
            action_name=policy.action_name,
        )
        if (
            not isinstance(grant, ActionGrantSnapshot)
            or grant.policy_id != policy.policy_id
            or grant.policy_version != policy.policy_version
            or grant.provider_name != policy.provider_name
        ):
            raise RequestTargetUnavailableError
        return grant

    def _approval_target_for(
        self,
        policy: ActionPolicySnapshot,
    ) -> NotificationTarget | None:
        if policy.effect is not ActionPolicyEffect.REQUIRE_APPROVAL:
            return None
        target = self._approval_routes.get(policy.policy_id)
        if target is None:
            raise RequestTargetUnavailableError
        return target

    @staticmethod
    def _policy_audit_record(
        *,
        request_id: RequestId | None,
        principal_id: PrincipalId,
        correlation_id: CorrelationId,
        evaluation: PolicyEvaluation,
    ) -> AuditRecord:
        return AuditRecord(
            request_id=request_id,
            actor_principal_id=principal_id,
            event_type=AuditEventType.POLICY_EVALUATED,
            evidence=PolicyEvaluationAuditEvidence(
                policy=evaluation.policy,
                effective_effect=evaluation.effective_effect,
                evaluation=evaluation.evidence,
            ),
            correlation_id=correlation_id,
        )


__all__ = [
    "RequestService",
    "RequestServiceDependencies",
    "RequestTargetUnavailableError",
]
