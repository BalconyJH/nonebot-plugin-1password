"""Pure transitions for the access request's single authoritative state."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from .enums import RequestStatus
from .errors import (
    DomainInvariant,
    DomainValidationError,
    InvalidRequestTransitionError,
    RequestExpiredError,
    RequestNotExpiredError,
)

if TYPE_CHECKING:
    from datetime import datetime

    from .models import AccessRequest

_REQUEST_TRANSITIONS: dict[RequestStatus, frozenset[RequestStatus]] = {
    RequestStatus.PENDING: frozenset(
        {
            RequestStatus.APPROVED,
            RequestStatus.REJECTED,
            RequestStatus.CANCELLED,
            RequestStatus.EXPIRED,
        }
    ),
    RequestStatus.APPROVED: frozenset({RequestStatus.EXECUTING}),
    RequestStatus.EXECUTING: frozenset({RequestStatus.SUCCEEDED, RequestStatus.FAILED}),
    RequestStatus.SUCCEEDED: frozenset(),
    RequestStatus.FAILED: frozenset(),
    RequestStatus.REJECTED: frozenset(),
    RequestStatus.CANCELLED: frozenset(),
    RequestStatus.EXPIRED: frozenset(),
}


def _require_transition_time(now: datetime) -> None:
    if now.tzinfo is None or now.utcoffset() is None:
        raise DomainValidationError(DomainInvariant.AWARE_DATETIME)


def allowed_request_transitions(status: RequestStatus) -> frozenset[RequestStatus]:
    """Return the immutable set of legal direct targets for one status."""
    return _REQUEST_TRANSITIONS[status]


def request_is_terminal(status: RequestStatus) -> bool:
    """Return whether the authoritative request state has no legal successor."""
    return not _REQUEST_TRANSITIONS[status]


def transition_request(
    request: AccessRequest,
    target: RequestStatus,
    *,
    now: datetime,
) -> AccessRequest:
    """Return a versioned state transition or a precise domain failure."""
    if target not in _REQUEST_TRANSITIONS[request.status]:
        raise InvalidRequestTransitionError(request.status, target)
    _require_transition_time(now)
    if now < request.updated_at:
        raise DomainValidationError(DomainInvariant.TIME_ORDER)
    if request.status is RequestStatus.PENDING:
        expired = now >= request.expires_at
        if target is RequestStatus.EXPIRED and not expired:
            raise RequestNotExpiredError
        if target is not RequestStatus.EXPIRED and expired:
            raise RequestExpiredError
    return replace(
        request,
        status=target,
        updated_at=now,
        version=request.version + 1,
    )


def expire_request(request: AccessRequest, *, now: datetime) -> AccessRequest:
    """Expire a due pending request and leave every other request unchanged."""
    _require_transition_time(now)
    if request.status is not RequestStatus.PENDING or now < request.expires_at:
        return request
    return transition_request(request, RequestStatus.EXPIRED, now=now)


__all__ = [
    "allowed_request_transitions",
    "expire_request",
    "request_is_terminal",
    "transition_request",
]
