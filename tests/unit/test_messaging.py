"""Tests for the adapter-neutral safe messaging port."""

from __future__ import annotations

import pytest

from nonebot_plugin_1password.domain.enums import ApprovalDecision
from nonebot_plugin_1password.domain.ids import RequestId
from nonebot_plugin_1password.ports.messaging import (
    ApprovalAction,
    NotificationTarget,
    SafeMessage,
    UnsafeMessageError,
)


def test_safe_message_accepts_bounded_multiline_text() -> None:
    """Allow ordinary presentation text and deliberate line breaks."""
    message = SafeMessage("Request req_123 is pending.\nAwaiting approval.")

    assert message.text.startswith("Request")


def test_safe_message_accepts_one_closed_request_scoped_approval_action_set() -> None:
    """Carry only typed decisions for one canonical public request ID."""
    request_id = RequestId("req-public")
    actions = (
        ApprovalAction(ApprovalDecision.APPROVE, request_id),
        ApprovalAction(ApprovalDecision.REJECT, request_id),
    )

    message = SafeMessage("Request req-public is pending.", actions=actions)

    assert message.actions == actions


@pytest.mark.parametrize(
    "actions",
    [
        (
            ApprovalAction(ApprovalDecision.APPROVE, RequestId("req-one")),
            ApprovalAction(ApprovalDecision.APPROVE, RequestId("req-one")),
        ),
        (
            ApprovalAction(ApprovalDecision.APPROVE, RequestId("req-one")),
            ApprovalAction(ApprovalDecision.REJECT, RequestId("req-two")),
        ),
    ],
)
def test_safe_message_rejects_ambiguous_approval_action_sets(
    actions: tuple[ApprovalAction, ...],
) -> None:
    """Prevent duplicate decisions or mixed request identities in one message."""
    with pytest.raises(UnsafeMessageError):
        SafeMessage("Pending approval.", actions=actions)


@pytest.mark.parametrize("request_id", ["req with space", "req\nother", "/reject"])
def test_approval_action_rejects_command_injection_coordinates(
    request_id: str,
) -> None:
    """Keep the only dynamic component value inside a canonical token."""
    with pytest.raises(UnsafeMessageError):
        ApprovalAction(ApprovalDecision.REJECT, RequestId(request_id))


@pytest.mark.parametrize(
    "text",
    [
        "",
        " leading",
        "trailing ",
        "control\x00value",
        "op://Vault/Item/field",
        "Authorization: Bearer secret",
        "ops_service_account_token",
    ],
)
def test_safe_message_rejects_ambiguous_or_sensitive_text(text: str) -> None:
    """Prevent notifications from becoming a credential delivery channel."""
    with pytest.raises(UnsafeMessageError) as captured:
        SafeMessage(text)

    if text:
        assert text not in str(captured.value)


def test_notification_target_is_exact_and_adapter_neutral() -> None:
    """Retain only normalized scene coordinates."""
    target = NotificationTarget(
        scope="Console",
        self_id="bot",
        scene_id="scene",
        scene_type="private",
        parent_scene_id=None,
    )

    assert target.scene_id == "scene"


def test_notification_target_rejects_control_characters() -> None:
    """Fail before an invalid coordinate reaches an adapter."""
    with pytest.raises(UnsafeMessageError):
        NotificationTarget(
            scope="Console",
            self_id="bot",
            scene_id="scene\nother",
            scene_type="private",
            parent_scene_id=None,
        )
