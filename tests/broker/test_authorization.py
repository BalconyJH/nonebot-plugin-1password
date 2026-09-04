"""Tests for Broker-local policy and private-binding authorization lookup."""

from __future__ import annotations

from dataclasses import replace

from nonebot_plugin_1password.actions import ActionBinding, ActionBindingCatalog
from nonebot_plugin_1password.application.action_policy_catalog import (
    ActionPolicyCatalog,
)
from nonebot_plugin_1password.broker.authorization import (
    LocalBrokerAuthorizationResolver,
)
from nonebot_plugin_1password.broker.protocol import AttestedPolicyEffect
from nonebot_plugin_1password.core import (
    ActionPolicyEffect,
    ActionPolicySnapshot,
    SecretReference,
)


def _policy(
    effect: ActionPolicyEffect = ActionPolicyEffect.REQUIRE_APPROVAL,
) -> ActionPolicySnapshot:
    requires_approval = effect is ActionPolicyEffect.REQUIRE_APPROVAL
    return ActionPolicySnapshot(
        policy_id="rotation-policy",
        policy_version=3,
        resource_alias="grafana-prod",
        action_name="rotate-credential",
        provider_name="grafana-rotation",
        effect=effect,
        requester_groups=frozenset(),
        requester_permissions=frozenset(),
        approver_permissions=(
            frozenset({"grafana.approve"}) if requires_approval else frozenset()
        ),
        quorum=2 if requires_approval else 0,
        request_ttl_seconds=300,
        require_reason=False,
        require_confirmation=False,
        require_incident=False,
        allow_self_approval=False,
        require_private=False,
        allowed_scene_types=frozenset(),
        allowed_utc_weekdays=frozenset(),
        allowed_utc_hours=frozenset(),
    )


def _binding(policy: ActionPolicySnapshot) -> ActionBinding:
    return ActionBinding(
        resource_alias=policy.resource_alias,
        action_name=policy.action_name,
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        provider_name=policy.provider_name,
        secret_references={
            "credential": SecretReference("op://Operations/Grafana/credential")
        },
    )


async def test_resolver_projects_current_grant_without_private_references() -> None:
    """Return effect/quorum/fingerprint while keeping references inside bindings."""
    policy = _policy()
    resolver = LocalBrokerAuthorizationResolver(
        policies=ActionPolicyCatalog((policy,)),
        bindings=ActionBindingCatalog((_binding(policy),)),
    )

    snapshot = await resolver.pull(
        resource_alias="grafana-prod",
        action_name="rotate-credential",
    )

    assert snapshot is not None
    assert snapshot.policy_effect is AttestedPolicyEffect.REQUIRE_APPROVAL
    assert snapshot.required_quorum == 2
    assert snapshot.grant.policy_id == policy.policy_id
    assert "op://" not in repr(snapshot)


async def test_resolver_hides_missing_denied_and_drifted_capabilities() -> None:
    """Collapse every non-executable or inconsistent coordinate to one miss."""
    allowed = _policy(ActionPolicyEffect.ALLOW)
    denied = _policy(ActionPolicyEffect.DENY)
    cases = (
        (
            ActionPolicyCatalog(()),
            ActionBindingCatalog(()),
        ),
        (
            ActionPolicyCatalog((denied,)),
            ActionBindingCatalog(()),
        ),
        (
            ActionPolicyCatalog((allowed,)),
            ActionBindingCatalog(
                (_binding(replace(allowed, policy_version=allowed.policy_version + 1)),)
            ),
        ),
    )

    for policies, bindings in cases:
        resolver = LocalBrokerAuthorizationResolver(
            policies=policies,
            bindings=bindings,
        )
        assert (
            await resolver.pull(
                resource_alias="grafana-prod",
                action_name="rotate-credential",
            )
            is None
        )
