"""Broker-owned current policy and private-binding authorization resolver."""

from __future__ import annotations

from typing import TYPE_CHECKING

from nonebot_plugin_1password.core import ActionPolicyEffect

from .protocol import ActionGrantProof, AttestedPolicyEffect
from .service import BrokerAuthorizationSnapshot

if TYPE_CHECKING:
    from nonebot_plugin_1password.actions import ActionBindingCatalog
    from nonebot_plugin_1password.application.action_policy_catalog import (
        ActionPolicyCatalog,
    )


class LocalBrokerAuthorizationResolver:
    """Resolve grants from Broker-local policy and private binding snapshots."""

    __slots__ = ("_bindings", "_policies")

    def __init__(
        self,
        *,
        policies: ActionPolicyCatalog,
        bindings: ActionBindingCatalog,
    ) -> None:
        """Retain immutable catalogs without exposing their private references."""
        self._policies = policies
        self._bindings = bindings

    async def pull(
        self,
        *,
        resource_alias: str,
        action_name: str,
    ) -> BrokerAuthorizationSnapshot | None:
        """Return exact current executable facts or one indistinguishable miss."""
        policy = self._policies.get(
            resource_alias=resource_alias,
            action_name=action_name,
        )
        grant = self._bindings.grant_for(
            resource_alias=resource_alias,
            action_name=action_name,
        )
        if policy is None or not policy.executable or grant is None:
            return None
        if (
            grant.policy_id != policy.policy_id
            or grant.policy_version != policy.policy_version
            or grant.provider_name != policy.provider_name
        ):
            return None
        effect = (
            AttestedPolicyEffect.ALLOW
            if policy.effect is ActionPolicyEffect.ALLOW
            else AttestedPolicyEffect.REQUIRE_APPROVAL
        )
        return BrokerAuthorizationSnapshot(
            grant=ActionGrantProof(
                policy_id=grant.policy_id,
                policy_version=grant.policy_version,
                provider_name=grant.provider_name,
                binding_fingerprint=grant.binding_fingerprint,
            ),
            policy_effect=effect,
            required_quorum=policy.quorum,
        )


__all__ = ["LocalBrokerAuthorizationResolver"]
