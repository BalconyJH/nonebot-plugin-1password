"""Typed, fail-closed 1Password SDK integration."""

from .backend import (
    DISTRIBUTION_NAME,
    SERVICE_ACCOUNT_TOKEN_ENV,
    OnePasswordBackend,
    create_backend_from_environment,
)
from .unavailable import DisabledSecretBackend, UnavailableSecretBackend

__all__ = [
    "DISTRIBUTION_NAME",
    "SERVICE_ACCOUNT_TOKEN_ENV",
    "DisabledSecretBackend",
    "OnePasswordBackend",
    "UnavailableSecretBackend",
    "create_backend_from_environment",
]
