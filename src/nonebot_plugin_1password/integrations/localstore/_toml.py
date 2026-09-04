"""Small TOML loading boundary shared by strict document loaders."""

import importlib
import sys
from collections.abc import Callable
from io import BufferedReader
from pathlib import Path
from typing import Protocol, TypeVar, cast

from pydantic import BaseModel, ValidationError

from .errors import DocumentLoadError


class _TomlModule(Protocol):
    TOMLDecodeError: type[ValueError]
    load: Callable[[BufferedReader], dict[str, object]]


_toml_module_name = "tomllib" if sys.version_info >= (3, 11) else "tomli"
tomllib = cast("_TomlModule", importlib.import_module(_toml_module_name))

DocumentT = TypeVar("DocumentT", bound=BaseModel)


def load_toml_document(path: Path, model: type[DocumentT]) -> DocumentT:
    """Load one strict TOML document without exposing its contents in errors."""
    try:
        with path.open("rb") as stream:
            payload = tomllib.load(stream)
    except OSError as exc:
        raise DocumentLoadError(
            document=path.name,
            category="read_failed",
        ) from exc
    except tomllib.TOMLDecodeError as exc:
        raise DocumentLoadError(
            document=path.name,
            category="invalid_toml",
        ) from exc

    try:
        return model.model_validate(payload, strict=True)
    except ValidationError as exc:
        raise DocumentLoadError(
            document=path.name,
            category="invalid_schema",
        ) from exc


__all__ = ["load_toml_document"]
