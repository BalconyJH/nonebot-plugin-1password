"""Safe errors raised by Localstore document integrations."""


class DocumentLoadError(ValueError):
    """An administrator document could not be read or validated."""

    def __init__(self, *, document: str, category: str) -> None:
        """Retain only a non-sensitive document name and stable category."""
        self.document = document
        self.category = category
        super().__init__(f"{document}: {category}")


class CatalogUnavailableError(RuntimeError):
    """No valid catalog snapshot has been loaded yet."""

    def __init__(self) -> None:
        """Build a fixed unavailable-catalog error."""
        super().__init__("no valid catalog is loaded")


__all__ = ["CatalogUnavailableError", "DocumentLoadError"]
