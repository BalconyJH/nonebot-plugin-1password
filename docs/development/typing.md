# Typing

The project ships `py.typed`, supports Python 3.10–3.13, and passes BasedPyright strict mode, verifytypes, and ty.

## Rules

- SDK, NoneBot, ORM, and TLS types exist only at their respective integration or transport boundaries.
- Public Providers import only `nonebot_plugin_1password.api`.
- Domain and wire values use frozen, slotted dataclasses, closed Enums, and precise unions.
- External TOML models are strict and frozen and forbid extra fields. Loaders expose bounded failure categories; underlying validation exceptions must remain internal.
- `SecretValue`, grants, approval attestations, and Broker requests use validated boundary objects. Some fields, including binding fingerprints and `SecretName`, remain strings; runtime validation, not nominal typing, enforces their vocabulary and shape.
- Python 3.10 compatibility is maintained through `typing_extensions` and `tomli`, without unexplained ignores or Any values that obscure boundaries.

## Gates

```bash
make typecheck
```

This runs the existing `basedpyright`, `verifytypes`, and `ty` Make targets with the frozen environment. BasedPyright checks `src` and `tests` for unreachable code, unused symbols, implicit overrides, and invalid ignores; any warning fails the gate. verifytypes statically analyzes exported symbols across the typed package, but the third-party compatibility commitment still applies only to `nonebot_plugin_1password.api`.
