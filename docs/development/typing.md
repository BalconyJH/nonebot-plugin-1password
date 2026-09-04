# Typing

The project ships `py.typed`, supports Python 3.10–3.13, and passes BasedPyright strict mode, verifytypes, and ty.

## Rules

- SDK, NoneBot, ORM, and TLS types exist only at their respective integration or transport boundaries.
- Public Providers import only `nonebot_plugin_1password.api`.
- Domain and wire values use frozen, slotted dataclasses, closed Enums, and precise unions.
- External TOML models are strict and frozen, forbid extra fields, and hide input values in Pydantic errors.
- `SecretValue`, binding fingerprints, approval attestations, and Broker requests use distinct types so concepts that happen to be strings cannot be interchanged.
- Python 3.10 compatibility is maintained through `typing_extensions` and `tomli`, without unexplained ignores or Any values that obscure boundaries.

## Gates

```bash
uv run basedpyright
uv run basedpyright --verifytypes nonebot_plugin_1password --ignoreexternal
uv run ty check src tests
```

`basedpyright` checks `src` and `tests` for unreachable code, unused symbols, implicit overrides, and invalid ignores; any warning fails the gate. verifytypes imports the entire typed package, but the third-party compatibility commitment still applies only to `nonebot_plugin_1password.api`.
