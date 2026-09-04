# Local type stubs

This directory supplies only the minimal type surfaces used by the project but not yet exposed by upstream distributions through `py.typed` or `.pyi` files:

- `onepassword.client.Client.authenticate`: the current `onepassword-sdk` distribution has no `py.typed` marker.
- `nonebug` pytest stash keys: the current `nonebug` distribution has no `py.typed` marker.

Removing these stubs causes BasedPyright strict mode to report `reportMissingTypeStubs` for the respective packages. When upgrading dependencies, first verify a temporary copy that does not load this directory, then remove only the portions officially supplied upstream.
