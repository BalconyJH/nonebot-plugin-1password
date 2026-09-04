"""NoneBot command, identity, permission, waiter, and messaging integrations.

Concrete modules are imported explicitly by the lifecycle after NoneBot has been
initialized. Keeping this initializer inert also makes pure helpers safe to import
in isolated tests.
"""
