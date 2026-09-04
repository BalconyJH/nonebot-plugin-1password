class Client:
    @classmethod
    async def authenticate(
        cls,
        *,
        auth: str,
        integration_name: str,
        integration_version: str,
    ) -> Client: ...
