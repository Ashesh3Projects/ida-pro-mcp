"""FastMCP composition and CLI hosting for exact Nexus database bindings."""
from pathlib import Path
from .instance_router import InstanceRouter
from .fastmcp_frontend import create_server


def _profile_names(profile):
    if profile is None or isinstance(profile, set):
        return profile
    return {name for line in Path(profile).read_text(encoding="utf-8").splitlines()
            if (name := line.split("#", 1)[0].strip())}


def configure_server(*, extensions=None, profile=None, provider=None, database=None):
    if provider is None:
        from .nexus_backend import NexusProvider
        provider = NexusProvider()
    return create_server(InstanceRouter(provider), extensions=set(extensions or ()),
                         profile=_profile_names(profile), database=database)


class UnifiedHost:
    def __init__(self, *, extensions=None, profile=None):
        self.extensions = extensions
        self.profile = profile

    def _server(self, database=None, agent=None, idle_timeout=None):
        if idle_timeout is not None:
            raise ValueError("Leases remain alive until explicit close or server shutdown")
        return configure_server(extensions=self.extensions, profile=self.profile, database=database)

    def serve_stdio(self, **options):
        self._server(**options).run(transport="stdio", show_banner=False)

    def serve_http(self, host="127.0.0.1", port=8737, *, path_prefix="", background=False, **options):
        if background:
            raise ValueError("Use the HTTP app lifespan for background hosting")
        self._server(**options).run(
            transport="http", host=host, port=port,
            path=path_prefix.rstrip("/") + "/mcp", show_banner=False,
            json_response=False, stateless_http=False,
            host_origin_protection=True, allowed_hosts=[host, "localhost", "127.0.0.1", "::1"],
        )
