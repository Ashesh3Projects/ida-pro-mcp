"""Pinned Nexus GUI lifecycle adapter for database replacement in one process.

Admission is closed without blocking IDA's thread. Pending main-thread callbacks
fail their immutable generation check, then teardown and re-registration run on
the IDA thread once the old service has drained.
"""

import sys
import threading
import time

from .instance_runtime import runtime_identity

_retiring = False


def guard_runtime(runtime, generation):
    if hasattr(runtime, "_ida_pro_mcp_generation"):
        return
    original = runtime._run_sync
    runtime._ida_pro_mcp_generation = generation

    def guarded(function, *args, **kwargs):
        def execute():
            runtime_identity().check(generation)
            return function()
        return original(execute, *args, **kwargs)

    runtime._run_sync = guarded


def refresh_gui_service():
    global _retiring
    plugin = sys.modules.get("ida_nexus.plugin")
    component = getattr(plugin, "_component", None)
    if component is None or _retiring:
        return
    info = runtime_identity().snapshot()
    server = component._server
    runtime = component._runtime
    if server is None:
        if info:
            plugin.start()
            runtime = component._runtime
        if runtime is not None and info:
            guard_runtime(runtime, info["generation"])
        return
    if runtime is not None and info and not hasattr(runtime, "_ida_pro_mcp_generation"):
        guard_runtime(runtime, info["generation"])
        return
    if info and getattr(runtime, "_ida_pro_mcp_generation", None) == info["generation"]:
        return
    _retiring = True
    # This adapter is restricted to pinned Nexus 0.13.0's lifecycle fields.
    with server._activity:
        server._draining = True
        server._stream_stop.set()
        for lease in server._leases.values():
            lease.stop.set()
        server._activity.notify_all()

    def drain():
        # The main thread remains available to reject queued stale callbacks.
        with server._activity:
            while server._active_requests:
                server._activity.wait(0.05)
        analysis = server._analysis_thread
        if analysis is not None:
            analysis.join()
        server.stop()
        import ida_kernwin
        def finish():
            global _retiring
            try:
                # No SDK work is done in this background thread.
                if getattr(plugin, "_component", None) is component:
                    plugin.term()
                    if runtime_identity().snapshot():
                        plugin.init(owner="ida-pro-mcp")
                        plugin.start()
                        next_runtime = plugin._component._runtime
                        guard_runtime(next_runtime, runtime_identity().snapshot()["generation"])
            finally:
                _retiring = False
            return 1
        ida_kernwin.execute_sync(finish, ida_kernwin.MFF_FAST | ida_kernwin.MFF_NOWAIT)

    threading.Thread(target=drain, name="ida-mcp-database-retire", daemon=True).start()
