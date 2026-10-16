import asyncio

import pytest

from _instance_support import FakeProvider, identity
from ida_pro_mcp.instance_contract import RoutingError
from ida_pro_mcp.instance_registry import InstanceRegistry
from ida_pro_mcp.instance_router import InstanceRouter
from ida_pro_mcp.output_store import OutputStore


def test_output_ownership_and_expiration():
    registry = InstanceRegistry()
    a, b = [registry.publish(identity(key)) for key in ("A", "B")]
    store = OutputStore()
    first = store.remember(a, "generation-a", "same", "context-a")
    second = store.remember(b, "generation-b", "same", "context-b")
    assert first != second
    with pytest.raises(RoutingError) as error:
        store.lookup(b.instance_id, first)
    assert error.value.code == "OUTPUT_INSTANCE_MISMATCH"
    store.expire(a.instance_id)
    with pytest.raises(RoutingError) as error:
        store.lookup(a.instance_id, first)
    assert error.value.code == "OUTPUT_EXPIRED"
    assert store.lookup(b.instance_id, second).backend_output_id == "same"


def test_capacity_expires_oldest_output():
    binding = InstanceRegistry().publish(identity("A"))
    store = OutputStore(max_outputs=2)
    first = store.remember(binding, "a", "one", "a")
    second = store.remember(binding, "a", "two", "a")
    store.remember(binding, "a", "three", "a")
    with pytest.raises(RoutingError):
        store.lookup(binding.instance_id, first)
    assert store.lookup(binding.instance_id, second).backend_output_id == "two"


def test_router_output_pages_and_close_ownership():
    async def scenario():
        p = FakeProvider([identity("A"), identity("B")])
        p.result = {
            "content": [
                {"type": "text", "text": "preview"},
                {"type": "text", "text": "curl http://bad"},
            ],
            "structuredContent": {"value": "preview"},
            "isError": False,
            "_meta": {
                "ida_mcp": {"output_id": "backend", "download_url": "http://bad"}
            },
        }
        p.outputs["backend"] = "0123456789"
        router = InstanceRouter(p)
        a, b = [r["instance_id"] for r in (await router.list_instances())["instances"]]
        result = await router.request(
            a, "tools/call", {"name": "py_eval", "arguments": {}}
        )
        meta = result["_meta"]["ida_mcp"]
        assert meta["instance_id"] == a
        assert "download_url" not in meta
        assert a in meta["download_hint"] and "http://bad" not in str(result)
        page = await router.read_output(a, meta["output_id"], limit=4)
        assert page["text"] == "0123" and page["next_offset"] == 4
        before = len(p.calls)
        with pytest.raises(RoutingError):
            await router.read_output(b, meta["output_id"])
        assert len(p.calls) == before
        await router.close_database(a)
        with pytest.raises(RoutingError):
            await router.read_output(a, meta["output_id"])
        await router.shutdown()

    asyncio.run(scenario())


def test_backend_cache_rejects_previous_database_generation(monkeypatch):
    from _mcp_spec_support import load_ida_rpc_module
    from ida_pro_mcp import instance_runtime

    rpc = load_ida_rpc_module()
    state = instance_runtime.RuntimeIdentity()
    monkeypatch.setattr(instance_runtime, "_runtime", state)
    old = state.activate("a.exe", "a.i64")
    with instance_runtime.generation_context(old):
        rpc._cache_output("owned-generation", {"secret": "A"})
    state.invalidate()
    new = state.activate("b.exe", "b.i64")
    with instance_runtime.generation_context(new):
        assert rpc.get_cached_output("owned-generation") is None
