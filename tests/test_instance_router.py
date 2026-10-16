import asyncio
from contextlib import suppress

import pytest

from _instance_support import FakeProvider, identity
from ida_pro_mcp.instance_contract import RoutingError
from ida_pro_mcp.instance_router import InstanceRouter

PARAMS = {"name": "server_health", "arguments": {}}


async def setup():
    provider = FakeProvider([identity("A"), identity("B")])
    router = InstanceRouter(provider)
    a, b = [r["instance_id"] for r in (await router.list_instances())["instances"]]
    return provider, router, a, b


def test_many_queued_calls_do_not_block_another_instance():
    async def scenario():
        p, router, a, b = await setup()
        p.block_request("A")
        tasks = [
            asyncio.create_task(router.request(a, "tools/call", PARAMS))
            for _ in range(65)
        ]
        await p.wait_entered("A", "request")
        peer = await asyncio.wait_for(router.request(b, "tools/call", PARAMS), 2)
        assert peer["structuredContent"]["backend"] == "B"
        assert all(not t.done() for t in tasks)
        p.release_request("A")
        await asyncio.gather(*tasks)
        assert len(p.sessions) == 2
        assert len({row[3] for row in p.calls}) == 66
        await router.shutdown()

    asyncio.run(scenario())


def test_cancel_and_close_affect_only_named_instance():
    async def scenario():
        p, router, a, b = await setup()
        p.block_request("A")
        pending = asyncio.create_task(router.request(a, "tools/call", PARAMS))
        await p.wait_entered("A", "request")
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        assert [key for key, _ in p.cancelled] == ["A"]
        p.block("B", "attach")
        peer = asyncio.create_task(router.request(b, "tools/call", PARAMS))
        await p.wait_entered("B", "attach")
        await asyncio.wait_for(router.close_database(a), 2)
        assert not peer.done()
        p.release("B", "attach")
        assert (await peer)["structuredContent"]["backend"] == "B"
        await router.shutdown()

    asyncio.run(scenario())


def test_failed_close_is_retriable_and_cannot_be_bypassed():
    async def scenario():
        p, router, a, b = await setup()
        await router.request(a, "tools/call", PARAMS)
        p.fail_close.add("A")
        with pytest.raises(RuntimeError, match="drain failed"):
            await router.close_database(a)
        rows = (await router.list_instances())["instances"]
        assert next(r for r in rows if r["binary_name"] == "A.exe")["instance_id"] == a
        with pytest.raises(RoutingError):
            await router.request(a, "tools/call", PARAMS)
        assert (await router.request(b, "tools/call", PARAMS))["structuredContent"][
            "backend"
        ] == "B"
        p.fail_close.clear()
        await router.close_database(a)
        assert p.sessions[0].close_count == 1
        await router.shutdown()

    asyncio.run(scenario())


def test_close_waits_for_attachment_and_releases_acquired_handle():
    async def scenario():
        p, router, a, _ = await setup()
        p.block("A", "attach")
        call = asyncio.create_task(router.request(a, "tools/call", PARAMS))
        await p.wait_entered("A", "attach")
        close = asyncio.create_task(router.close_database(a))
        await asyncio.sleep(0)
        assert not close.done()
        p.release("A", "attach")
        with suppress(asyncio.CancelledError, RoutingError):
            await call
        await close
        assert p.calls == []
        assert p.sessions[0].closed
        await router.shutdown()

    asyncio.run(scenario())


def test_cancel_open_waiter_does_not_abandon_shared_lease():
    async def scenario():
        p, router, _, _ = await setup()
        p.block("A", "open")
        first = asyncio.create_task(router.open_database("/samples/A.exe"))
        await p.wait_entered("A", "open")
        second = asyncio.create_task(router.open_database("/samples/A.exe"))
        await asyncio.sleep(0)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        p.release("A", "open")
        result = await second
        assert result["instance_id"]
        assert p.opens == ["/samples/A.exe"]
        assert not p.sessions[0].closed
        await router.shutdown()
        assert p.sessions[0].closed

    asyncio.run(scenario())


def test_shutdown_drains_healthy_peers_after_one_failure():
    async def scenario():
        p, router, a, b = await setup()
        await router.request(a, "tools/call", PARAMS)
        await router.request(b, "tools/call", PARAMS)
        p.fail_close.add("A")
        with pytest.raises(ExceptionGroup):
            await router.shutdown()
        assert not p.sessions[0].closed and p.sessions[1].closed
        with pytest.raises(RoutingError):
            await router.open_database("/samples/A.exe")
        p.fail_close.clear()
        await router.shutdown()
        assert p.sessions[0].closed

    asyncio.run(scenario())


def test_replacement_does_not_receive_stale_request():
    async def scenario():
        p, router, a, _ = await setup()
        p.records[0] = identity("replacement", binary_name="A.exe")
        await router.list_instances()
        with pytest.raises(RoutingError):
            await router.request(a, "tools/call", PARAMS)
        assert p.calls == []
        await router.shutdown()

    asyncio.run(scenario())


def test_repeated_open_of_provider_owned_session_does_not_close_it():
    async def scenario():
        p, router, a, _ = await setup()
        await router.request(a, "tools/call", PARAMS)
        existing = p.sessions[0]

        async def reuse(path, options):
            return existing

        p.open_path = reuse
        opened = await router.open_database("/samples/A.exe")
        assert opened["instance_id"] == a
        assert not existing.closed
        await router.shutdown()

    asyncio.run(scenario())


def test_open_cannot_release_retained_session_after_failed_save():
    async def scenario():
        p, router, a, _ = await setup()
        await router.request(a, "tools/call", PARAMS)
        existing = p.sessions[0]
        original = existing.request

        async def fail_save(invocation, method, params):
            if method == "save_database":
                raise RuntimeError("disk full")
            return await original(invocation, method, params)

        async def reuse(path, options):
            return existing

        existing.request = fail_save
        p.open_path = reuse
        try:
            with pytest.raises(RuntimeError, match="disk full"):
                await router.close_database(a, save=True)
            with pytest.raises(RoutingError, match="closing"):
                await router.open_database("/samples/A.exe")
            assert not existing.closed
            assert (await router.instance_status(a))["status"] == "closing"
        finally:
            existing.request = original
            await router.shutdown()

    asyncio.run(scenario())


def test_shutdown_cancels_work_before_waiting_for_dependent_alias_open():
    async def scenario():
        p, router, a, _ = await setup()
        p.block_request("A")
        call = asyncio.create_task(router.request(a, "tools/call", PARAMS))
        await p.wait_entered("A", "request")
        existing = p.sessions[0]
        opening = asyncio.Event()

        async def reuse(path, options):
            opening.set()
            return existing

        p.open_path = reuse
        opened = asyncio.create_task(router.open_database("/samples/A.i64"))
        await opening.wait()
        shutdown = asyncio.create_task(router.shutdown())
        try:
            done, _ = await asyncio.wait({shutdown}, timeout=1)
            assert shutdown in done, "shutdown waits for open before cancelling A"
            await shutdown
            assert [key for key, _ in p.cancelled] == ["A"]
            assert existing.closed
            assert existing.close_count == 1
        finally:
            p.release_request("A")
            await asyncio.gather(call, opened, shutdown, return_exceptions=True)

    asyncio.run(scenario())


def test_late_alias_open_does_not_close_previously_owned_session_twice():
    async def scenario():
        p, router, a, _ = await setup()
        await router.request(a, "tools/call", PARAMS)
        existing = p.sessions[0]
        entered, release = asyncio.Event(), asyncio.Event()

        async def reuse(path, options):
            entered.set()
            await release.wait()
            return existing

        p.open_path = reuse
        opened = asyncio.create_task(router.open_database("/samples/A.i64"))
        await entered.wait()
        await router.close_database(a)
        release.set()
        try:
            with pytest.raises(RoutingError):
                await opened
        finally:
            await router.shutdown()
        assert existing.close_count == 1

    asyncio.run(scenario())
