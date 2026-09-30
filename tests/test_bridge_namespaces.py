"""Exercise actual py_eval/idasync with a minimal IDA scheduling boundary."""

import ast
import importlib
import pathlib
import queue
import sys
import threading
import time
import types

import pytest

from _mcp_spec_support import load_ida_rpc_module


@pytest.fixture
def python_runtime(monkeypatch):
    rpc = load_ida_rpc_module()
    package = rpc.__package__
    for name in ("sync", "api_python", "execution_context"):
        monkeypatch.delitem(sys.modules, package + "." + name, raising=False)
    source = pathlib.Path(rpc.__file__).with_name("api_python.py").read_text()
    imported = {
        alias.name
        for item in ast.parse(source).body
        if isinstance(item, ast.Import)
        for alias in item.names
    }
    for name in imported:
        if name.startswith("ida") or name == "idc":
            monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    idaapi = sys.modules["idaapi"]
    idaapi.get_kernel_version = lambda: "9.4"
    idaapi.MFF_WRITE = 1
    state = {"batch": 0}

    def batch(value):
        old = state["batch"]
        state["batch"] = value
        return old

    sys.modules["idc"].batch = batch
    sys.modules["ida_kernwin"].clr_cancelled = lambda: None
    sys.modules["ida_kernwin"].set_cancelled = lambda: None

    def execute_sync(callback, mode):
        # IDA executes on another thread and swallows escaped exceptions.
        def run():
            try:
                callback()
            except BaseException:
                pass

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join(2)
        assert not thread.is_alive()
        return 1

    idaapi.execute_sync = execute_sync
    utils = types.ModuleType(package + ".utils")
    utils.parse_address = int
    utils.get_function = lambda ea: ea
    monkeypatch.setitem(sys.modules, utils.__name__, utils)
    compat = types.ModuleType(package + ".compat")
    compat.get_inf_structure = lambda: None
    monkeypatch.setitem(sys.modules, compat.__name__, compat)
    monkeypatch.setenv("IDA_MCP_TOOL_TIMEOUT_SEC", "0")
    original_tools = rpc.MCP_SERVER.tools.methods.copy()
    sync = importlib.import_module(package + ".sync")
    api = importlib.import_module(package + ".api_python")
    context = importlib.import_module(package + ".execution_context")
    yield api, sync, context, state
    rpc.MCP_SERVER.tools.methods = original_tools
    for name in ("sync", "api_python", "execution_context"):
        sys.modules.pop(package + "." + name, None)


def test_py_eval_namespaces_survive_thread_handoff_and_reset_own_client_only(
    python_runtime,
):
    api, _, context, _ = python_runtime
    assert api.py_eval("value = 'legacy'", new_locals=True)["stderr"] == ""
    with context.bridge_context("one"):
        assert (
            api.py_eval("value = 'one'\ndef callback():\n return value")["stderr"] == ""
        )
    with context.bridge_context("two"):
        assert api.py_eval("'value' in globals()")["result"] == "False"
        api.py_eval("value = 'two'")
    with context.bridge_context("one"):
        assert api.py_eval("value = 42\ncallback()")["result"] == "42"
        assert api.py_eval("'value' in globals()", new_locals=True)["result"] == "False"
    with context.bridge_context("two"):
        assert api.py_eval("value")["result"] == "two"
    assert api.py_eval("value")["result"] == "legacy"


def test_namespace_release_is_deferred_until_active_call_finishes(python_runtime):
    api, _, context, _ = python_runtime
    with context.bridge_context("one"):
        api.py_eval("value = 42")
        assert context.release_bridge_client("one")
        assert api.py_eval("value")["result"] == "42"
    with context.bridge_context("one"):
        assert api.py_eval("'value' in globals()")["result"] == "False"


def test_context_capacity_rejects_new_client_without_evicting_live_state(
    python_runtime, monkeypatch
):
    api, _, context, _ = python_runtime
    monkeypatch.setattr(context, "MAX_BRIDGE_CLIENTS", 2)
    with context.bridge_context("one"):
        api.py_eval("value = 1")
    with context.bridge_context("two"):
        api.py_eval("value = 2")
    with pytest.raises(RuntimeError, match="capacity"):
        with context.bridge_context("three"):
            pass
    with context.bridge_context("one"):
        assert api.py_eval("value")["result"] == "1"
    context.release_bridge_client("two")
    with context.bridge_context("three"):
        assert api.py_eval("'value' in globals()")["result"] == "False"


@pytest.mark.parametrize("exception", [SystemExit, KeyboardInterrupt])
def test_baseexception_unwinds_scheduler_without_hanging_or_leaking_batch(
    python_runtime, exception
):
    _, sync, _, state = python_runtime

    @sync.idasync
    def fails():
        raise exception("test")

    result = queue.Queue()

    def invoke():
        try:
            fails()
        except BaseException as exc:
            result.put(exc)

    caller = threading.Thread(target=invoke, daemon=True)
    caller.start()
    caller.join(1)
    assert not caller.is_alive(), (
        "execute_sync swallowed BaseException and left the waiter hung"
    )
    assert isinstance(result.get_nowait(), exception)
    assert state["batch"] == 0
    assert sync.call_stack.empty()


def test_py_eval_does_not_convert_cancellation_to_success(python_runtime):
    api, sync, _, _ = python_runtime
    api._persisted_locals["cancel_error"] = sync.CancelledError
    with pytest.raises(sync.CancelledError):
        api.py_eval("raise cancel_error('cancelled')")


def test_precancelled_context_prevents_python_mutation(python_runtime):
    api, sync, context, _ = python_runtime
    event = threading.Event()
    event.set()
    with context.bridge_context("one", event):
        with pytest.raises(sync.CancelledError):
            api.py_eval("changed = True")
    with context.bridge_context("one"):
        assert api.py_eval("'changed' in globals()")["result"] == "False"


def test_keep_batch_deferred_success_and_exception_restore_are_preserved(
    python_runtime,
):
    _, sync, _, state = python_runtime
    seen = []

    @sync.idasync
    @sync.keep_batch
    def deferred():
        seen.append(sync.get_pre_call_batch())
        return 42

    assert deferred() == 42
    assert seen == [0]
    assert state["batch"] == 1
    state["batch"] = 0

    @sync.idasync
    @sync.keep_batch
    def failure():
        raise ValueError("failure")

    with pytest.raises(ValueError):
        failure()
    assert state["batch"] == 0


@pytest.mark.parametrize("fail_on", [1, 2])
def test_batch_setup_or_restore_exception_reaches_waiter(python_runtime, fail_on):
    _, sync, _, _ = python_runtime
    calls = 0

    def broken_batch(value):
        nonlocal calls
        calls += 1
        if calls == fail_on:
            raise RuntimeError("batch failure")
        return 0

    sync.idc.batch = broken_batch
    result = queue.Queue()

    def invoke():
        try:
            result.put(sync.idasync(lambda: 42)())
        except BaseException as exc:
            result.put(exc)

    caller = threading.Thread(target=invoke, daemon=True)
    caller.start()
    caller.join(1)
    assert not caller.is_alive(), "batch setup left the synchronized caller blocked"
    assert isinstance(result.get_nowait(), RuntimeError)
    assert sync.call_stack.empty()


def test_request_cancellation_interrupts_native_wait_before_tool_timeout(
    python_runtime, monkeypatch
):
    _, sync, context, _ = python_runtime
    monkeypatch.setenv("IDA_MCP_TOOL_TIMEOUT_SEC", "0.5")
    monkeypatch.delenv("IDA_IS_INTERACTIVE", raising=False)
    native_wake = threading.Event()
    cancel = threading.Event()
    times = {}

    def native_cancel():
        times["native"] = time.monotonic()
        native_wake.set()

    monkeypatch.setattr(sync.ida_kernwin, "set_cancelled", native_cancel)

    @sync.idasync
    def native_wait():
        native_wake.wait(1)

    def signal_cancel():
        times["request"] = time.monotonic()
        cancel.set()

    timer = threading.Timer(0.05, signal_cancel)
    timer.start()
    try:
        with (
            context.bridge_context("native", cancel),
            pytest.raises(sync.CancelledError),
        ):
            native_wait()
    finally:
        timer.cancel()
        timer.join()
    assert times["native"] - times["request"] < 0.2


def test_native_cancellation_watcher_finishes_before_next_operation(
    python_runtime, monkeypatch
):
    _, sync, context, _ = python_runtime
    monkeypatch.setenv("IDA_MCP_TOOL_TIMEOUT_SEC", "0")
    monkeypatch.delenv("IDA_IS_INTERACTIVE", raising=False)
    native_started = threading.Event()
    native_unblock = threading.Event()
    tool_unblock = threading.Event()
    call_finished = threading.Event()
    cancel = threading.Event()
    flags = []

    def native_cancel():
        native_started.set()
        native_unblock.wait(1)
        flags.append(True)

    monkeypatch.setattr(sync.ida_kernwin, "set_cancelled", native_cancel)
    monkeypatch.setattr(sync.ida_kernwin, "clr_cancelled", lambda: flags.clear())

    @sync.idasync
    def native_wait():
        tool_unblock.wait(1)

    def invoke():
        try:
            with context.bridge_context("native", cancel):
                native_wait()
        except sync.CancelledError:
            pass
        finally:
            call_finished.set()

    caller = threading.Thread(target=invoke)
    caller.start()
    time.sleep(0.03)
    cancel.set()
    try:
        assert native_started.wait(0.3)
        tool_unblock.set()
        assert not call_finished.wait(0.04)
    finally:
        native_unblock.set()
        tool_unblock.set()
        caller.join(2)
    assert call_finished.is_set()
    assert not flags
    assert sync.idasync(lambda: 42)() == 42
    assert not flags


def test_late_gui_native_cancel_callback_cannot_cancel_successor(
    python_runtime, monkeypatch
):
    _, sync, context, _ = python_runtime
    monkeypatch.setenv("IDA_IS_INTERACTIVE", "1")
    monkeypatch.setenv("IDA_MCP_TOOL_TIMEOUT_SEC", "0")
    monkeypatch.setattr(sync.ida_kernwin, "is_idaq", lambda: True, raising=False)
    monkeypatch.setattr(sync.ida_kernwin, "MFF_FAST", 0, raising=False)
    monkeypatch.setattr(sync.ida_kernwin, "MFF_NOWAIT", 4, raising=False)
    scheduled = threading.Event()
    callbacks = []
    flags = []

    def queue_gui(callback, mode):
        assert mode == 4
        callbacks.append(callback)
        scheduled.set()
        return 1

    monkeypatch.setattr(sync.ida_kernwin, "execute_sync", queue_gui, raising=False)
    monkeypatch.setattr(sync.ida_kernwin, "set_cancelled", lambda: flags.append(True))
    cancel = threading.Event()

    @sync.idasync
    def native_wait():
        scheduled.wait(0.5)

    timer = threading.Timer(0.03, cancel.set)
    timer.start()
    try:
        with context.bridge_context("gui", cancel), pytest.raises(sync.CancelledError):
            native_wait()
    finally:
        timer.cancel()
        timer.join()
    assert callbacks, "GUI native cancellation was not scheduled"
    assert not flags, "watcher invoked GUI cancellation synchronously"
    for callback in callbacks:
        callback()
    assert not flags, "late native callback changed a successor's cancellation flag"
    assert sync.idasync(lambda: 42)() == 42
