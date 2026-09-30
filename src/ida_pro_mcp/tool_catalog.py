"""Build the GUI tool catalog from shipped signatures without loading IDAPython.

The API modules also contain IDA imports, decorators and database side effects.
Only their typing declarations, literal constants and inert tool signatures are
evaluated here. The regular MCP schema generator remains the single authority
for how these signatures appear to clients.
"""

import __future__

import ast
import importlib.util
import inspect
import sys
from copy import deepcopy
from functools import lru_cache
from pathlib import Path
from threading import Lock
from types import ModuleType
from typing import Callable, TypedDict, get_type_hints, is_typeddict

_API_ROOT = Path(__file__).resolve().parent / "ida_mcp"
_CATALOG_LOCK = Lock()


def _registered_api_modules(root: Path) -> list[str]:
    """Follow the plugin's registration order without executing its initializer."""
    tree = ast.parse((root / "__init__.py").read_text(encoding="utf-8"))
    return list(dict.fromkeys(
        alias.name
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module is None
        for alias in node.names
        if alias.name.startswith("api_")
    ))


def _is_tool(node: ast.FunctionDef) -> bool:
    return any(
        isinstance(decorator, ast.Name) and decorator.id == "tool"
        for decorator in node.decorator_list
    )


def _tool_extension(node: ast.FunctionDef) -> str | None:
    for decorator in node.decorator_list:
        if (
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Name)
            and decorator.func.id == "ext"
        ):
            return ast.literal_eval(decorator.args[0])
    return None


def _is_type_declaration(node: ast.ClassDef, namespace: dict) -> bool:
    return any(
        isinstance(base, ast.Name)
        and (namespace.get(base.id) is TypedDict or is_typeddict(namespace.get(base.id)))
        for base in node.bases
    )


def _is_schema_assignment(node: ast.Assign) -> bool:
    if (
        isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id in {"TypedDict", "TypeVar"}
    ):
        return True
    try:
        ast.literal_eval(node.value)
    except (ValueError, TypeError):
        return False
    return True


def _load_signature_module(
    root: Path, name: str, modules: dict[str, ModuleType]
) -> tuple[ModuleType, list[tuple[str, str | None]]]:
    path = root / f"{name}.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    module = ModuleType(f"_ida_mcp_catalog_{name}")
    module.__file__ = str(path)
    namespace = module.__dict__
    # Keep a separate module identity until all forward references are resolved.
    sys.modules[module.__name__] = module
    modules[name] = module
    tools = []
    compiler_flags = 0

    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module == "__future__":
                if any(alias.name == "annotations" for alias in node.names):
                    compiler_flags |= __future__.annotations.compiler_flag
                continue
            elif node.level == 0 and node.module == "typing":
                pass
            elif node.level == 1 and node.module in modules:
                source = modules[node.module].__dict__
                for alias in node.names:
                    if alias.name in source:
                        namespace[alias.asname or alias.name] = source[alias.name]
                continue
            else:
                continue
        elif isinstance(node, ast.ClassDef):
            if not _is_type_declaration(node, namespace):
                continue
            node.decorator_list = []
            node.body = [
                item for item in node.body
                if isinstance(item, ast.AnnAssign)
                or (isinstance(item, ast.Expr) and isinstance(item.value, ast.Constant))
            ] or [ast.Pass()]
            for item in node.body:
                if isinstance(item, ast.AnnAssign):
                    item.value = None
        elif isinstance(node, ast.Assign):
            if not _is_schema_assignment(node):
                continue
        elif isinstance(node, ast.FunctionDef) and _is_tool(node):
            tools.append((node.name, _tool_extension(node)))
            # Preserve the raw docstring: the schema generator strips its ends
            # but does not dedent its internal lines.
            docstring = ast.get_docstring(node, clean=False)
            node.body = [ast.Pass()]
            if docstring is not None:
                node.body.insert(0, ast.Expr(value=ast.Constant(value=docstring)))
            node.decorator_list = []
        else:
            continue

        declarations = ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[]))
        exec(
            compile(declarations, str(path), "exec", flags=compiler_flags, dont_inherit=True),
            namespace,
        )

    return module, tools


@lru_cache(maxsize=1)
def _load_catalog(schema_generator: Callable) -> tuple[tuple[dict, str | None], ...]:
    modules: dict[str, ModuleType] = {}
    catalog = []
    try:
        _load_signature_module(_API_ROOT, "utils", modules)
        for name in _registered_api_modules(_API_ROOT):
            module, tools = _load_signature_module(_API_ROOT, name, modules)
            for tool_name, extension in tools:
                catalog.append((schema_generator(tool_name, module.__dict__[tool_name]), extension))
    finally:
        for module in modules.values():
            sys.modules.pop(module.__name__, None)
    return tuple(catalog)


def get_ida_tools(schema_generator: Callable, enabled_extensions: set[str]) -> list[dict]:
    """Return independent descriptors for the installed tools and extensions.

    Database-specific tool settings are enforced by IDA when a tool is called;
    they cannot determine discovery while that database is closed.
    """
    # lru_cache alone permits duplicate initial builds in parallel HTTP requests.
    # Serialize construction while temporary type namespaces are in sys.modules.
    with _CATALOG_LOCK:
        catalog = _load_catalog(schema_generator)
    return [
        deepcopy(schema)
        for schema, extension in catalog
        if extension is None or extension in enabled_extensions
    ]


@lru_cache(maxsize=1)
def fork_schema_generator() -> Callable:
    """Load the fork schema authority under an isolated, IDA-free package name.

    The official frontend imports a newer top-level ``zeromcp``. Importing the
    legacy proxy to obtain its schema generator would poison that module name.
    """
    name = "_ida_pro_mcp_catalog_zeromcp"
    spec = importlib.util.spec_from_file_location(
        name, _API_ROOT / "zeromcp" / "__init__.py",
        submodule_search_locations=[str(_API_ROOT / "zeromcp")],
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module.McpServer("ida-pro-mcp-catalog")._generate_tool_schema


def get_ida_tool_signatures(enabled_extensions: set[str]) -> dict[str, inspect.Signature]:
    """Resolve real inert annotations before their temporary namespaces vanish."""
    modules: dict[str, ModuleType] = {}
    signatures = {}
    with _CATALOG_LOCK:
        try:
            _load_signature_module(_API_ROOT, "utils", modules)
            for name in _registered_api_modules(_API_ROOT):
                module, tools = _load_signature_module(_API_ROOT, name, modules)
                for tool_name, extension in tools:
                    if extension is not None and extension not in enabled_extensions:
                        continue
                    function = module.__dict__[tool_name]
                    hints = get_type_hints(function, include_extras=True)
                    signature = inspect.signature(function)
                    signatures[tool_name] = signature.replace(
                        parameters=[parameter.replace(annotation=hints.get(key, parameter.annotation))
                                    for key, parameter in signature.parameters.items()],
                        return_annotation=hints.get("return", signature.return_annotation),
                    )
        finally:
            for module in modules.values():
                sys.modules.pop(module.__name__, None)
    return signatures


def get_ida_resources() -> list[dict]:
    """Read resource metadata without importing the IDA implementation."""
    resources = []
    for name in _registered_api_modules(_API_ROOT):
        tree = ast.parse((_API_ROOT / f"{name}.py").read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            for decorator in node.decorator_list:
                if (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name)
                        and decorator.func.id == "resource"):
                    resources.append({"uri": ast.literal_eval(decorator.args[0]),
                                      "name": node.name,
                                      "description": ast.get_docstring(node) or ""})
    return resources
