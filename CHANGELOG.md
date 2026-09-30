# Changelog

## 3.0.1

- Publish the unified MCP integration on main with matching package, GUI plugin, and client manifest versions.

## 3.0.0

- Merge community upstream through c133c385, preserving the fork's history and custom behavior.
- Add paginated decompilation, corrected immediate searches/call graph edges, explicit-zero pagination, union-string coercion, Windows wildcard discovery, IPv6 URL and blank configuration fixes.
- Combine all typed analysis tools and optional debugger tools with the official MCP's database lifecycle, Python executor, installed API reference, tracing, dashboard and support archives.
- Authenticate the local typed bridge, isolate Python namespaces by client, forward cancellation, wait for backend drain before releasing leases, and retain original-instance output retrieval.
- Preserve original MCP response schemas and resources, offline discovery, callback globals, profiles, legacy GUI/headless routes, and 120-second typed-tool timeouts.
- Use canonical plugin imports to coexist with the official ida_mcp package.
- Add a single CLI, unified client manifests, reproducible pinned-source dependency bootstrap and regression/fixture acceptance tests.

The unified runtime requires IDA 9.4+. Profiles filter typed tools; they do not constrain arbitrary Python. Separate HTTP sessions in one server share its DatabaseManager. Timed idle release is disabled for unified typed execution. Existing legacy entry points remain available.
