"""Installation identity independent of symlink/copy layout and IDAPython."""

import hashlib
from pathlib import Path


def package_fingerprint(root: Path | None = None) -> str:
    """Hash relative paths and source bytes for shipped executable Python files."""
    root = root or Path(__file__).resolve().parent
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*.py"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root)
        if "tests" in relative.parts or "__pycache__" in relative.parts:
            continue
        name, data = relative.as_posix().encode("utf-8"), path.read_bytes()
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


# Capture once: an IDA runtime cannot claim newer disk source after an upgrade.
PACKAGE_FINGERPRINT = package_fingerprint()
