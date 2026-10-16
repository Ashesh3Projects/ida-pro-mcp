#!/usr/bin/env python3
"""Build the reviewed unified-mode dependencies from pinned source commits."""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence

RECEIPT_NAME = "ida-pro-mcp-bootstrap-receipt.json"
FRONTEND_REQUIREMENTS = (
    "fastmcp==4.1.0",
    "fastmcp-slim==4.1.0",
    "mcp==2.3.0",
    "mcp-types==2.3.0",
)


@dataclasses.dataclass(frozen=True)
class SourceSpec:
    key: str
    distribution: str
    version: str
    url: str
    ref: str
    metadata_version_from: str | None = None


SOURCE_SPECS = (
    SourceSpec(
        key="zeromcp",
        distribution="zeromcp",
        version="1.10.3",
        url="https://github.com/mrexodia/zeromcp.git",
        ref="c7cec74a1b5a5f0d56a9f1b5550e70de738dee62",
        metadata_version_from="0.0.0",
    ),
    SourceSpec(
        key="ida-nexus",
        distribution="ida-nexus",
        version="0.13.0",
        url="https://github.com/HexRaysSA/ida-nexus.git",
        ref="c470ed0a2c1671ce8ee5217d0131f4bcd79d58df",
    ),
    SourceSpec(
        key="ida-mcp",
        distribution="ida-mcp",
        version="20260929.0.1",
        url="https://github.com/HexRaysSA/ida-mcp.git",
        ref="cb2735f4ef8fbb31c666c411f4c8819ff42e25cb",
    ),
)


class SourceRevisionError(RuntimeError):
    pass


def _run(
    command: Sequence[str], *, capture_output: bool = False
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        check=True,
        capture_output=capture_output,
        text=True,
    )


def verify_source_revision(checkout: Path, expected_ref: str) -> str:
    if not re.fullmatch(r"[0-9a-fA-F]{40}", expected_ref):
        raise ValueError(
            f"Pinned source ref must be a full commit ID: {expected_ref!r}"
        )
    actual = _run(
        [
            "git",
            "-c",
            "core.longpaths=true",
            "-C",
            str(checkout),
            "rev-parse",
            "HEAD",
        ],
        capture_output=True,
    ).stdout.strip()
    if actual.lower() != expected_ref.lower():
        raise SourceRevisionError(
            f"Source revision mismatch for {checkout}: expected {expected_ref}, got {actual}"
        )
    return actual


def patch_project_version(project: Path, old_version: str, new_version: str) -> None:
    pyproject = project / "pyproject.toml"
    original = pyproject.read_text(encoding="utf-8")
    old_line = f'version = "{old_version}"'
    new_line = f'version = "{new_version}"'
    matches = re.findall(rf"(?m)^{re.escape(old_line)}\s*$", original)
    if len(matches) != 1:
        raise ValueError(
            f"Expected exactly one {old_line!r} line in {pyproject}, found {len(matches)}"
        )
    updated = re.sub(
        rf"(?m)^{re.escape(old_line)}\s*$",
        new_line,
        original,
        count=1,
    )
    pyproject.write_text(updated, encoding="utf-8")


def prepare_source(spec: SourceSpec, checkouts_root: Path) -> Path:
    checkouts_root.mkdir(parents=True, exist_ok=True)
    checkout = checkouts_root / spec.key
    if checkout.exists():
        raise FileExistsError(f"Refusing to replace existing checkout: {checkout}")
    _run(
        [
            "git",
            "-c",
            "core.longpaths=true",
            "clone",
            "--no-checkout",
            spec.url,
            str(checkout),
        ]
    )
    _run(
        [
            "git",
            "-c",
            "core.longpaths=true",
            "-C",
            str(checkout),
            "checkout",
            "--detach",
            spec.ref,
        ]
    )
    verify_source_revision(checkout, spec.ref)
    if spec.metadata_version_from is not None:
        patch_project_version(checkout, spec.metadata_version_from, spec.version)
    return checkout


def build_wheel_command(python: str, source: Path, wheel_dir: Path) -> list[str]:
    return [
        python,
        "-m",
        "pip",
        "wheel",
        "--no-deps",
        "--wheel-dir",
        str(wheel_dir),
        str(source),
    ]


def _canonical_distribution(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _wheel_identity(wheel: Path) -> tuple[str, str]:
    if wheel.suffix != ".whl":
        raise ValueError(f"Not a wheel: {wheel}")
    fields = wheel.name[:-4].split("-")
    if len(fields) < 5:
        raise ValueError(f"Invalid wheel filename: {wheel.name}")
    return _canonical_distribution(fields[0]), fields[1]


def _expected_versions() -> dict[str, str]:
    return {
        _canonical_distribution(spec.distribution): spec.version
        for spec in SOURCE_SPECS
    }


def validate_exact_wheels(wheels: Sequence[Path]) -> dict[str, Path]:
    expected = _expected_versions()
    selected: dict[str, Path] = {}
    for wheel in wheels:
        distribution, version = _wheel_identity(Path(wheel))
        if distribution not in expected:
            continue
        wanted = expected[distribution]
        if version != wanted:
            raise ValueError(
                f"Expected {distribution}=={wanted}, got {distribution}=={version}"
            )
        if distribution in selected:
            raise ValueError(f"Multiple wheels found for {distribution}=={wanted}")
        selected[distribution] = Path(wheel)
    missing = [
        f"{name}=={version}"
        for name, version in expected.items()
        if name not in selected
    ]
    if missing:
        raise ValueError(f"Missing exact dependency wheels: {', '.join(missing)}")
    return selected


def build_install_command(
    python: str, wheels: Sequence[Path], repo_root: Path
) -> list[str]:
    validate_exact_wheels(wheels)
    return [
        python,
        "-m",
        "pip",
        "install",
        *(str(Path(wheel)) for wheel in wheels),
        str(repo_root),
    ]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_receipt(
    wheel_dir: Path,
    python: str,
    built: Sequence[tuple[SourceSpec, Path]],
    *,
    repo_root: Path,
    installed: bool,
) -> Path:
    payload = {
        "schema_version": 1,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "python": python,
        "repository": str(repo_root.resolve()),
        "installed": installed,
        "frontend_requirements": list(FRONTEND_REQUIREMENTS),
        "frontend_wheels": [
            {
                "distribution": _wheel_identity(wheel)[0],
                "version": _wheel_identity(wheel)[1],
                "wheel": wheel.name,
                "sha256": _sha256(wheel),
            }
            for wheel in sorted(wheel_dir.glob("*.whl"))
            if _wheel_identity(wheel)[0]
            in {"fastmcp", "fastmcp-slim", "mcp", "mcp-types"}
        ],
        "sources": [
            {
                "distribution": spec.distribution,
                "version": spec.version,
                "url": spec.url,
                "ref": spec.ref,
                "metadata_version_from": spec.metadata_version_from,
                "wheel": wheel.name,
                "sha256": _sha256(wheel),
            }
            for spec, wheel in built
        ],
    }
    wheel_dir.mkdir(parents=True, exist_ok=True)
    receipt = wheel_dir / RECEIPT_NAME
    fd, temporary_name = tempfile.mkstemp(
        dir=wheel_dir, prefix=f".{RECEIPT_NAME}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary_name, receipt)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise
    return receipt


def _copy_preserving_existing(source: Path, destination_dir: Path) -> Path:
    destination = destination_dir / source.name
    if destination.exists():
        if _sha256(destination) != _sha256(source):
            raise FileExistsError(
                f"Refusing to overwrite different existing wheel: {destination}"
            )
        return destination
    shutil.copy2(source, destination)
    return destination


def build_dependencies(python: str, wheel_dir: Path) -> list[tuple[SourceSpec, Path]]:
    wheel_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ida-pro-mcp-bootstrap-") as temporary:
        work = Path(temporary)
        build_output = work / "wheels"
        build_output.mkdir()
        built: list[tuple[SourceSpec, Path]] = []
        for spec in SOURCE_SPECS:
            checkout = prepare_source(spec, work / "sources")
            before = set(build_output.glob("*.whl"))
            _run(build_wheel_command(python, checkout, build_output))
            produced = set(build_output.glob("*.whl")) - before
            matches = [
                wheel
                for wheel in produced
                if _wheel_identity(wheel)
                == (_canonical_distribution(spec.distribution), spec.version)
            ]
            if len(matches) != 1:
                names = ", ".join(sorted(path.name for path in produced)) or "none"
                raise RuntimeError(
                    f"Expected one {spec.distribution}=={spec.version} wheel; produced: {names}"
                )
            built.append((spec, _copy_preserving_existing(matches[0], wheel_dir)))
        validate_exact_wheels([wheel for _, wheel in built])
        return built


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build pinned unified IDA MCP dependencies into a wheelhouse."
    )
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument(
        "--install",
        action="store_true",
        help="Install the exact built wheels and this repository with normal pip index settings.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    wheel_dir = args.wheel_dir.resolve()
    built = build_dependencies(args.python, wheel_dir)
    _run(
        [
            args.python,
            "-m",
            "pip",
            "download",
            "--only-binary=:all:",
            "--no-deps",
            "--dest",
            str(wheel_dir),
            *FRONTEND_REQUIREMENTS,
        ]
    )
    if args.install:
        _run(
            build_install_command(args.python, [wheel for _, wheel in built], repo_root)
        )
    receipt = write_receipt(
        wheel_dir,
        args.python,
        built,
        repo_root=repo_root,
        installed=args.install,
    )
    print(f"Wheels: {wheel_dir}")
    print(f"Receipt: {receipt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
