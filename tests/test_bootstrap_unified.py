import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from scripts import bootstrap_unified as bootstrap


def test_receipt_records_frontend_wheel_versions_and_hashes(tmp_path):
    import json

    frontend = tmp_path / "fastmcp-4.1.0-py3-none-any.whl"
    sdk = tmp_path / "mcp-2.3.0-py3-none-any.whl"
    frontend.write_bytes(b"frontend fixture wheel")
    sdk.write_bytes(b"sdk fixture wheel")
    receipt = bootstrap.write_receipt(
        tmp_path, "python", [], repo_root=tmp_path, installed=False
    )
    data = json.loads(receipt.read_text())
    entries = {row["distribution"]: row for row in data["frontend_wheels"]}
    assert entries["fastmcp"]["version"] == "4.1.0"
    assert entries["mcp"]["sha256"] == hashlib.sha256(b"sdk fixture wheel").hexdigest()


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-c", "core.longpaths=true", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _source_repo(tmp_path: Path, *, version: str = "0.0.0") -> tuple[Path, str]:
    repo = tmp_path / "source"
    repo.mkdir()
    subprocess.run(
        ["git", "-c", "core.longpaths=true", "init", "-q", str(repo)], check=True
    )
    _git(repo, "config", "user.name", "Bootstrap Test")
    _git(repo, "config", "user.email", "bootstrap@example.invalid")
    (repo / "pyproject.toml").write_text(
        "[project]\n"
        'name = "zeromcp"\n'
        f'version = "{version}"\n'
        "\n[build-system]\n"
        'requires = ["setuptools"]\n'
        'build-backend = "setuptools.build_meta"\n',
        encoding="utf-8",
    )
    (repo / "README.md").write_text("fixture\n", encoding="utf-8")
    _git(repo, "add", "pyproject.toml", "README.md")
    _git(repo, "commit", "-q", "-m", "fixture")
    return repo, _git(repo, "rev-parse", "HEAD")


def test_prepare_source_clones_exact_ref_and_patches_zeromcp_metadata(tmp_path):
    source, revision = _source_repo(tmp_path)
    spec = bootstrap.SourceSpec(
        key="zeromcp",
        distribution="zeromcp",
        version="1.10.3",
        url=str(source),
        ref=revision,
        metadata_version_from="0.0.0",
    )

    checkout = bootstrap.prepare_source(spec, tmp_path / "checkouts")

    assert _git(checkout, "rev-parse", "HEAD") == revision
    metadata = (checkout / "pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "1.10.3"' in metadata
    assert 'version = "0.0.0"' not in metadata


def test_verify_source_revision_rejects_mismatched_checkout(tmp_path):
    source, revision = _source_repo(tmp_path)

    with pytest.raises(bootstrap.SourceRevisionError, match="expected"):
        bootstrap.verify_source_revision(source, "0" * 40)

    assert revision != "0" * 40


def test_patch_project_version_requires_one_exact_project_version(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    pyproject = project / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "zeromcp"\nversion = "1.2.3"\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exactly one"):
        bootstrap.patch_project_version(project, "0.0.0", "1.10.3")

    assert 'version = "1.2.3"' in pyproject.read_text(encoding="utf-8")


def test_build_wheel_command_uses_argument_array_and_no_deps(tmp_path):
    command = bootstrap.build_wheel_command(
        "C:/Python/python.exe", tmp_path / "source tree", tmp_path / "wheel house"
    )

    assert command == [
        "C:/Python/python.exe",
        "-m",
        "pip",
        "wheel",
        "--no-deps",
        "--wheel-dir",
        str(tmp_path / "wheel house"),
        str(tmp_path / "source tree"),
    ]


def test_install_command_accepts_exact_wheels_and_keeps_configured_index(tmp_path):
    repo = tmp_path / "current repo"
    repo.mkdir()
    wheels = []
    for filename in (
        "zeromcp-1.10.3-py3-none-any.whl",
        "ida_nexus-0.13.0-py3-none-any.whl",
        "ida_mcp-20260929.0.1-py3-none-any.whl",
    ):
        wheel = tmp_path / filename
        wheel.write_bytes(b"wheel")
        wheels.append(wheel)

    command = bootstrap.build_install_command("python.exe", wheels, repo)

    assert command == [
        "python.exe",
        "-m",
        "pip",
        "install",
        *(str(wheel) for wheel in wheels),
        str(repo),
    ]
    assert "--no-index" not in command
    assert "--index-url" not in command


def test_install_command_rejects_wrong_wheel_version(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    wheels = [
        tmp_path / "zeromcp-1.10.2-py3-none-any.whl",
        tmp_path / "ida_nexus-0.13.0-py3-none-any.whl",
        tmp_path / "ida_mcp-20260929.0.1-py3-none-any.whl",
    ]
    for wheel in wheels:
        wheel.write_bytes(b"wheel")

    with pytest.raises(ValueError, match="zeromcp==1.10.3"):
        bootstrap.build_install_command("python.exe", wheels, repo)


def test_write_receipt_records_source_refs_and_wheel_hashes(tmp_path):
    wheel = tmp_path / "zeromcp-1.10.3-py3-none-any.whl"
    wheel.write_bytes(b"wheel payload")
    spec = bootstrap.SourceSpec(
        key="zeromcp",
        distribution="zeromcp",
        version="1.10.3",
        url="https://example.invalid/zeromcp.git",
        ref="c7cec74a1b5a5f0d56a9f1b5550e70de738dee62",
        metadata_version_from="0.0.0",
    )

    receipt = bootstrap.write_receipt(
        tmp_path,
        "python.exe",
        [(spec, wheel)],
        repo_root=tmp_path / "repo",
        installed=False,
    )
    payload = json.loads(receipt.read_text(encoding="utf-8"))

    assert payload["sources"][0]["ref"] == spec.ref
    assert payload["sources"][0]["wheel"] == wheel.name
    assert (
        payload["sources"][0]["sha256"] == hashlib.sha256(b"wheel payload").hexdigest()
    )
    assert payload["installed"] is False
