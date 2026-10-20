"""Build a self-contained source/demo ZIP, with per-file hashes and no venv."""

import hashlib
import json
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FOLDERS = ("config", "controller", "dashboard", "demo", "experiments", "scripts",
           "tests", "topology", "traffic", "results", "audit")
ARTIFACTS = ("flowguard-dashboard.png", "flowguard-presentation.png", "offline-asset-check.json",
             "terminal-preflight.json", "terminal-python312.txt", "terminal-verified")


def sources():
    files = {p for p in ROOT.iterdir() if p.is_file() and
             (p.suffix in {".md", ".cmd", ".command", ".in", ".txt"} or p.name in {"LICENSE", ".gitignore", ".gitattributes"})}
    for name in FOLDERS:
        files.update(p for p in (ROOT / name).rglob("*") if p.is_file() and
                     "__pycache__" not in p.parts and not p.is_symlink())
    for name in ARTIFACTS:
        item = ROOT / "artifacts" / name
        if item.is_file():
            files.add(item)
        elif item.is_dir():
            files.update(p for p in item.rglob("*") if p.is_file())
    return sorted(files)


def main():
    destination = ROOT / "artifacts/FlowGuard-Windows-Demo.zip"
    destination.parent.mkdir(exist_ok=True)
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
                                         stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        commit = "not available in portable copy"
    manifest = {"created_utc": datetime.now(timezone.utc).isoformat(),
                "upstream_base_commit": commit,
                "includes_unpublished_local_changes": True, "python_minimum": "3.12",
                "native_runtime_verified_on": "macOS; Windows rehearsal required", "files": {}}
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for source in sources():
            relative = source.relative_to(ROOT).as_posix()
            payload = source.read_bytes()
            if source.suffix == ".cmd":
                payload = payload.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
            archive.writestr("FlowGuard/" + relative, payload)
            manifest["files"][relative] = {"sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}
        archive.writestr("FlowGuard/PACKAGE_MANIFEST.json", json.dumps(manifest, indent=2) + "\n")
    with zipfile.ZipFile(destination) as archive:
        assert archive.testzip() is None
        for relative, expected in manifest["files"].items():
            assert hashlib.sha256(archive.read("FlowGuard/" + relative)).hexdigest() == expected["sha256"]
        assert not any("/.venv/" in name or "/.git/" in name or "__pycache__" in name for name in archive.namelist())
    report = {"file": destination.name, "bytes": destination.stat().st_size,
              "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
              "files": len(manifest["files"]), "zip_integrity": "passed", "file_hashes": "passed"}
    (ROOT / "artifacts/package-check.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
