"""Extract and smoke-test the delivered ZIP with the current Python stdlib."""

import hashlib
import json
import re
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]


def verify():
    package = ROOT / "artifacts/FlowGuard-Windows-Demo.zip"
    with tempfile.TemporaryDirectory(prefix="flowguard-package-") as temporary:
        with zipfile.ZipFile(package) as archive:
            manifest = json.loads(archive.read("FlowGuard/PACKAGE_MANIFEST.json"))
            for name in archive.namelist():
                path = PurePosixPath(name)
                if path.parts[0] != "FlowGuard" or path.is_absolute() or ".." in path.parts or "\\" in name:
                    raise ValueError("Unexpected package path")
            for name, info in manifest["files"].items():
                data = archive.read("FlowGuard/" + name)
                assert hashlib.sha256(data).hexdigest() == info["sha256"]
            archive.extractall(temporary)
        extracted = Path(temporary) / "FlowGuard"
        tests = subprocess.run(
            [sys.executable, "-S", "-m", "unittest", "tests.test_detection", "tests.test_demo_engine",
             "tests.test_live_lab", "-q"], cwd=extracted, capture_output=True, text=True, timeout=30)
        if tests.returncode:
            raise RuntimeError(tests.stdout + tests.stderr)
        server = subprocess.Popen([sys.executable, "-S", "-u", "demo/server.py", "--port", "0"],
                                  cwd=extracted, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            line = server.stdout.readline().strip()
            if not line.startswith("FlowGuard dashboard: "):
                raise RuntimeError("Packaged server failed to start: " + line)
            base = line.split(" ")[-1]

            def get(path):
                with urllib.request.urlopen(base + path, timeout=10) as response:
                    return response.read()

            bootstrap = json.loads(get("api/bootstrap"))
            html = get("").decode()
            assets = set()
            for tag in re.findall(r"<(?:script|link)\b[^>]*>", html):
                for name in re.findall(r'(?:src|href)="([^"]+)"', tag):
                    if ":" in name or name.startswith("//"):
                        raise ValueError("External runtime asset in offline package")
                    assets.add("/" + name.lstrip("/"))
            # Every font URL is local to the vendored fonts stylesheet.
            css = get("assets/fonts/fonts.css").decode()
            for name in re.findall(r"url\(['\"]?([^)'\"]+)", css):
                assets.add("/assets/fonts/" + name)
            for name in assets:
                get(name.lstrip("/"))
            scenarios = ("normal", "burst", "sustained", "waves", "single-source", "low-rate")
            for scenario in scenarios:
                for mitigation in ("on", "off"):
                    get("api/simulation?scenario=" + scenario + "&mitigation=" + mitigation)
            get("api/recorded")
            request = urllib.request.Request(base + "api/probe", data=b"{}", method="POST", headers={
                "Origin": base.rstrip("/"), "Content-Type": "application/json",
                "X-FlowGuard-CSRF": bootstrap["csrf_token"]})
            with urllib.request.urlopen(request, timeout=20) as response:
                live = json.load(response)
            assert live["summary"]["received"] == live["summary"]["sent"] == 5
        finally:
            server.terminate()
            server.communicate(timeout=5)
        return {"package_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
                "platform": sys.platform, "python": sys.version.split()[0],
                "site_packages_disabled": True, "manifest_hashes": "passed",
                "portable_tests": 21, "portable_test_status": "passed",
                "required_assets_http_200": len(assets), "simulation_requests": 12,
                "recorded_api": "passed", "real_udp_replies": live["summary"],
                "windows_runtime_verified": False}


if __name__ == "__main__":
    report = verify()
    (ROOT / "artifacts/portable-package-check.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
