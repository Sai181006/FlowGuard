"""Open the local dashboard on Windows or macOS, without third-party packages."""

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
URL = "http://127.0.0.1:8765/"


def ready():
    try:
        with urllib.request.urlopen(URL + "api/bootstrap", timeout=0.4) as response:
            data = json.load(response)
        return isinstance(data, dict) and "simulation_defaults" in data
    except (OSError, ValueError, urllib.error.URLError):
        return False


def main():
    if ready():
        webbrowser.open(URL)
        print("FlowGuard is already running at " + URL)
        return 0
    server = subprocess.Popen([sys.executable, "-u", str(ROOT / "demo/server.py")], cwd=ROOT)
    try:
        for _ in range(60):
            if server.poll() is not None:
                return server.returncode or 1
            if ready():
                webbrowser.open(URL)
                print("Keep this terminal open. Press Ctrl+C to stop FlowGuard.", flush=True)
                return server.wait()
            time.sleep(0.1)
        print("Dashboard startup timed out; check whether port 8765 is occupied.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0
    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=3)


if __name__ == "__main__":
    raise SystemExit(main())
