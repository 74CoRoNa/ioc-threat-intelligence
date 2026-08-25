"""Desktop entry point for the packaged IOC Threat Intelligence Analyzer.

Serves the application on a free local port, opens the interface in the
default browser, and keeps running until the console window is closed.
"""

import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path

import uvicorn

from app.core.paths import BUNDLE_DIR, DATA_ROOT


HOST = "127.0.0.1"
PREFERRED_PORT = 8000


def choose_port() -> int:
    """Return the preferred port, or any free port if it is already taken."""

    for candidate in (PREFERRED_PORT, 0):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind((HOST, candidate))
            except OSError:
                continue
            return probe.getsockname()[1]
    return PREFERRED_PORT


def ensure_configuration() -> None:
    """Create a .env beside the executable so keys can be edited after packaging."""

    target = DATA_ROOT / ".env"
    if target.exists():
        return
    example = BUNDLE_DIR / ".env.example"
    if example.exists():
        target.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
        print(f"  Created {target}. Add provider API keys there, then restart.", flush=True)


def open_when_ready(url: str) -> None:
    """Open the browser once the server answers, without blocking startup."""

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.3)
            if probe.connect_ex((HOST, PORT)) == 0:
                webbrowser.open(url)
                return
        time.sleep(0.2)


def main() -> int:
    ensure_configuration()
    url = f"http://{HOST}:{PORT}"

    # Flush explicitly: a frozen console can otherwise buffer this away.
    print("", flush=True)
    print("  IOC Threat Intelligence", flush=True)
    print(f"  Running at {url}", flush=True)
    print("  Close this window to stop.", flush=True)
    print("", flush=True)

    threading.Thread(target=open_when_ready, args=(url,), daemon=True).start()

    from app.main import app

    try:
        uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
    except KeyboardInterrupt:
        pass
    return 0


PORT = choose_port()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:  # pragma: no cover - last-resort console message
        print()
        print(f"  The application could not start: {error}")
        print()
        input("  Press Enter to close ")
        sys.exit(1)
