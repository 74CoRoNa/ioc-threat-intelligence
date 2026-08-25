"""Package the analyzer as a single self-contained Windows executable.

Run:  .venv\\Scripts\\python.exe build_exe.py

Produces dist/IOC-Threat-Intelligence.exe, which embeds Python, every
dependency, and the web interface. The target machine needs nothing installed.
"""

import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "backend"
NAME = "IOC-Threat-Intelligence"

# uvicorn and pydantic-settings resolve parts of themselves at runtime, so the
# analyser cannot see every module by following imports alone.
HIDDEN_IMPORTS = [
    "uvicorn.logging",
    "uvicorn.loops.auto",
    "uvicorn.loops.asyncio",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan.on",
    "uvicorn.lifespan.off",
    "app.main",
    "dns.asyncresolver",
    "dns.resolver",
    "dns.rdtypes",
    "dns.rdtypes.ANY",
    "dns.rdtypes.IN",
    "sqlalchemy.dialects.sqlite",
    "pydantic_settings",
]


def main() -> int:
    for stale in (ROOT / "build", ROOT / "dist", ROOT / f"{NAME}.spec"):
        if stale.is_dir():
            shutil.rmtree(stale)
        elif stale.exists():
            stale.unlink()

    separator = ";" if sys.platform == "win32" else ":"
    command = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", NAME,
        "--distpath", str(ROOT / "dist"),
        "--workpath", str(ROOT / "build"),
        "--specpath", str(ROOT),
        "--paths", str(BACKEND),
        # The interface and the settings template travel inside the executable.
        "--add-data", f"{ROOT / 'frontend'}{separator}frontend",
        "--add-data", f"{ROOT / '.env.example'}{separator}.",
        "--console",
        "--noconfirm",
        "--clean",
    ]
    for module in HIDDEN_IMPORTS:
        command += ["--hidden-import", module]
    command.append(str(BACKEND / "launcher.py"))

    print("Building. This takes a minute or two.\n")
    result = subprocess.run(command, cwd=ROOT)
    if result.returncode != 0:
        print("\nBuild failed.")
        return result.returncode

    produced = ROOT / "dist" / f"{NAME}.exe"
    size_mb = produced.stat().st_size / (1024 * 1024)
    print(f"\nBuilt {produced}  ({size_mb:.1f} MB)")
    print("Ship this .exe together with a .env holding the API keys.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
