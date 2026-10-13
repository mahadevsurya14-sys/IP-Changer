"""PyInstaller build script for IP Changer on Windows 11.

Packages the PySide6 desktop application into a standalone distribution directory.

Requirements:
    pip install pyinstaller PySide6 requests keyring

Usage:
    python scripts/build_windows.py

Administrative Requirements:
    Running the built executable in standalone mode does not strictly require admin rights
    for proxy operation. However, administrative elevation ('Run as Administrator') is
    required if using the Firewall Kill Switch or System-wide VPN adapters (OpenVPN/WireGuard).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


def build() -> None:
    """Execute PyInstaller build pipeline."""
    project_root = Path(__file__).resolve().parent.parent
    dist_dir = project_root / "dist"
    build_dir = project_root / "build"
    main_script = project_root / "src" / "main.py"
    icon_path = project_root / "resources" / "icon.ico"

    print("=" * 60)
    print(" IP Changer - Windows PyInstaller Packaging Script")
    print(f" Author: Mahaduuu")
    print(f" Project root: {project_root}")
    print("=" * 60)

    if not main_script.exists():
        # Fallback to main.py at root if src/main.py does not exist
        if (project_root / "main.py").exists():
            main_script = project_root / "main.py"
        else:
            print(f"Error: Entry point script not found at {main_script}")
            sys.exit(1)

    # PyInstaller arguments
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onedir",  # Single-directory build for faster launch and easier plugin/config access
        "--windowed",  # Suppress console window on launch
        "--name=IPChanger",
        f"--distpath={dist_dir}",
        f"--workpath={build_dir}",
        f"--paths={project_root}",
        # Add src and config data
        f"--add-data={project_root / 'config'};config",
    ]

    # Include resources if present
    resources_dir = project_root / "resources"
    if resources_dir.exists():
        cmd.append(f"--add-data={resources_dir};resources")

    if icon_path.exists():
        cmd.append(f"--icon={icon_path}")

    # Hidden imports for dynamic loader resolution
    hidden_imports = [
        "PySide6.QtCore",
        "PySide6.QtGui",
        "PySide6.QtWidgets",
        "requests",
        "keyring",
        "keyring.backends.Windows",
        "ipaddress",
        "urllib.parse",
    ]
    for imp in hidden_imports:
        cmd.extend(["--hidden-import", imp])

    cmd.append(str(main_script))

    print("\nRunning command:")
    print(" ".join(cmd))
    print("\nCompiling application...")

    try:
        subprocess.run(cmd, check=True)
        print("\n" + "=" * 60)
        print(" Build succeeded!")
        print(f" Output directory: {dist_dir / 'IPChanger'}")
        print("=" * 60)
        print("\nIMPORTANT NOTE:")
        print("For full functionality (Firewall Kill Switch & System VPN Routing),")
        print("right-click IPChanger.exe and select 'Run as Administrator'.")
    except subprocess.CalledProcessError as exc:
        print(f"\nBuild failed with exit code {exc.returncode}")
        sys.exit(exc.returncode)


if __name__ == "__main__":
    build()
