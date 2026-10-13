#!/usr/bin/env bash
# ==============================================================================
# IP Changer - Linux Installation & Setup Script (Kali Linux / Debian)
# Author: Mahaduuu
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "============================================================"
echo " 🌐 IP Changer - Installation Script for Linux"
echo " Author: Mahaduuu"
echo " Target: Kali Linux / Debian"
echo " Directory: ${PROJECT_ROOT}"
echo "============================================================"

# 1. Check Python version (requires >= 3.10)
echo "[1/5] Checking Python 3 version..."
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed. Please install Python 3.10+ and rerun."
    exit 1
fi

PYTHON_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')

echo "Found Python version: ${PYTHON_VER}"
if [ "$MAJOR" -lt 3 ] || ([ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 10 ]); then
    echo "Error: Python 3.10 or higher is required. Found Python ${PYTHON_VER}."
    exit 1
fi

# 2. Check system network packages
echo "[2/5] Checking recommended system network packages..."
MISSING_PKGS=()
for pkg in openvpn wireguard iptables; do
    if ! command -v "$pkg" &> /dev/null; then
        MISSING_PKGS+=("$pkg")
    fi
done

if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
    echo "Notice: The following optional system packages for VPN / Kill Switch are missing:"
    echo "  ${MISSING_PKGS[*]}"
    echo "To install them on Kali/Debian, execute:"
    echo "  sudo apt update && sudo apt install -y openvpn wireguard-tools iptables"
else
    echo "All recommended network utilities (openvpn, wireguard, iptables) are installed."
fi

# 3. Create virtual environment
echo "[3/5] Setting up Python virtual environment..."
VENV_DIR="${PROJECT_ROOT}/venv"
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    echo "Virtual environment created at: ${VENV_DIR}"
else
    echo "Virtual environment already exists at: ${VENV_DIR}"
fi

# 4. Install Python dependencies
echo "[4/5] Installing Python dependencies..."
"${VENV_DIR}/bin/pip" install --upgrade pip
"${VENV_DIR}/bin/pip" install -r "${PROJECT_ROOT}/requirements.txt"

# 5. Create Desktop Launcher
echo "[5/5] Generating Desktop entry shortcut..."
DESKTOP_DIR="${HOME}/.local/share/applications"
mkdir -p "$DESKTOP_DIR"
DESKTOP_FILE="${DESKTOP_DIR}/ip-changer.desktop"

cat <<EOF > "$DESKTOP_FILE"
[Desktop Entry]
Version=1.0
Type=Application
Name=IP Changer
Comment=Public IP address rotation and management tool
Exec=${VENV_DIR}/bin/python ${PROJECT_ROOT}/src/main.py
Path=${PROJECT_ROOT}
Terminal=false
Categories=Network;Security;Utility;
StartupNotify=true
EOF

chmod +x "$DESKTOP_FILE"

echo "============================================================"
echo " ✅ Installation completed successfully!"
echo " Launcher created: ${DESKTOP_FILE}"
echo ""
echo " To run the application manually:"
echo "   cd ${PROJECT_ROOT}"
echo "   source venv/bin/activate"
echo "   python -m src.main"
echo ""
echo " Note: For kill switch and system VPN routing, run with sudo privileges."
echo "============================================================"
