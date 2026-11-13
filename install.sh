#!/usr/bin/env bash
# FaceLock (Kali Hello) Automatic One-Command Installer for Kali Linux / Debian
# Author: Muheeb

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[!] Please run the installer with sudo: sudo ./install.sh"
    exit 1
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_USER="${SUDO_USER:-$(logname 2>/dev/null || echo "")}"

echo "=================================================================="
echo "  FaceLock by Muheeb — Windows Hello Biometric Suite for Kali"
echo "=================================================================="

# 1. Check & install missing apt packages if apt-get is available
NEEDED_PKGS=()
python3 -c "import gi" 2>/dev/null || NEEDED_PKGS+=("python3-gi" "python3-gi-cairo" "gir1.2-gtk-3.0")
python3 -c "import cv2" 2>/dev/null || NEEDED_PKGS+=("python3-opencv")
python3 -c "import cryptography" 2>/dev/null || NEEDED_PKGS+=("python3-cryptography")
python3 -c "import dbus" 2>/dev/null || NEEDED_PKGS+=("python3-dbus")
[[ -f /usr/include/security/pam_modules.h ]] || NEEDED_PKGS+=("libpam0g-dev" "gcc")

if [[ ${#NEEDED_PKGS[@]} -gt 0 ]] && command -v apt-get >/dev/null 2>&1; then
    echo "[*] Installing required system dependencies: ${NEEDED_PKGS[*]}"
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${NEEDED_PKGS[@]}" fprintd libpam-fprintd policykit-1 || true
fi

# 2. Compile native C PAM module (pam_facelock.so)
INSTALL_LIB="/usr/lib/facelock"
mkdir -p "$INSTALL_LIB"
cp -r "$REPO_DIR/src" "$INSTALL_LIB/"
cp -r "$REPO_DIR/config" "$INSTALL_LIB/"
cp -r "$REPO_DIR/scripts" "$INSTALL_LIB/"

PAM_SEC_DIR="/lib/x86_64-linux-gnu/security"
for d in "/lib/x86_64-linux-gnu/security" "/lib/aarch64-linux-gnu/security" "/lib64/security" "/lib/security"; do
    if [[ -d "$d" ]]; then
        PAM_SEC_DIR="$d"
        break
    fi
done

if command -v gcc >/dev/null 2>&1 && [[ -f /usr/include/security/pam_modules.h ]]; then
    echo "[*] Compiling native C PAM module -> $PAM_SEC_DIR/pam_facelock.so"
    gcc -fPIC -shared -Wall -Wextra -O2 \
        -DFACELOCK_HELPER_PATH="\"$INSTALL_LIB/facelock-pam-helper\"" \
        "$REPO_DIR/src/pam/pam_facelock.c" \
        -o "$PAM_SEC_DIR/pam_facelock.so" -lpam
    chown root:root "$PAM_SEC_DIR/pam_facelock.so"
    chmod 0644 "$PAM_SEC_DIR/pam_facelock.so"
else
    echo "[!] libpam0g-dev or gcc not present; using pam_exec.so bridge automatically."
fi

# 3. Create root-owned system wrappers
cat > "$INSTALL_LIB/facelock-pam-helper" << 'EOF'
#!/usr/bin/env bash
export PYTHONPATH="/usr/lib/facelock/src:${PYTHONPATH:-}"
exec /usr/bin/python3 -m facelock.cli.pam_helper "$@"
EOF

cat > "$INSTALL_LIB/facelock-privileged" << 'EOF'
#!/usr/bin/env bash
export PYTHONPATH="/usr/lib/facelock/src:${PYTHONPATH:-}"
exec /usr/bin/python3 -m facelock.cli.privileged_helper "$@"
EOF

cat > "/usr/local/bin/facelock-cli" << 'EOF'
#!/usr/bin/env bash
export PYTHONPATH="/usr/lib/facelock/src:${PYTHONPATH:-}"
exec /usr/bin/python3 -m facelock.cli.main "$@"
EOF

cat > "/usr/local/bin/facelock-gui" << 'EOF'
#!/usr/bin/env bash
export PYTHONPATH="/usr/lib/facelock/src:${PYTHONPATH:-}"
exec /usr/bin/python3 -m facelock.cli.main gui "$@"
EOF

chown -R root:root "$INSTALL_LIB"
chmod 0755 "$INSTALL_LIB/facelock-pam-helper" "$INSTALL_LIB/facelock-privileged"
chmod 0755 "/usr/local/bin/facelock-cli" "/usr/local/bin/facelock-gui"

# 4. Initialize /etc/facelock, master key, and default config
mkdir -p /etc/facelock/encodings /var/lib/facelock/vaults /var/lib/facelock/state /var/log/facelock /var/backups/facelock
chmod 0755 /etc/facelock /etc/facelock/encodings /var/lib/facelock /var/log/facelock
chmod 0700 /var/lib/facelock/vaults
chmod 1777 /var/lib/facelock/state

if [[ ! -f /etc/facelock/config.json ]]; then
    cp "$REPO_DIR/config/default_config.json" /etc/facelock/config.json
    chmod 0644 /etc/facelock/config.json
fi

# Generate AES-256-GCM master key via privileged helper
PYTHONPATH="$INSTALL_LIB/src" /usr/bin/python3 -c "from facelock.core.crypto import ensure_master_key; ensure_master_key()"

# 5. Install Polkit policy, Desktop launcher, and File Manager right-click action
if [[ -d /usr/share/polkit-1/actions ]]; then
    cp "$REPO_DIR/config/com.muheeb.facelock.policy" /usr/share/polkit-1/actions/com.muheeb.facelock.policy
    chmod 0644 /usr/share/polkit-1/actions/com.muheeb.facelock.policy
fi

if [[ -d /usr/share/applications ]]; then
    cp "$REPO_DIR/config/facelock-control.desktop" /usr/share/applications/facelock-control.desktop
    chmod 0644 /usr/share/applications/facelock-control.desktop
fi

if [[ -n "$TARGET_USER" && "$TARGET_USER" != "root" ]]; then
    usermod -aG video "$TARGET_USER" 2>/dev/null || true
    bash "$REPO_DIR/scripts/thunar-integration.sh" || true
fi

# 6. Auto-enable default PAM hooks safely (with automatic backup)
echo "[*] Backing up /etc/pam.d/* and activating default Kali Hello PAM hooks..."
/usr/local/bin/facelock-cli pam enable-defaults || true

echo ""
echo "[+] Installation Complete!"
echo "    - Launch Frontend Control Center : facelock-gui"
echo "    - Test Windows Hello Prompt      : facelock-cli prompt"
echo "    - Check Status                   : facelock-cli status"
echo "    - Emergency PAM Restore          : sudo facelock-cli pam restore"
echo "=================================================================="
