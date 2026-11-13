#!/usr/bin/env bash
# FaceLock (Kali Hello) Automatic One-Command Installer & Launcher for Kali Linux
# Author: Muheeb

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[!] Run this single command to install and open Kali Hello:"
    echo "    sudo ./install.sh"
    exit 1
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_USER="${SUDO_USER:-$(logname 2>/dev/null || echo "")}"

echo "=================================================================="
echo "  FaceLock by Muheeb — Windows Hello Biometric Suite for Kali"
echo "=================================================================="

# 1. Check & install missing apt packages if needed
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

# 2. Sync latest codebase and bundled Neural ONNX models (YuNet + SFace) to /usr/lib/facelock
INSTALL_LIB="/usr/lib/facelock"
rm -rf "$INSTALL_LIB/src" "$INSTALL_LIB/config" "$INSTALL_LIB/scripts" "$INSTALL_LIB/models"
mkdir -p "$INSTALL_LIB" /var/lib/facelock/models
cp -r "$REPO_DIR/src" "$INSTALL_LIB/"
cp -r "$REPO_DIR/config" "$INSTALL_LIB/"
cp -r "$REPO_DIR/scripts" "$INSTALL_LIB/"
if [[ -d "$REPO_DIR/models" ]]; then
    cp -r "$REPO_DIR/models" "$INSTALL_LIB/"
    cp -f "$REPO_DIR/models/"*.onnx /var/lib/facelock/models/ 2>/dev/null || true
fi

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
fi

# 3. Create global CLI and GUI executables
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

# 4. Initialize directories & permissions so the desktop user can enroll faces & lock folders seamlessly
mkdir -p /etc/facelock/encodings /var/lib/facelock/vaults /var/lib/facelock/state /var/log/facelock /var/backups/facelock
chmod 0755 /etc/facelock /var/lib/facelock
chmod 0777 /etc/facelock/encodings /var/lib/facelock/vaults /var/lib/facelock/state /var/log/facelock
rm -f /etc/facelock/encodings/*.tmp

# Remove any legacy non-neural face encodings so user gets 100% Neural SFace accuracy
for enc_f in /etc/facelock/encodings/*.enc "/home/${TARGET_USER:-}/.local/share/facelock/encodings/"*.enc; do
    if [[ -f "$enc_f" ]] && grep -q "spatial-lbp-hog-dct" "$enc_f" 2>/dev/null; then
        echo "[*] Removing legacy non-neural profile ($enc_f) for SFace Neural upgrade..."
        rm -f "$enc_f"
    fi
done
if [[ -n "$TARGET_USER" && "$TARGET_USER" != "root" ]]; then
    chown -R "$TARGET_USER:$TARGET_USER" /etc/facelock/encodings 2>/dev/null || true
fi

if [[ ! -f /etc/facelock/config.json ]]; then
    cp "$REPO_DIR/config/default_config.json" /etc/facelock/config.json
fi
chmod 0666 /etc/facelock/config.json

PYTHONPATH="$INSTALL_LIB/src" /usr/bin/python3 -c "from facelock.core.crypto import ensure_master_key; ensure_master_key()"
chmod 0644 /etc/facelock/master.key

# 5. Install Polkit policy, Desktop shortcut & Thunar Right-Click integration
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

# 6. Auto-enable PAM hooks (sudo, LightDM, Polkit, Lock Screen) with backup
echo "[*] Auto-configuring PAM hooks (sudo, Login, Lock Screen, Polkit)..."
/usr/local/bin/facelock-cli pam enable-defaults || true

echo ""
echo "[+] Everything is installed and configured automatically!"
echo "=================================================================="

# 7. Automatically open the Kali Hello GUI window for the user right away!
if [[ -n "${DISPLAY:-}" ]] && [[ "${FACELOCK_NO_AUTO_GUI:-0}" != "1" ]]; then
    echo "[*] Opening Kali Hello Sign-in Options window..."
    if [[ -n "$TARGET_USER" && "$TARGET_USER" != "root" ]]; then
        TargetUID="$(id -u "$TARGET_USER")"
        sudo -u "$TARGET_USER" \
            DISPLAY="${DISPLAY}" \
            XAUTHORITY="${XAUTHORITY:-/home/$TARGET_USER/.Xauthority}" \
            XDG_RUNTIME_DIR="/run/user/${TargetUID}" \
            DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${TargetUID}/bus" \
            /usr/local/bin/facelock-gui >/dev/null 2>&1 &
    else
        /usr/local/bin/facelock-gui >/dev/null 2>&1 &
    fi
fi
