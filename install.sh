#!/usr/bin/env bash
# FaceLock (Windows Hello for Kali Linux) Automatic 1-Command Installer
# Made by Muheeb Bin Nadeem (https://muheebbinnadeem.cv)

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

# 1. Check & install missing apt packages
NEEDED_PKGS=()
python3 -c "import gi" 2>/dev/null || NEEDED_PKGS+=("python3-gi" "python3-gi-cairo" "gir1.2-gtk-3.0")
python3 -c "import cv2" 2>/dev/null || NEEDED_PKGS+=("python3-opencv")
python3 -c "import cryptography" 2>/dev/null || NEEDED_PKGS+=("python3-cryptography")
python3 -c "import dbus" 2>/dev/null || NEEDED_PKGS+=("python3-dbus")
[[ -f /usr/include/security/pam_modules.h ]] || NEEDED_PKGS+=("libpam0g-dev" "gcc")
command -v fprintd-enroll >/dev/null 2>&1 || NEEDED_PKGS+=("fprintd" "libpam-fprintd" "libfprint-2-2")

if [[ ${#NEEDED_PKGS[@]} -gt 0 ]] && command -v apt-get >/dev/null 2>&1; then
    echo "[*] Installing required system dependencies: ${NEEDED_PKGS[*]}"
    apt-get update -qq || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${NEEDED_PKGS[@]}" policykit-1 acl || true
fi

# Start fprintd if installed
systemctl unmask fprintd.service 2>/dev/null || true
systemctl start fprintd.service 2>/dev/null || true

# 2. Sync latest codebase & bundled Neural ONNX models to /usr/lib/facelock
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

# 4. Initialize directories with strict per-user ACL permissions (no 0777 world-writable exposure)
mkdir -p /etc/facelock/encodings /var/lib/facelock/vaults /var/lib/facelock/state /var/log/facelock /var/backups/facelock
chmod 0755 /etc/facelock /var/lib/facelock
chmod 0700 /etc/facelock/encodings /var/lib/facelock/vaults
chmod 1777 /var/lib/facelock/state /var/log/facelock
rm -f /etc/facelock/encodings/*.tmp

if [[ ! -f /etc/facelock/config.json ]]; then
    cp "$REPO_DIR/config/default_config.json" /etc/facelock/config.json
fi
chmod 0644 /etc/facelock/config.json

PYTHONPATH="$INSTALL_LIB/src" /usr/bin/python3 -c "from facelock.core.crypto import ensure_master_key; ensure_master_key()"
chmod 0600 /etc/facelock/master.key

# Remove legacy non-neural profiles so user gets Neural SFace accuracy
for enc_f in /etc/facelock/encodings/*.enc "/home/${TARGET_USER:-}/.local/share/facelock/encodings/"*.enc; do
    if [[ -f "$enc_f" ]] && grep -q "spatial-lbp-hog-dct" "$enc_f" 2>/dev/null; then
        rm -f "$enc_f"
    fi
done

# Grant scoped ACL permissions exclusively to TARGET_USER (keeps other local users locked out)
if [[ -n "$TARGET_USER" && "$TARGET_USER" != "root" ]]; then
    usermod -aG video "$TARGET_USER" 2>/dev/null || true
    if command -v setfacl >/dev/null 2>&1; then
        setfacl -m "u:${TARGET_USER}:r--" /etc/facelock/master.key 2>/dev/null || true
        setfacl -m "u:${TARGET_USER}:rw-" /etc/facelock/config.json 2>/dev/null || true
        setfacl -m "u:${TARGET_USER}:rwx" /etc/facelock/encodings /var/lib/facelock/vaults 2>/dev/null || true
    fi
    bash "$REPO_DIR/scripts/thunar-integration.sh" || true
    # Disable KWallet nag & initialize passwordless login keyring if none exists yet
    PYTHONPATH="$INSTALL_LIB/src" /usr/bin/python3 -c "from facelock.core.keyring_manager import initialize_fresh_keyring_if_missing; initialize_fresh_keyring_if_missing('$TARGET_USER')" || true
fi

# 5. Install Polkit policy & Desktop shortcut
if [[ -d /usr/share/polkit-1/actions ]]; then
    cp "$REPO_DIR/config/com.muheeb.facelock.policy" /usr/share/polkit-1/actions/com.muheeb.facelock.policy
    chmod 0644 /usr/share/polkit-1/actions/com.muheeb.facelock.policy
fi

if [[ -d /usr/share/applications ]]; then
    cp "$REPO_DIR/config/facelock-control.desktop" /usr/share/applications/facelock-control.desktop
    chmod 0644 /usr/share/applications/facelock-control.desktop
fi

# 6. Auto-enable PAM hooks (sudo, LightDM, Lock Screen, Polkit) with automatic backup
echo "[*] Auto-configuring PAM hooks (sudo, Login, Lock Screen, Polkit)..."
/usr/local/bin/facelock-cli pam enable-defaults || true

echo ""
echo "[+] Installation Complete! Made by Muheeb (https://muheebbinnadeem.cv)"
echo "=================================================================="

# 7. Auto-open Windows Hello Sign-in Options GUI immediately
if [[ -n "${DISPLAY:-}" ]] && [[ "${FACELOCK_NO_AUTO_GUI:-0}" != "1" ]]; then
    echo "[*] Opening Windows Hello Sign-in Options window..."
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
