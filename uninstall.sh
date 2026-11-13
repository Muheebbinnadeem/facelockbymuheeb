#!/usr/bin/env bash
# FaceLock Uninstaller & Automatic PAM Restorer

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[!] Please run with sudo: sudo ./uninstall.sh"
    exit 1
fi

echo "[*] Restoring original PAM configurations from /var/backups/facelock..."
if [[ -x /usr/local/bin/facelock-cli ]]; then
    /usr/local/bin/facelock-cli pam restore || true
fi

rm -f /lib/x86_64-linux-gnu/security/pam_facelock.so \
      /lib/aarch64-linux-gnu/security/pam_facelock.so \
      /lib64/security/pam_facelock.so \
      /lib/security/pam_facelock.so

rm -f /usr/local/bin/facelock-cli /usr/local/bin/facelock-gui
rm -f /usr/share/polkit-1/actions/com.muheeb.facelock.policy
rm -f /usr/share/applications/facelock-control.desktop
rm -rf /usr/lib/facelock

echo "[+] FaceLock binaries and PAM hooks removed. (/etc/facelock and /var/lib/facelock/vaults preserved for safety)."
