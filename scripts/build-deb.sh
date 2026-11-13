#!/usr/bin/env bash
# Build a distributable Debian / Kali Linux .deb package for FaceLock
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="1.2.0"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
PKG_NAME="facelock-kali_${VERSION}_${ARCH}"
STAGE_DIR="$REPO_DIR/build/deb/$PKG_NAME"

rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR/DEBIAN"
mkdir -p "$STAGE_DIR/usr/lib/facelock"
mkdir -p "$STAGE_DIR/usr/local/bin"
mkdir -p "$STAGE_DIR/usr/share/applications"
mkdir -p "$STAGE_DIR/usr/share/polkit-1/actions"
mkdir -p "$STAGE_DIR/lib/x86_64-linux-gnu/security"
mkdir -p "$STAGE_DIR/etc/facelock"

make -C "$REPO_DIR" pam
cp "$REPO_DIR/build/pam_facelock.so" "$STAGE_DIR/lib/x86_64-linux-gnu/security/pam_facelock.so"
chmod 0644 "$STAGE_DIR/lib/x86_64-linux-gnu/security/pam_facelock.so"

cp -r "$REPO_DIR/src" "$STAGE_DIR/usr/lib/facelock/"
cp -r "$REPO_DIR/config" "$STAGE_DIR/usr/lib/facelock/"
cp -r "$REPO_DIR/scripts" "$STAGE_DIR/usr/lib/facelock/"
cp "$REPO_DIR/config/default_config.json" "$STAGE_DIR/etc/facelock/config.json"
cp "$REPO_DIR/config/com.muheeb.facelock.policy" "$STAGE_DIR/usr/share/polkit-1/actions/"
cp "$REPO_DIR/config/facelock-control.desktop" "$STAGE_DIR/usr/share/applications/"

cat > "$STAGE_DIR/usr/lib/facelock/facelock-pam-helper" << 'EOF'
#!/usr/bin/env bash
export PYTHONPATH="/usr/lib/facelock/src:${PYTHONPATH:-}"
exec /usr/bin/python3 -m facelock.cli.pam_helper "$@"
EOF

cat > "$STAGE_DIR/usr/lib/facelock/facelock-privileged" << 'EOF'
#!/usr/bin/env bash
export PYTHONPATH="/usr/lib/facelock/src:${PYTHONPATH:-}"
exec /usr/bin/python3 -m facelock.cli.privileged_helper "$@"
EOF

cat > "$STAGE_DIR/usr/local/bin/facelock-cli" << 'EOF'
#!/usr/bin/env bash
export PYTHONPATH="/usr/lib/facelock/src:${PYTHONPATH:-}"
exec /usr/bin/python3 -m facelock.cli.main "$@"
EOF

cat > "$STAGE_DIR/usr/local/bin/facelock-gui" << 'EOF'
#!/usr/bin/env bash
export PYTHONPATH="/usr/lib/facelock/src:${PYTHONPATH:-}"
exec /usr/bin/python3 -m facelock.cli.main gui "$@"
EOF

chmod 0755 "$STAGE_DIR/usr/lib/facelock/facelock-pam-helper" \
           "$STAGE_DIR/usr/lib/facelock/facelock-privileged" \
           "$STAGE_DIR/usr/local/bin/facelock-cli" \
           "$STAGE_DIR/usr/local/bin/facelock-gui"

cat > "$STAGE_DIR/DEBIAN/control" << EOF
Package: facelock-kali
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Depends: python3, python3-gi, python3-gi-cairo, gir1.2-gtk-3.0, python3-opencv, python3-cryptography, python3-dbus, policykit-1
Recommends: fprintd, libpam-fprintd
Maintainer: Muheeb <muheeb@kali.local>
Description: Windows Hello style Face, Fingerprint, and Password PAM authentication for Kali Linux
 Provides a native PAM module, 3-method graphical authentication switcher
 (Face Lock with anti-spoofing liveness, Fingerprint via fprintd, and System Password),
 AES-256-GCM encrypted folder vaults, and a GTK3 Control Center.
EOF

cat > "$STAGE_DIR/DEBIAN/postinst" << 'EOF'
#!/usr/bin/env bash
set -e
mkdir -p /etc/facelock/encodings /var/lib/facelock/vaults /var/lib/facelock/state /var/log/facelock /var/backups/facelock
chmod 0700 /var/lib/facelock/vaults
chmod 1777 /var/lib/facelock/state
PYTHONPATH="/usr/lib/facelock/src" /usr/bin/python3 -c "from facelock.core.crypto import ensure_master_key; ensure_master_key()"
EOF

cat > "$STAGE_DIR/DEBIAN/prerm" << 'EOF'
#!/usr/bin/env bash
set -e
if [[ -x /usr/local/bin/facelock-cli ]]; then
    /usr/local/bin/facelock-cli pam restore || true
fi
EOF

chmod 0755 "$STAGE_DIR/DEBIAN/postinst" "$STAGE_DIR/DEBIAN/prerm"
dpkg-deb --build "$STAGE_DIR" "$REPO_DIR/build/${PKG_NAME}.deb"
echo "[+] Built Debian package: $REPO_DIR/build/${PKG_NAME}.deb"
