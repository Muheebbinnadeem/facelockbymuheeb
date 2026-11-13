#!/usr/bin/env bash
# Register right-click "Lock / Unlock with Kali Hello" action in Thunar (Kali XFCE) and Nautilus.
set -euo pipefail

TARGET_USER="${SUDO_USER:-$(logname 2>/dev/null || whoami)}"
USER_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"

if [[ -z "$USER_HOME" || ! -d "$USER_HOME" ]]; then
    exit 0
fi

# 1. Thunar Custom Action (Kali XFCE default file manager)
THUNAR_DIR="$USER_HOME/.config/Thunar"
UCA_FILE="$THUNAR_DIR/uca.xml"
mkdir -p "$THUNAR_DIR"

if [[ ! -f "$UCA_FILE" ]]; then
    cat > "$UCA_FILE" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<actions>
  <action>
    <icon>security-high</icon>
    <name>Lock / Unlock with Kali Hello (FaceLock)</name>
    <submenu></submenu>
    <unique-id>1731500100-facelock</unique-id>
    <command>facelock-cli folder toggle %f --open</command>
    <description>Encrypt and lock folder or unlock via Face, Fingerprint, or Password</description>
    <range>*</range>
    <patterns>*</patterns>
    <directories/>
  </action>
</actions>
EOF
elif ! grep -q "facelock-cli folder toggle" "$UCA_FILE" 2>/dev/null; then
    sed -i 's|</actions>|  <action>\n    <icon>security-high</icon>\n    <name>Lock / Unlock with Kali Hello (FaceLock)</name>\n    <unique-id>1731500100-facelock</unique-id>\n    <command>facelock-cli folder toggle %f --open</command>\n    <description>Encrypt and lock folder or unlock via Face, Fingerprint, or Password</description>\n    <range>*</range>\n    <patterns>*</patterns>\n    <directories/>\n  </action>\n</actions>|' "$UCA_FILE" || true
fi

# 2. Nautilus Script (for Kali GNOME installs)
NAUTILUS_SCRIPTS="$USER_HOME/.local/share/nautilus/scripts"
mkdir -p "$NAUTILUS_SCRIPTS"
NAUT_SCRIPT="$NAUTILUS_SCRIPTS/Lock or Unlock with Kali Hello"
cat > "$NAUT_SCRIPT" << 'EOF'
#!/usr/bin/env bash
IFS=$'\n'
for path in $NAUTILUS_SCRIPT_SELECTED_FILE_PATHS; do
    if [[ -d "$path" ]]; then
        facelock-cli folder toggle "$path" --open
    fi
done
EOF
chmod +x "$NAUT_SCRIPT"

chown -R "$TARGET_USER:$TARGET_USER" "$THUNAR_DIR" "$USER_HOME/.local/share/nautilus" 2>/dev/null || true
