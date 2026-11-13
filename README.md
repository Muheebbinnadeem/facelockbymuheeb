# FaceLock for Kali Linux (`Kali Hello`)

Windows Hello-style biometric and multi-factor authentication for **Kali Linux** (and Debian-based distributions).

FaceLock hooks directly into Linux PAM (`pam_facelock.so`) so you can authenticate across **`sudo`**, **Desktop Login (`LightDM` / `GDM`)**, **Lock Screen (`xfce4-screensaver` / `light-locker`)**, **GUI Admin Prompts (`Polkit` / `pkexec`)**, and **Encrypted Folder Vaults** using:

1. **Face Lock** (Bundled `YuNet` 5-landmark face detector + `SFace` 128-D deep neural recognition + 3-frame liveness check)
2. **Fingerprint** (`fprintd` hardware sensor integration, auto-detected if present)
3. **System Password** (Your original Kali Linux account password via `libpam` / `unix_chkpwd` — no extra password setup required)

Whenever authentication is requested, a dark Kali-themed **Windows Hello prompt** appears on screen. You can switch between **Face Lock**, **Fingerprint**, and **Password** at any time by clicking either the **3 method icons** or the **"Sign-in options" dropdown** inside the popup.

---

## Install & Setup (1 Command Only)

Clone the repository and run the installer:

```bash
git clone https://github.com/muheeb/facelockbymuheeb.git
cd facelockbymuheeb
sudo ./install.sh
```

### What `sudo ./install.sh` Does Automatically:
1. Installs any missing dependencies (`python3-gi`, `gir1.2-gtk-3.0`, `python3-opencv`, `python3-cryptography`, `libpam0g-dev`, `fprintd`).
2. Compiles the native C PAM module (`src/pam/pam_facelock.c` -> `/lib/x86_64-linux-gnu/security/pam_facelock.so`).
3. Installs the bundled **YuNet + SFace Neural ONNX Models** (`models/*.onnx`), sets up `/etc/facelock`, and generates the AES-256-GCM master key.
4. Backs up `/etc/pam.d/*` and activates Kali Hello across `sudo`, `LightDM`, `Lock Screen`, and `Polkit` automatically.
5. Adds the **"Lock / Unlock with Kali Hello"** right-click action to Kali's **Thunar** (and Nautilus) file manager.
6. **Automatically opens the Kali Hello Sign-in Options window** on your screen as soon as installation finishes.

---

## Using the Kali Hello Window

Once the window opens (or anytime via `facelock-gui` / Application Menu -> **FaceLock (Kali Hello)**):

1. **Face Lock**:
   - Click **"Set Up Face Lock (Auto 3s Scan)"** and look at the camera for 3 seconds.
   - Your 128-D neural face profile is encrypted with AES-256-GCM and activated immediately.
2. **Fingerprint**:
   - If your laptop has a fingerprint sensor, click **"Set Up Fingerprint"** to enroll your finger.
   - If no fingerprint sensor is connected, FaceLock automatically uses Face Lock + System Password.
3. **System Password**:
   - Already active out of the box using your auto-detected Linux username and original Kali password.
4. **Folder Lock (AES-256-GCM Encrypted Folders)**:
   - Click **"+ Select & Lock a Folder"** to encrypt and lock any folder (or right-click any folder in Thunar and select **"Lock / Unlock with Kali Hello"**).
   - Click **"Unlock Selected Folder"** (or double-click the launcher inside the locked folder) — the Windows Hello popup will verify your Face, Fingerprint, or Password and immediately unlock and open the folder.
5. **Test Popup Live**:
   - Click **"★ Test Windows Hello Popup Now"** to test the live popup and method switcher (icons + dropdown).

---

## Security Architecture

- **Bundled Deep Neural Face Engine (`YuNet` + `SFace` 128-D)**:
  - `YuNet` validates all 5 anatomical facial landmarks (right eye, left eye, nose tip, right/left mouth corners) with confidence `>= 0.85` — walls, hands, or covered faces are rejected immediately.
  - `SFace` extracts 128-D neural identity embeddings and requires **3 consecutive matching frames** (`cosine >= 0.50`, `L2 <= 1.01`) plus temporal liveness verification to prevent photo/screen spoofing and false accepts.
- **AES-256-GCM Encrypted Storage**:
  - Raw camera photos are never stored on disk. Only encrypted mathematical embeddings signed with HMAC-SHA256 are stored in `/etc/facelock/encodings/<user>.enc`.
  - Locked folders are packed and stream-encrypted with chunked AES-256-GCM (`FLVAULT1`).
- **Biometric Rate Limiting**:
  - After 4 consecutive failed biometric attempts, Face Lock and Fingerprint lock out for 60 seconds and require your original system password.
- **Zero-Lockout PAM Design**:
  - Uses non-locking PAM control flags. Pressing `Esc` or clicking **"Cancel / Terminal Prompt"** in the popup cleanly hands authentication back to standard terminal `pam_unix.so`.
  - Remote SSH sessions automatically bypass local camera/fingerprint checks.

---

## Helpful Commands

```bash
# Open the Kali Hello GUI window anytime
facelock-gui

# Test the Windows Hello Sign-in Popup from terminal
facelock-cli prompt

# Check hardware, camera, neural engine, and PAM status
facelock-cli status

# Lock or unlock a folder from terminal
facelock-cli folder lock ~/Documents/SecretFolder
facelock-cli folder unlock ~/Documents/SecretFolder --open

# Emergency restore default PAM configuration
sudo facelock-cli pam restore

# Full uninstall
sudo ./uninstall.sh
```

---

## Repository Structure

```text
facelockbymuheeb/
├── Makefile                        # Compiles pam_facelock.so, runs tests, builds .deb
├── install.sh                      # 1-command automatic installer & GUI launcher
├── uninstall.sh                    # Clean uninstaller & PAM backup restorer
├── models/                         # Bundled YuNet & SFace neural ONNX models
│   ├── face_detection_yunet_2023mar.onnx
│   └── face_recognition_sface_2021dec_int8.onnx
├── config/
│   ├── default_config.json         # Default biometric, PAM, and security policy
│   ├── com.muheeb.facelock.policy  # PolicyKit rule for frontend GUI
│   └── facelock-control.desktop    # Desktop entry for Kali application menu
├── src/
│   ├── pam/
│   │   └── pam_facelock.c          # Native C PAM module (pam_facelock.so)
│   └── facelock/
│       ├── config.py               # Config manager & automatic username detection
│       ├── constants.py            # System paths and service definitions
│       ├── core/                   # Crypto, Neural Face, Fingerprint, Password, PAM, Vaults
│       ├── ui/                     # Windows Hello Prompt & Unified Control Center (GTK3)
│       └── cli/                    # CLI & PAM graphical session helper
├── scripts/
│   ├── build-deb.sh                # Builds facelock-kali_<ver>_amd64.deb
│   ├── screensaver-autolock.py     # Auto-relocks folder vaults on screen lock
│   └── thunar-integration.sh       # Right-click folder lock action for Thunar & Nautilus
└── tests/                          # Automated unit & integration tests
```

## License

MIT License — Created by **Muheeb**.
