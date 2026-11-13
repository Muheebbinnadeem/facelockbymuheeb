# FaceLock for Kali Linux (`Kali Hello`)

Windows Hello-style biometric and multi-factor authentication for **Kali Linux** (and Debian-based distributions).

FaceLock hooks directly into Linux PAM (`pam_facelock.so`) so you can authenticate across **`sudo`**, **Desktop Login (`LightDM` / `GDM`)**, **Lock Screen (`xfce4-screensaver` / `light-locker`)**, **GUI Admin Prompts (`Polkit` / `pkexec`)**, and **Encrypted Folder Vaults** using:

1. **Face Lock** (Camera biometric recognition with 3-layer anti-spoofing liveness check)
2. **Fingerprint** (`fprintd` hardware sensor integration, auto-detected if present)
3. **System Password** (Your original Linux account password via `libpam` / `unix_chkpwd` — no duplicate password setup)

Whenever authentication is triggered, a dark Kali-themed **Windows Hello prompt** appears on screen. You can switch between **Face Lock**, **Fingerprint**, and **Password** at any time by clicking either the **3 method icons** or the **"Sign-in options" dropdown** inside the dialog.

---

## Core Capabilities

- **Zero Backend Editing Required**: Run `sudo ./install.sh` once, then open `facelock-gui`. Your Linux username is auto-detected, your existing system password works out of the box, and enabling/disabling PAM hooks (`sudo`, login, lockscreen, Polkit) or enrolling faces/fingerprints is done directly from the GUI Control Center.
- **3-Way Method Switcher (Icons + Dropdown)**: Every prompt includes three quick-switch buttons (**Face Lock**, **Fingerprint**, **Password**) plus a synchronized dropdown selector so you are never stuck if your camera is covered or lighting is poor.
- **Native C PAM Module (`pam_facelock.so`)**:
  - Compiled directly against `libpam` (`src/pam/pam_facelock.c`).
  - Uses non-locking PAM control flags (`[success=done new_authtok_reqd=done ignore=ignore default=ignore]`). If you authenticate in the popup (via Face, Fingerprint, or Password), `sudo` runs immediately without asking twice. If you close the popup or connect over SSH, it falls through cleanly to standard `pam_unix.so` terminal password auth.
  - Verifies that the helper executable is owned by `root:root` and not group/world-writable (`0755`) before running.
- **Security & Anti-Spoofing**:
  - **AES-256-GCM Encrypted Face Templates**: Raw camera photos are never stored on disk. Only mathematical feature vectors encrypted with a 256-bit root master key (`/etc/facelock/master.key`, `0600`) bound to `/etc/machine-id` via HKDF-SHA256 + HMAC-SHA256 integrity tags are saved in `/etc/facelock/encodings/<user>.enc`.
  - **3-Layer Liveness Check**: Rejects static photos or phone screens by checking Laplacian sharpness/texture, bilateral eye landmarks / blink variation, and frame-to-frame 3D parallax micro-motion.
  - **Hybrid Recognition Engine**: Works 100% offline out of the box using Tan-Triggs illumination normalization + spatial 4x4 Uniform LBP + oriented gradients + 2D DCT descriptors, and supports one-click upgrade to OpenCV Zoo **YuNet + SFace** 128-D neural ONNX models.
  - **Biometric Rate Limiting**: After 4 consecutive failed biometric attempts (configurable), Face and Fingerprint lock out for 60 seconds and require your original system password — matching Windows Hello and TouchID behavior.
- **AES-256-GCM Folder Lock Vaults**:
  - Lock any sensitive folder from the GUI Control Center, from the Thunar/Nautilus right-click menu (**"Lock / Unlock with Kali Hello"**), or via CLI.
  - Folder contents are archived and encrypted using chunked AES-256-GCM into `/var/lib/facelock/vaults/` and replaced with an unlock launcher. Opening or unlocking the folder pops up the Windows Hello prompt first.
  - Optional automatic re-locking whenever the desktop screensaver activates.

---

## Quick Installation (Kali Linux / Debian)

Clone the repository and run the installer once:

```bash
git clone https://github.com/muheeb/facelockbymuheeb.git
cd facelockbymuheeb
sudo ./install.sh
```

What `sudo ./install.sh` does automatically:
1. Installs any missing dependencies (`python3-gi`, `gir1.2-gtk-3.0`, `python3-opencv`, `python3-cryptography`, `libpam0g-dev`, `fprintd`).
2. Compiles `src/pam/pam_facelock.c` into `/lib/x86_64-linux-gnu/security/pam_facelock.so`.
3. Initializes `/etc/facelock`, generates your 256-bit `master.key` (`0600`), and installs the PolicyKit action so the GUI can manage backend settings seamlessly.
4. Backs up `/etc/pam.d/*` to `/var/backups/facelock/pam.d/` and enables default PAM hooks.
5. Adds the **"Lock / Unlock with Kali Hello"** right-click action to Thunar (Kali XFCE) and Nautilus.

---

## Frontend Setup Guide (No Manual Config Needed)

After installation, launch the Control Center from your Kali Application Menu (**Settings -> FaceLock (Kali Hello)**) or run:

```bash
facelock-gui
```

### 1. Account & System Password (Auto-Configured)
- On startup, `facelock-gui` automatically detects your logged-in username (e.g. `muheeb`) in the top bar.
- Your **System Password** method is already active and linked directly to Linux PAM / `unix_chkpwd` — it uses your real Kali login password automatically.

### 2. Enroll Your Face (`Tab 2: Face Lock Setup`)
1. Open **Tab 2 (Face Lock Setup)** and select your webcam (default `/dev/video0`).
2. Click **"Enroll / Update My Face (5-Pose Guided Scan)"**.
3. Follow the 5 on-screen pose prompts inside the circular scanner ring (Center, Slight Left, Slight Right, Slight Tilt, Blink).
4. Once all 5 poses reach 100%, your encrypted profile is saved automatically.
5. Click **"Test Live Face Recognition & Liveness"** to verify match score and liveness detection live.
6. *(Optional)* Click **"Download High-Accuracy OpenCV Zoo Neural Models (YuNet + SFace)"** if you want deep 128-D ONNX neural embeddings in addition to the offline engine.

### 3. Enroll Your Fingerprint (`Tab 3: Fingerprint Setup`)
- Open **Tab 3 (Fingerprint Setup)**. FaceLock automatically scans `fprintd` and USB buses for biometric sensors (Synaptics, Goodix, Elan, Validity, FocalTech, AuthenTec).
- If your laptop has a supported sensor, select a finger from the dropdown and click **"Enroll Selected Finger"**.
- If your machine has no fingerprint sensor, FaceLock cleanly shows hardware status and uses Face Lock + System Password.

### 4. Lock & Unlock Protected Folders (`Tab 4: Folder Lock Vaults`)
- Click **"+ Select & Lock a Folder"** and pick any directory you want to protect.
- To unlock it later:
  - Select it in **Tab 4** and click **"Unlock Selected Folder"**, **OR**
  - Right-click the folder in Kali's **Thunar** file manager and click **"Lock / Unlock with Kali Hello"**, **OR**
  - Double-click the `Unlock-<FolderName>.desktop` launcher inside the locked folder.
- The **Windows Hello Prompt** will appear — authenticate with **Face Lock**, **Fingerprint**, or **System Password** and your folder decrypts and opens immediately.

### 5. Choose Where Kali Hello Appears (`Tab 5: Where to Use & PAM`)
Toggle any service on or off and click **"Apply & Sync PAM Backend"**:
- `sudo` (`/etc/pam.d/sudo`)
- `Polkit / pkexec` (`/etc/pam.d/polkit-1`)
- `LightDM Desktop Login` (`/etc/pam.d/lightdm`)
- `XFCE Screensaver` (`/etc/pam.d/xfce4-screensaver`)
- `Light Locker` (`/etc/pam.d/light-locker`)
- `GDM Login` (`/etc/pam.d/gdm-password`)
- `su` (`/etc/pam.d/su`)

You can also choose which method opens first by default (**Face Lock**, **Fingerprint**, or **System Password**) and tune the match threshold and anti-spoofing liveness mode (`Strict`, `Balanced`, `Fast`).

---

## CLI Reference

While everything can be managed from `facelock-gui`, a full CLI is included for scripting and diagnostics:

```bash
# Open the Frontend Control Center GUI
facelock-gui

# Test the Windows Hello 3-method prompt dialog
facelock-cli prompt --service sudo

# Force the prompt to open directly on a specific tab (face | fingerprint | password)
facelock-cli prompt --method password

# Inspect hardware, enrollment, PAM status, and vault count (JSON output)
facelock-cli status

# Lock or unlock a folder from the terminal
facelock-cli folder lock ~/Documents/PrivateLab
facelock-cli folder unlock ~/Documents/PrivateLab --open
facelock-cli folder list

# Inspect or restore PAM configurations
facelock-cli pam status
sudo facelock-cli pam restore

# View recent authentication audit logs
facelock-cli audit-log
```

---

## Building a Debian / Kali `.deb` Package

To build a standalone `.deb` package for distribution or GitHub Releases:

```bash
make deb
sudo dpkg -i build/facelock-kali_1.2.0_amd64.deb
```

---

## Emergency Recovery & Uninstall

FaceLock is designed so you **cannot lock yourself out**:
1. Pressing `Esc` or clicking **"Cancel / Terminal Prompt"** in the popup immediately hands authentication back to standard Linux `pam_unix.so` in your terminal.
2. Original `/etc/pam.d/*` files are backed up automatically to `/var/backups/facelock/pam.d/*.original`.
3. To disable all PAM hooks and restore the original system PAM files at any time:

```bash
sudo facelock-cli pam restore
```

To completely uninstall FaceLock:

```bash
sudo ./uninstall.sh
```

---

## Repository Structure

```text
facelockbymuheeb/
├── Makefile                        # Builds pam_facelock.so, runs tests, builds .deb
├── install.sh                      # One-command automatic installer for Kali Linux
├── uninstall.sh                    # Clean uninstaller & PAM backup restorer
├── config/
│   ├── default_config.json         # Default biometric, PAM, and security policy
│   ├── com.muheeb.facelock.policy  # PolicyKit privilege rule for frontend GUI
│   └── facelock-control.desktop    # Desktop entry for Kali application menu
├── src/
│   ├── pam/
│   │   └── pam_facelock.c          # Native C PAM module (compiles to pam_facelock.so)
│   └── facelock/
│       ├── config.py               # Config manager & automatic username detection
│       ├── constants.py            # System paths and service definitions
│       ├── core/
│       │   ├── audit.py            # Syslog & JSONL security audit trail
│       │   ├── crypto.py           # AES-256-GCM + HKDF-SHA256 + HMAC storage engine
│       │   ├── face_engine.py      # Hybrid neural/spatial face recognition & 3-layer liveness
│       │   ├── fingerprint_engine.py # fprintd D-Bus/CLI & USB sensor integration
│       │   ├── folder_lock.py      # AES-256-GCM encrypted folder vault manager
│       │   ├── pam_manager.py      # Atomic PAM configurator & backup manager
│       │   ├── password_engine.py  # Native libpam.so.0 / unix_chkpwd password verifier
│       │   └── rate_limiter.py     # Brute-force lockout timer
│       ├── ui/
│       │   ├── theme.py            # Kali Dark CSS & Cairo HUD scanner rendering
│       │   ├── prompt_window.py    # Windows Hello 3-method prompt (icons + dropdown)
│       │   └── control_center.py   # Full GTK3 Frontend Control Center
│       └── cli/
│           ├── main.py             # facelock-cli & facelock-gui entrypoint
│           ├── pam_helper.py       # Graphical session resolver for PAM calls
│           └── privileged_helper.py # Root helper called by GUI via pkexec
├── scripts/
│   ├── build-deb.sh                # Builds facelock-kali_<ver>_amd64.deb
│   ├── screensaver-autolock.py     # Auto-relocks folder vaults on screen lock
│   └── thunar-integration.sh       # Right-click folder lock action for Thunar & Nautilus
└── tests/                          # Unit & integration test suite
```

## License

MIT License — Created by **Muheeb**.
