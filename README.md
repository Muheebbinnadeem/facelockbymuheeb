<div align="center">

# 🔐 FaceLock — Windows Hello Biometric & Folder Lock Suite for Kali Linux

### Windows Hello Face Recognition • Fingerprint (`fprintd`) • System Password Switcher • Zero Startup Keyring Prompt • AES-256-GCM Encrypted Folder Vaults

**Crafted & Engineered by [Muheeb Bin Nadeem](https://muheebbinnadeem.cv) (`Made by Muheeb`)**

[![Platform: Kali Linux](https://img.shields.io/badge/OS-Kali%20Linux%20Rolling-0078D4?style=for-the-badge&logo=kalilinux&logoColor=white)](https://www.kali.org/)
[![UI: Windows Hello Style](https://img.shields.io/badge/UI-Windows%20Hello%20Fluent-0284C7?style=for-the-badge&logo=windows11&logoColor=white)](#windows-hello-sign-in-experience)
[![Encryption: AES-256-GCM](https://img.shields.io/badge/Security-AES--256--GCM%20%2B%20PAM-059669?style=for-the-badge&logo=letsencrypt&logoColor=white)](#security--anti-spoofing)
[![Portfolio: Muheebbinnadeem.cv](https://img.shields.io/badge/Portfolio-Muheebbinnadeem.cv-047857?style=for-the-badge&logo=googlechrome&logoColor=white)](https://muheebbinnadeem.cv)
[![WhatsApp: 0307 4171882](https://img.shields.io/badge/WhatsApp-0307%204171882-25D366?style=for-the-badge&logo=whatsapp&logoColor=white)](https://wa.me/923074171882)
[![License: MIT](https://img.shields.io/badge/License-MIT-1E293B?style=for-the-badge)](LICENSE)

</div>

---

## 🌟 Overview — True Windows Hello Experience on Kali Linux

Want **Windows Hello Face Unlock, Fingerprint Unlock, and Folder Lock** on **Kali Linux** (`sudo`, Login Screen, Lock Screen, Polkit Admin Prompts, and Private Folders) without editing PAM config files by hand?

**FaceLock (`Kali Hello`)** integrates a compiled native C PAM module (`pam_facelock.so`) with a clean **Windows 11 Sign-in Options** desktop UI. Whenever Kali asks for authentication, the Windows Hello popup appears with **3 instant sign-in methods**:

1. **Face Lock** — Deep neural `YuNet` 5-landmark face detection + `SFace` 128-D identity verification + anti-spoofing liveness check.
2. **Fingerprint** — Hardware fingerprint reader support via `fprintd` / `libfprint-2` (auto-detected on USB/SPI biometric laptops).
3. **System Password** — Uses your **original Kali Linux password** directly via `libpam` / `unix_chkpwd` (zero duplicate passwords).

Switch between all 3 methods anytime using either the **3 clickable icon buttons** or the **Method Dropdown** inside the popup.

---

## ✨ Full Feature List

- **🪟 Clean Windows Hello UI & Sign-in Options (`facelock-gui`)**
  - Single-screen **Windows 11 Settings → Sign-in options** dashboard — zero clutter, zero manual config editing.
  - Auto-detects your active Kali username, webcam, fingerprint reader, and keyring status automatically.
- **🔓 Zero Startup Keyring Lock Prompt (Auto-Unlock Login Keyring & KWallet)**
  - Biometric logins (`Face` / `Fingerprint`) skip typing a password, which normally triggers *"Enter password to unlock your login keyring"* on startup.
  - FaceLock includes built-in **1-Click Keyring Auto-Unlock** (`facelock-gui` → **Fix Keyring Prompt** or `facelock-cli keyring fix`) that converts your GNOME Login Keyring to passwordless auto-unlock (keeping all saved browser/Wi-Fi passwords intact) and silences KWallet startup nags.
- **⚡ Works Everywhere Automatically (Native C PAM Module)**
  - `sudo` in terminal
  - **LightDM / GDM** Desktop Login Screen
  - **XFCE Screensaver / Light Locker** Lock Screen
  - **Polkit (`pkexec`)** Graphical Admin Prompts
  - **Protected Folder Vaults** (GUI, Thunar Right-Click, or double-click launcher)
- **📁 AES-256-GCM Encrypted Folder Lock Vaults**
  - Lock any folder in 1 click (or right-click in **Thunar / Nautilus** → **Lock / Unlock with Kali Hello**).
  - Contents are encrypted with chunked `AES-256-GCM` + `HKDF-SHA256` and only decrypt after passing the Windows Hello prompt.
- **🛡️ Anti-Spoofing & Zero-Lockout Security**
  - Raw camera photos are never saved — only `AES-256-GCM` + `HMAC-SHA256` encrypted 128-D embeddings are stored in `/etc/facelock/encodings/`.
  - **3-Frame Neural Confirmation + Liveness Check** rejects static photos, phone screens, hands, and walls.
  - **4-Attempt Biometric Lockout**: Temporarily locks biometrics for 60s after repeated failures and falls back to your system password.
  - **Non-Locking PAM Rules**: Pressing `Esc` or clicking **Cancel / Terminal Prompt** hands auth cleanly back to standard Linux `pam_unix.so`.

---

## 🚀 1-Command Installation (Kali Linux / Debian)

Open your Kali Linux terminal and run:

```bash
git clone https://github.com/Muheebbinnadeem/facelockbymuheeb.git && cd facelockbymuheeb && sudo ./install.sh
```

**What `sudo ./install.sh` does automatically:**
1. Installs required dependencies (`python3-gi`, `gir1.2-gtk-3.0`, `python3-opencv`, `python3-cryptography`, `fprintd`, `libpam-fprintd`, `libpam0g-dev`, `acl`).
2. Compiles `src/pam/pam_facelock.c` → `/lib/x86_64-linux-gnu/security/pam_facelock.so`.
3. Installs bundled **YuNet + SFace Neural ONNX Models** (`models/*.onnx`) and sets scoped ACL permissions on `/etc/facelock`.
4. Backs up `/etc/pam.d/*` to `/var/backups/facelock/pam.d/` and enables PAM hooks across `sudo`, `LightDM`, `Lock Screen`, and `Polkit`.
5. Pre-configures passwordless keyring defaults & disables KWallet startup prompts on fresh systems.
6. **Automatically opens the Windows Hello Sign-in Options window** so you can click **"Set up Face Lock"** in 3 seconds.

### 🔄 How to Update on Your Laptop or Friend's Laptop

Already cloned earlier? Pull the latest update and re-run the installer in one line:

```bash
cd facelockbymuheeb && git pull && sudo ./install.sh
```

---

## 🖥️ Quick Usage Guide

| Action | How to Do It |
|---|---|
| **Open Sign-in Options GUI** | `facelock-gui` *(or Kali Menu → Settings → FaceLock)* |
| **Enroll Face Lock** | Click **Set up Face Lock** and look at the camera for ~3 seconds |
| **Enroll Fingerprint** | Click **Set up** under Fingerprint *(requires `fprintd`-supported sensor)* |
| **Fix Startup Keyring Prompt** | Click **Fix Keyring Prompt** in GUI *(or run `facelock-cli keyring fix`)* |
| **Lock / Unlock a Folder** | Click **+ Lock Folder** in GUI, or right-click any folder in **Thunar** |
| **Test Windows Hello Popup** | Click **★ Test Windows Hello Popup** or run `facelock-cli prompt` |
| **Check System & Hardware Status** | `facelock-cli status` |
| **Restore Default PAM / Uninstall** | `sudo facelock-cli pam restore` or `sudo ./uninstall.sh` |

---

## 💖 Support & Sponsor This Project

If **FaceLock (Windows Hello for Kali Linux)** helps your workflow and you want to support ongoing open-source development or hire **Muheeb** for custom cybersecurity, Linux, or AI projects, feel free to connect or sponsor!

| Channel | Details |
|---|---|
| 🏦 **Bank Transfer** | **Askari Bank Limited** — Account No: **`02110200000209`** |
| 🌐 **Portfolio / Website** | **[Muheebbinnadeem.cv](https://muheebbinnadeem.cv)** |
| 💬 **WhatsApp** | **[0307 4171882](https://wa.me/923074171882)** (`+92 307 4171882`) |
| 🐙 **GitHub** | **[github.com/Muheebbinnadeem](https://github.com/Muheebbinnadeem)** |

---

## 🏷️ SEO Keywords & Topics

`windows-hello-linux` • `kali-linux-face-unlock` • `face-unlock-linux` • `biometric-authentication-linux` • `fingerprint-login-kali-linux` • `pam-face-authentication` • `linux-folder-lock` • `aes-256-gcm-vault` • `fprintd-gui` • `gnome-keyring-biometric-fix` • `made-by-muheeb`

---

<div align="center">
  <b>Designed &amp; Engineered with ❤️ by <a href="https://muheebbinnadeem.cv">Muheeb Bin Nadeem</a> (<code>Made by Muheeb</code>)</b>
</div>
