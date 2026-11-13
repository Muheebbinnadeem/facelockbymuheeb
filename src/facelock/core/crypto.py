"""
Cryptographic storage for biometric face embeddings and folder vaults.

Uses AES-256-GCM authenticated encryption with keys derived via HKDF-SHA256
from a root-protected 256-bit master secret bound to the host's /etc/machine-id.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from facelock.constants import ENCODINGS_DIR, MASTER_KEY_PATH

CHUNK_SIZE = 64 * 1024  # 64 KiB streaming chunk size for folder vault archives


def _read_machine_id() -> bytes:
    for candidate in (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")):
        if candidate.is_file():
            try:
                raw = candidate.read_text(encoding="utf-8").strip()
                if raw:
                    return raw.encode("utf-8")
            except Exception:
                continue
    return b"kali-linux-default-machine-binding"


def ensure_master_key(key_path: Optional[Path] = None) -> bytes:
    """
    Load or generate the 32-byte root master key.
    """
    path = key_path or MASTER_KEY_PATH
    if path.is_file():
        raw = path.read_bytes().strip()
        if len(raw) == 64:
            return bytes.fromhex(raw.decode("ascii"))
        if len(raw) >= 32:
            return raw[:32]

    path.parent.mkdir(parents=True, exist_ok=True)
    secret = secrets.token_bytes(32)
    tmp = path.with_suffix(".tmp")
    # Open with 0600 permissions before writing secret material
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(secret.hex().encode("ascii"))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return secret


def derive_subkey(purpose: str, context: str = "", master_key: Optional[bytes] = None) -> bytes:
    """
    Derive an isolated 256-bit AES-GCM subkey for a specific purpose and user/vault ID.
    """
    mk = master_key or ensure_master_key()
    salt = hashlib.sha256(_read_machine_id() + b":facelock-v1").digest()
    info = f"facelock:{purpose}:{context}".encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(mk)


def encrypt_json_payload(
    payload: Dict[str, Any],
    purpose: str,
    context: str,
    master_key: Optional[bytes] = None,
) -> Dict[str, str]:
    """
    Encrypt a dictionary payload with AES-256-GCM and bind AAD to purpose+context.
    """
    key = derive_subkey(purpose, context, master_key=master_key)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    aad = f"{purpose}:{context}:v1".encode("utf-8")
    plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    mac_key = derive_subkey(f"{purpose}-hmac", context, master_key=master_key)
    signature = hmac.new(mac_key, nonce + aad + ciphertext, hashlib.sha256).hexdigest()

    return {
        "schema": "facelock-enc-v1",
        "purpose": purpose,
        "context": context,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "hmac": signature,
    }


def decrypt_json_payload(
    envelope: Dict[str, Any],
    purpose: str,
    context: str,
    master_key: Optional[bytes] = None,
) -> Dict[str, Any]:
    """
    Verify HMAC and decrypt an AES-256-GCM envelope back to its dictionary payload.
    Raises ValueError if tampered with or key/context mismatches.
    """
    if envelope.get("schema") != "facelock-enc-v1":
        raise ValueError("Unsupported encrypted envelope schema")
    if envelope.get("purpose") != purpose or envelope.get("context") != context:
        raise ValueError("Envelope purpose or user context mismatch")

    nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    aad = f"{purpose}:{context}:v1".encode("utf-8")

    mac_key = derive_subkey(f"{purpose}-hmac", context, master_key=master_key)
    expected_mac = hmac.new(mac_key, nonce + aad + ciphertext, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_mac, str(envelope.get("hmac", ""))):
        raise ValueError("HMAC integrity check failed: biometric profile tampered")

    key = derive_subkey(purpose, context, master_key=master_key)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return json.loads(plaintext.decode("utf-8"))


def save_encrypted_face_profile(
    username: str,
    profile_data: Dict[str, Any],
    encodings_dir: Optional[Path] = None,
    master_key: Optional[bytes] = None,
) -> Path:
    """
    Encrypt and write a user's face profile to /etc/facelock/encodings/<username>.enc.
    """
    safe_user = "".join(c for c in username if c.isalnum() or c in ("_", "-", "."))
    if not safe_user:
        raise ValueError("Invalid username")

    target_dir = encodings_dir or ENCODINGS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    out_file = target_dir / f"{safe_user}.enc"

    envelope = encrypt_json_payload(
        profile_data,
        purpose="face-profile",
        context=safe_user,
        master_key=master_key,
    )
    # Include non-sensitive metadata outside ciphertext so UI can check status
    envelope["meta"] = {
        "username": safe_user,
        "enrolled_at": profile_data.get("enrolled_at", ""),
        "sample_count": len(profile_data.get("samples", [])),
        "engine": profile_data.get("engine", "hybrid"),
    }

    tmp_file = out_file.with_suffix(".tmp")
    fd = os.open(str(tmp_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(envelope, fh, indent=2)
        fh.write("\n")
    os.chmod(tmp_file, 0o644)
    os.replace(tmp_file, out_file)
    return out_file


def load_encrypted_face_profile(
    username: str,
    encodings_dir: Optional[Path] = None,
    master_key: Optional[bytes] = None,
) -> Optional[Dict[str, Any]]:
    """
    Load and decrypt a user's face profile, returning None if not enrolled.
    """
    safe_user = "".join(c for c in username if c.isalnum() or c in ("_", "-", "."))
    target_dir = encodings_dir or ENCODINGS_DIR
    in_file = target_dir / f"{safe_user}.enc"
    if not in_file.is_file():
        return None

    with open(in_file, "r", encoding="utf-8") as fh:
        envelope = json.load(fh)

    return decrypt_json_payload(
        envelope,
        purpose="face-profile",
        context=safe_user,
        master_key=master_key,
    )


def get_face_profile_metadata(
    username: str,
    encodings_dir: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """
    Read non-sensitive enrollment metadata without needing root access to master.key.
    """
    safe_user = "".join(c for c in username if c.isalnum() or c in ("_", "-", "."))
    target_dir = encodings_dir or ENCODINGS_DIR
    in_file = target_dir / f"{safe_user}.enc"
    if not in_file.is_file():
        return None
    try:
        with open(in_file, "r", encoding="utf-8") as fh:
            envelope = json.load(fh)
        meta = envelope.get("meta")
        if isinstance(meta, dict):
            return meta
        return {"username": safe_user, "sample_count": 1, "engine": "hybrid"}
    except Exception:
        return None


def encrypt_file_stream(
    src_path: Path,
    dst_path: Path,
    vault_id: str,
    master_key: Optional[bytes] = None,
) -> None:
    """
    Stream-encrypt an arbitrary file (e.g. a tar archive of a locked folder)
    using chunked AES-256-GCM with per-chunk sequence AAD to prevent reordering.
    """
    key = derive_subkey("folder-vault", vault_id, master_key=master_key)
    aesgcm = AESGCM(key)
    base_nonce = secrets.token_bytes(8)

    dst_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(dst_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with open(src_path, "rb") as src_fh, os.fdopen(fd, "wb") as dst_fh:
        dst_fh.write(b"FLVAULT1")
        dst_fh.write(base_nonce)
        seq = 0
        while True:
            chunk = src_fh.read(CHUNK_SIZE)
            if not chunk:
                break
            nonce = base_nonce + seq.to_bytes(4, "big")
            aad = f"vault:{vault_id}:seq:{seq}".encode("utf-8")
            enc_chunk = aesgcm.encrypt(nonce, chunk, aad)
            dst_fh.write(len(enc_chunk).to_bytes(4, "big"))
            dst_fh.write(enc_chunk)
            seq += 1


def decrypt_file_stream(
    src_path: Path,
    dst_path: Path,
    vault_id: str,
    master_key: Optional[bytes] = None,
) -> None:
    """
    Decrypt a chunked AES-256-GCM vault archive back to dst_path.
    """
    key = derive_subkey("folder-vault", vault_id, master_key=master_key)
    aesgcm = AESGCM(key)

    dst_path.parent.mkdir(parents=True, exist_ok=True)
    with open(src_path, "rb") as src_fh, open(dst_path, "wb") as dst_fh:
        magic = src_fh.read(8)
        if magic != b"FLVAULT1":
            raise ValueError("Invalid vault archive header")
        base_nonce = src_fh.read(8)
        if len(base_nonce) != 8:
            raise ValueError("Truncated vault nonce")
        seq = 0
        while True:
            len_bytes = src_fh.read(4)
            if not len_bytes:
                break
            if len(len_bytes) != 4:
                raise ValueError("Corrupted chunk length in vault archive")
            chunk_len = int.from_bytes(len_bytes, "big")
            enc_chunk = src_fh.read(chunk_len)
            if len(enc_chunk) != chunk_len:
                raise ValueError("Truncated encrypted chunk in vault archive")
            nonce = base_nonce + seq.to_bytes(4, "big")
            aad = f"vault:{vault_id}:seq:{seq}".encode("utf-8")
            plain_chunk = aesgcm.decrypt(nonce, enc_chunk, aad)
            dst_fh.write(plain_chunk)
            seq += 1
