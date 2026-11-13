"""
System password verification against Linux PAM / unix_chkpwd.

Verifies the user's original Kali Linux account password directly via
libpam.so.0 (using ctypes) and /usr/sbin/unix_chkpwd without storing or
duplicating user passwords.
"""

import ctypes
import ctypes.util
import os
import subprocess
from ctypes import CFUNCTYPE, POINTER, Structure, c_char_p, c_int, c_void_p
from pathlib import Path
from typing import Tuple

PAM_PROMPT_ECHO_OFF = 1
PAM_PROMPT_ECHO_ON = 2
PAM_ERROR_MSG = 3
PAM_TEXT_INFO = 4
PAM_SUCCESS = 0


class PamMessage(Structure):
    _fields_ = [("msg_style", c_int), ("msg", c_char_p)]


class PamResponse(Structure):
    _fields_ = [("resp", c_void_p), ("resp_retcode", c_int)]


CONV_FUNC = CFUNCTYPE(
    c_int,
    c_int,
    POINTER(POINTER(PamMessage)),
    POINTER(POINTER(PamResponse)),
    c_void_p,
)


class PamConv(Structure):
    _fields_ = [("conv", CONV_FUNC), ("appdata_ptr", c_void_p)]


def _verify_via_unix_chkpwd(username: str, password: str) -> Tuple[bool, str]:
    """
    Use the SGID-shadow helper /usr/sbin/unix_chkpwd to verify a user's shadow password.
    """
    chkpwd = Path("/usr/sbin/unix_chkpwd")
    if not chkpwd.is_file():
        return False, "unix_chkpwd binary not found"
    try:
        payload = password.encode("utf-8") + b"\x00"
        res = subprocess.run(
            [str(chkpwd), username, "nullok"],
            input=payload,
            capture_output=True,
            timeout=5.0,
            check=False,
        )
        if res.returncode == 0:
            return True, "System password verified"
        return False, "Incorrect system password"
    except Exception as exc:
        return False, f"Password helper error: {exc}"


def _verify_via_libpam(username: str, password: str) -> Tuple[bool, str]:
    """
    Verify username + password directly against libpam.so.0 using pam_unix.
    """
    try:
        libpam = ctypes.CDLL("libpam.so.0")
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6")
    except Exception as exc:
        return False, f"Failed to load libpam.so.0: {exc}"

    strdup = libc.strdup
    strdup.argtypes = [c_char_p]
    strdup.restype = c_void_p

    calloc = libc.calloc
    calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
    calloc.restype = c_void_p

    pam_start = libpam.pam_start
    pam_start.argtypes = [c_char_p, c_char_p, POINTER(PamConv), POINTER(c_void_p)]
    pam_start.restype = c_int

    pam_authenticate = libpam.pam_authenticate
    pam_authenticate.argtypes = [c_void_p, c_int]
    pam_authenticate.restype = c_int

    pam_end = libpam.pam_end
    pam_end.argtypes = [c_void_p, c_int]
    pam_end.restype = c_int

    pw_bytes = password.encode("utf-8")

    @CONV_FUNC
    def _conv_cb(n_messages, messages, p_response, _appdata):
        if n_messages <= 0:
            return PAM_SUCCESS
        resp_array_ptr = calloc(n_messages, ctypes.sizeof(PamResponse))
        if not resp_array_ptr:
            return 1
        resp_array = ctypes.cast(resp_array_ptr, POINTER(PamResponse))
        for i in range(n_messages):
            msg_ptr = messages[i]
            if msg_ptr and msg_ptr.contents.msg_style in (PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON):
                resp_array[i].resp = strdup(pw_bytes)
                resp_array[i].resp_retcode = 0
            else:
                resp_array[i].resp = None
                resp_array[i].resp_retcode = 0
        p_response[0] = resp_array
        return PAM_SUCCESS

    conv = PamConv(_conv_cb, None)
    pamh = c_void_p()
    # Use "common-auth" or "login" service stack
    rc = pam_start(b"common-auth", username.encode("utf-8"), ctypes.byref(conv), ctypes.byref(pamh))
    if rc != PAM_SUCCESS:
        rc = pam_start(b"login", username.encode("utf-8"), ctypes.byref(conv), ctypes.byref(pamh))
        if rc != PAM_SUCCESS:
            return False, f"pam_start returned error {rc}"

    auth_rc = pam_authenticate(pamh, 0)
    pam_end(pamh, auth_rc)

    if auth_rc == PAM_SUCCESS:
        return True, "System password verified via PAM"
    return False, "Incorrect system password"


def verify_system_password(username: str, password: str) -> Tuple[bool, str]:
    """
    Authenticate username against the original Linux system password.
    Never accepts empty passwords.
    """
    if not username or not password:
        return False, "Password cannot be empty"

    # Try unix_chkpwd first when verifying current user or running as root (avoids recursive PAM loop!)
    ok, msg = _verify_via_unix_chkpwd(username, password)
    if ok:
        return True, msg

    # If running as root or checking another user, try libpam
    if os.geteuid() == 0:
        ok_pam, msg_pam = _verify_via_libpam(username, password)
        if ok_pam:
            return True, msg_pam
        return False, msg_pam

    return False, msg
