"""Read-only Authenticode verification using the Windows trust provider.

A valid signature is not proof of a benign binary or of Microsoft authorship.
Issuer identity and revocation verification are not implemented in Phase 3.
"""
from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class SignatureResult:
    """Small, honest representation of WinVerifyTrust's outcome."""

    status: str
    code: int | None = None
    publisher_verified: bool = False


class GUID(ctypes.Structure):
    """Win32 GUID layout required by WinVerifyTrust."""

    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]


class WINTRUST_FILE_INFO(ctypes.Structure):
    """File subject of Authenticode verification."""

    _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]


class WINTRUST_DATA(ctypes.Structure):
    """WinTrust options for noninteractive file-based verification."""

    _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                ("dwStateAction", wintypes.DWORD), ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", wintypes.LPCWSTR), ("dwProvFlags", wintypes.DWORD),
                ("dwUIContext", wintypes.DWORD), ("pSignatureSettings", ctypes.c_void_p)]


# https://learn.microsoft.com/windows/win32/api/wintrust/nf-wintrust-winverifytrust
_VERIFY_V2 = GUID(0x00AAC56B, 0xCD44, 0x11D0,
                  (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
_TRUST_E_NOSIGNATURE = {0x800B0100, 0x800B0003}


def verify_authenticode(path: Path) -> SignatureResult:
    """Verify an on-disk file; never download certificates or run the file."""
    if os.name != "nt":
        return SignatureResult("unavailable")
    if not path.is_file():
        return SignatureResult("unavailable")
    try:
        file_info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), str(path), None, None)
        data = WINTRUST_DATA()
        data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        data.dwUIChoice = 2  # WTD_UI_NONE
        data.fdwRevocationChecks = 0  # no online CRL/OCSP in read-only mode
        data.dwUnionChoice = 1  # WTD_CHOICE_FILE
        data.pFile = ctypes.pointer(file_info)
        data.dwStateAction = 0  # WTD_STATEACTION_IGNORE
        data.dwProvFlags = 0x1000  # WTD_CACHE_ONLY_URL_RETRIEVAL
        wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
        function = wintrust.WinVerifyTrust
        function.argtypes = (wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p)
        function.restype = ctypes.c_long
        code = int(function(None, ctypes.byref(_VERIFY_V2), ctypes.byref(data)))
        unsigned_code = code & 0xFFFFFFFF
        if code == 0:
            return SignatureResult("valid", code=0)
        if unsigned_code in _TRUST_E_NOSIGNATURE:
            return SignatureResult("unsigned", code=unsigned_code)
        return SignatureResult("invalid_or_untrusted", code=unsigned_code)
    except (OSError, ValueError, ctypes.ArgumentError):
        return SignatureResult("unavailable")
