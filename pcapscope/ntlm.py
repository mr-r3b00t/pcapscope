"""NTLMSSP (NTLM) message decoding and NetNTLM hash reconstruction.

NTLM rides inside SMB, HTTP, LDAP, RPC and MSSQL/TDS, so we find it by its
"NTLMSSP\\x00" signature anywhere in a reassembled stream rather than by port.
A CHALLENGE (type 2) carries the 8-byte server challenge; the matching
AUTHENTICATE (type 3) carries the user/domain/workstation and the LM/NT
responses. Correlating the two yields a NetNTLMv1/v2 hash in hashcat/john
format - exactly what you crack or feed to a downgrade/weak-auth assessment.

This is for analysing *your own* captures while troubleshooting authentication.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

SIGNATURE = b"NTLMSSP\x00"

# NegotiateFlags bits we surface.
F_UNICODE = 0x00000001
F_OEM = 0x00000002
F_SIGN = 0x00000010
F_SEAL = 0x00000020
F_NTLM = 0x00000200
F_DOMAIN_SUPPLIED = 0x00001000
F_WORKSTATION_SUPPLIED = 0x00002000
F_TARGET_TYPE_DOMAIN = 0x00010000
F_EXTENDED_SESSIONSECURITY = 0x00080000   # aka NTLM2 / NTLMv1 w/ session sec
F_TARGET_INFO = 0x00800000
F_VERSION = 0x02000000
F_128 = 0x20000000
F_KEY_EXCH = 0x40000000
F_56 = 0x80000000

FLAG_NAMES = [
    (F_UNICODE, "Unicode"),
    (F_OEM, "OEM"),
    (F_SIGN, "Sign"),
    (F_SEAL, "Seal"),
    (F_NTLM, "NTLM"),
    (F_EXTENDED_SESSIONSECURITY, "ExtendedSessionSecurity"),
    (F_TARGET_INFO, "TargetInfo"),
    (F_KEY_EXCH, "KeyExchange"),
    (F_128, "128bit"),
    (F_56, "56bit"),
]


@dataclass
class NtlmChallenge:
    flags: int = 0
    server_challenge: bytes = b""
    target_name: str = ""


@dataclass
class NtlmAuth:
    flags: int = 0
    domain: str = ""
    user: str = ""
    workstation: str = ""
    lm_response: bytes = b""
    nt_response: bytes = b""
    version: str = ""

    @property
    def ntlm_version(self) -> str:
        if len(self.nt_response) == 24:
            return "NTLMv1"
        if len(self.nt_response) > 24:
            return "NTLMv2"
        if len(self.nt_response) == 0 and len(self.lm_response) == 24:
            return "NTLMv1"
        return "unknown"

    def to_hashcat(self, server_challenge: bytes) -> tuple[str, str] | None:
        """Return ``(format_string, hashcat_mode)`` or ``None`` if unusable."""
        user = self.user or ""
        dom = self.domain or ""
        chal = server_challenge.hex()
        if self.ntlm_version == "NTLMv2" and len(self.nt_response) > 24 and server_challenge:
            nt_proof = self.nt_response[:16].hex()
            blob = self.nt_response[16:].hex()
            return (f"{user}::{dom}:{chal}:{nt_proof}:{blob}", "5600 (NetNTLMv2)")
        if self.ntlm_version == "NTLMv1" and server_challenge:
            lm = (self.lm_response or b"").hex().ljust(48, "0")[:48]
            nt = (self.nt_response or b"").hex().ljust(48, "0")[:48]
            return (f"{user}::{dom}:{lm}:{nt}:{chal}", "5500 (NetNTLMv1)")
        return None


def flag_names(flags: int) -> list[str]:
    return [name for bit, name in FLAG_NAMES if flags & bit]


def _read_str(buf: bytes, base: int, unicode_: bool) -> str:
    """Read a security buffer (Len, MaxLen, Offset) at *base* into a string."""
    if base + 8 > len(buf):
        return ""
    length, _maxlen, off = struct.unpack("<HHI", buf[base : base + 8])
    raw = buf[off : off + length]
    if not raw:
        return ""
    try:
        return raw.decode("utf-16-le" if unicode_ else "latin-1", "replace").rstrip("\x00")
    except Exception:
        return raw.hex()


def _read_bytes(buf: bytes, base: int) -> bytes:
    if base + 8 > len(buf):
        return b""
    length, _maxlen, off = struct.unpack("<HHI", buf[base : base + 8])
    return buf[off : off + length]


def _version(buf: bytes, base: int) -> str:
    if base + 8 > len(buf):
        return ""
    major, minor, build = buf[base], buf[base + 1], struct.unpack("<H", buf[base + 2 : base + 4])[0]
    return f"{major}.{minor}.{build}"


def find_messages(buf: bytes):
    """Yield ``(offset, msg_type)`` for each NTLMSSP message in *buf*."""
    start = 0
    while True:
        i = buf.find(SIGNATURE, start)
        if i < 0:
            return
        if i + 12 <= len(buf):
            mtype = struct.unpack("<I", buf[i + 8 : i + 12])[0]
            if mtype in (1, 2, 3):
                yield i, mtype
        start = i + 8


def parse_challenge(buf: bytes, off: int = 0) -> NtlmChallenge | None:
    m = buf[off:]
    if len(m) < 32 or not m.startswith(SIGNATURE):
        return None
    flags = struct.unpack("<I", m[20:24])[0]
    ch = NtlmChallenge(flags=flags, server_challenge=m[24:32])
    ch.target_name = _read_str(m, 12, bool(flags & F_UNICODE))
    return ch


def parse_authenticate(buf: bytes, off: int = 0) -> NtlmAuth | None:
    m = buf[off:]
    if len(m) < 52 or not m.startswith(SIGNATURE):
        return None
    flags = struct.unpack("<I", m[60:64])[0] if len(m) >= 64 else 0
    unicode_ = bool(flags & F_UNICODE) or flags == 0
    a = NtlmAuth(flags=flags)
    a.lm_response = _read_bytes(m, 12)
    a.nt_response = _read_bytes(m, 20)
    a.domain = _read_str(m, 28, unicode_)
    a.user = _read_str(m, 36, unicode_)
    a.workstation = _read_str(m, 44, unicode_)
    if flags & F_VERSION and len(m) >= 72:
        a.version = _version(m, 64)
    return a
