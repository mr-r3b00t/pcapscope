"""RADIUS (RFC 2865/2866) authentication analysis + MS-CHAP hash extraction.

RADIUS (UDP 1812/1813, legacy 1645/1646) wraps a NAS's authentication of a user.
We decode the packet, identify the auth method (PAP / CHAP / MS-CHAP / MS-CHAPv2 /
EAP), correlate Access-Request with its Accept/Reject, and - for MS-CHAP(v2) -
reconstruct a NetNTLMv1 hash crackable with hashcat -m 5500.

PAP User-Password is encrypted with the shared secret (not recoverable without it);
PEAP/TTLS/TLS inner auth is encrypted too. MS-CHAP(v2) carried directly in vendor
attributes is the crackable case.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass, field

CODES = {
    1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject",
    4: "Accounting-Request", 5: "Accounting-Response", 11: "Access-Challenge",
    12: "Status-Server", 13: "Status-Client",
}

# standard attribute types we use
A_USER_NAME = 1
A_USER_PASSWORD = 2
A_CHAP_PASSWORD = 3
A_NAS_IP = 4
A_REPLY_MESSAGE = 18
A_VENDOR_SPECIFIC = 26
A_CALLED_STATION = 30
A_CALLING_STATION = 31
A_NAS_IDENTIFIER = 32
A_CHAP_CHALLENGE = 60
A_EAP_MESSAGE = 79
A_MESSAGE_AUTHENTICATOR = 80

MS_VENDOR = 311
MS_CHAP_RESPONSE = 1
MS_CHAP_CHALLENGE = 11
MS_CHAP2_RESPONSE = 25

EAP_TYPES = {1: "Identity", 2: "Notification", 4: "MD5", 13: "TLS",
             17: "LEAP", 21: "TTLS", 25: "PEAP", 26: "MSCHAPv2", 43: "FAST"}


@dataclass
class RadiusPacket:
    code: int
    ident: int
    authenticator: bytes
    attrs: list = field(default_factory=list)        # list of (type, value)
    raw: bytes = b""                                 # full packet bytes
    msgauth: bytes = b""                             # Message-Authenticator value
    msgauth_off: int = -1                            # offset of that value in raw

    @property
    def code_name(self):
        return CODES.get(self.code, f"code-{self.code}")

    def get(self, t):
        for a, v in self.attrs:
            if a == t:
                return v
        return None

    def getall(self, t):
        return [v for a, v in self.attrs if a == t]

    def vendor(self, vid, vtype):
        for a, v in self.attrs:
            if a == A_VENDOR_SPECIFIC and len(v) >= 6:
                if struct.unpack("!I", v[:4])[0] != vid:
                    continue
                off = 4
                while off + 2 <= len(v):
                    vt, vl = v[off], v[off + 1]
                    if vl < 2 or off + vl > len(v):
                        break
                    if vt == vtype:
                        return v[off + 2:off + vl]
                    off += vl
        return None


def parse(payload: bytes) -> RadiusPacket | None:
    if len(payload) < 20:
        return None
    code, ident, length = struct.unpack("!BBH", payload[:4])
    if code not in CODES:
        return None
    if length < 20 or length > len(payload):
        length = len(payload)
    auth = payload[4:20]
    raw = payload[:length]
    attrs = []
    msgauth = b""
    msgauth_off = -1
    off = 20
    guard = 0
    while off + 2 <= length and guard < 512:
        guard += 1
        t, l = payload[off], payload[off + 1]
        if l < 2 or off + l > length:
            break
        val = payload[off + 2:off + l]
        if t == A_MESSAGE_AUTHENTICATOR and l >= 18:
            msgauth, msgauth_off = val[:16], off + 2
        attrs.append((t, val))
        off += l
    return RadiusPacket(code, ident, auth, attrs, raw, msgauth, msgauth_off)


# ---------------------------------------------------------------------------
# Shared-secret crypto (recover / validate / decrypt)
# ---------------------------------------------------------------------------
def decrypt_pap(secret: bytes, request_authenticator: bytes, enc: bytes) -> str:
    """Decrypt a PAP User-Password (RFC 2865 §5.2) given the shared secret."""
    if not enc or len(request_authenticator) != 16:
        return ""
    out = bytearray()
    prev = request_authenticator
    for i in range(0, len(enc), 16):
        block = enc[i:i + 16]
        b = hashlib.md5(secret + prev).digest()
        out += bytes(x ^ y for x, y in zip(block, b))
        prev = block
    return out.rstrip(b"\x00").decode("utf-8", "replace")


def verify_response_auth(secret: bytes, req_authenticator: bytes, resp_raw: bytes) -> bool:
    """Response Authenticator = MD5(code|id|len|ReqAuth|attrs|secret)."""
    if len(resp_raw) < 20 or len(req_authenticator) != 16:
        return False
    calc = hashlib.md5(resp_raw[0:4] + req_authenticator + resp_raw[20:] + secret).digest()
    return calc == resp_raw[4:20]


def msgauth_zeroed(pkt: RadiusPacket) -> bytes:
    """The packet bytes with the Message-Authenticator value zeroed (for HMAC)."""
    if pkt.msgauth_off < 0:
        return b""
    b = bytearray(pkt.raw)
    for i in range(16):
        b[pkt.msgauth_off + i] = 0
    return bytes(b)


def verify_msgauth(secret: bytes, zeroed_packet: bytes, msgauth: bytes) -> bool:
    """Message-Authenticator = HMAC-MD5(secret, packet-with-this-attr-zeroed)."""
    if not zeroed_packet or len(msgauth) != 16:
        return False
    return hmac.new(secret, zeroed_packet, hashlib.md5).digest() == msgauth


def check_secret(secret: bytes, target: tuple) -> bool:
    if target[0] == "resp":
        return verify_response_auth(secret, target[1], target[2])
    return verify_msgauth(secret, target[1], target[2])


def crack_secret(targets: list, candidates) -> bytes | None:
    """Try each candidate (bytes) against every verifiable target.

    A real capture's responses all share one secret, but a capture may contain
    targets from different servers (or malformed ones), so we test them all.
    """
    if not targets:
        return None
    # de-duplicate identical targets to avoid redundant work
    uniq = list({(t[0], t[1], t[2]): t for t in targets}.values())
    for sec in candidates:
        for t in uniq:
            if check_secret(sec, t):
                return sec
    return None


def _username(pkt: RadiusPacket) -> str:
    u = pkt.get(A_USER_NAME)
    if u:
        return u.decode("utf-8", "replace")
    # fall back to EAP-Identity
    eap = b"".join(pkt.getall(A_EAP_MESSAGE))
    if len(eap) >= 5 and eap[0] in (1, 2) and eap[4] == 1:
        return eap[5:].decode("utf-8", "replace")
    return ""


def _bare(username: str) -> str:
    return username.split("\\")[-1].split("@")[0]


def auth_method(pkt: RadiusPacket) -> str:
    if pkt.vendor(MS_VENDOR, MS_CHAP2_RESPONSE):
        return "MS-CHAPv2"
    if pkt.vendor(MS_VENDOR, MS_CHAP_RESPONSE):
        return "MS-CHAP"
    if pkt.get(A_CHAP_PASSWORD) is not None:
        return "CHAP"
    if pkt.get(A_USER_PASSWORD) is not None:
        return "PAP"
    eap = b"".join(pkt.getall(A_EAP_MESSAGE))
    if eap:
        if len(eap) >= 5 and eap[0] in (1, 2):
            return "EAP-" + EAP_TYPES.get(eap[4], f"type{eap[4]}")
        return "EAP"
    return "unknown"


def mschap_hash(pkt: RadiusPacket):
    """Return ``(hashcat5500, version)`` for an MS-CHAP(v2) request, else ``None``."""
    user = _bare(_username(pkt))
    chal = pkt.vendor(MS_VENDOR, MS_CHAP_CHALLENGE)
    resp2 = pkt.vendor(MS_VENDOR, MS_CHAP2_RESPONSE)
    if resp2 and len(resp2) >= 50 and chal and len(chal) >= 16:
        peer = resp2[2:18]
        nt = resp2[26:50]
        ch = hashlib.sha1(peer + chal[:16] + user.encode()).digest()[:8]
        return (f"{user}::::{nt.hex()}:{ch.hex()}", "MS-CHAPv2")
    resp1 = pkt.vendor(MS_VENDOR, MS_CHAP_RESPONSE)
    if resp1 and len(resp1) >= 50 and chal and len(chal) >= 8:
        nt = resp1[26:50]
        return (f"{user}::::{nt.hex()}:{chal[:8].hex()}", "MS-CHAP")
    return None


def calling_station(pkt: RadiusPacket) -> str:
    v = pkt.get(A_CALLING_STATION)
    return v.decode("utf-8", "replace") if v else ""


def nas_info(pkt: RadiusPacket) -> str:
    nid = pkt.get(A_NAS_IDENTIFIER)
    if nid:
        return nid.decode("utf-8", "replace")
    ip = pkt.get(A_NAS_IP)
    if ip and len(ip) == 4:
        return ".".join(str(b) for b in ip)
    return ""
