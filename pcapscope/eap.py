"""EAP / PEAP analysis (carried in RADIUS EAP-Message attributes, RFC 3748).

Tracks an EAP exchange across the RADIUS conversation and surfaces:
  * the outer **Identity** (anonymous for a well-configured PEAP/TTLS),
  * the negotiated **method** (PEAP / EAP-TLS / EAP-TTLS / MD5 / MSCHAPv2 / GTC ...),
  * the Success/Failure result, and
  * crackable hashes for the non-tunnelled methods:
      - EAP-MD5      -> hashcat -m 4800 (response:challenge:id)
      - EAP-MSCHAPv2 -> hashcat -m 5500 (NetNTLMv1)

TLS-tunnelled methods (PEAP/TTLS/EAP-TLS) encrypt the inner auth, so only the
outer identity, method and (separately, via the TLS analyzer) the server cert
are visible.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

EAP_CODES = {1: "Request", 2: "Response", 3: "Success", 4: "Failure"}
EAP_TYPES = {
    1: "Identity", 2: "Notification", 3: "Nak", 4: "MD5-Challenge", 6: "GTC",
    13: "EAP-TLS", 17: "LEAP", 18: "EAP-SIM", 21: "EAP-TTLS", 23: "EAP-AKA",
    25: "PEAP", 26: "EAP-MSCHAPv2", 43: "EAP-FAST", 50: "EAP-AKA'",
}
TUNNELLED = {"PEAP", "EAP-TLS", "EAP-TTLS", "EAP-FAST"}
_METHOD_PRIORITY = ["EAP-TLS", "PEAP", "EAP-TTLS", "EAP-FAST", "EAP-MSCHAPv2",
                    "MD5-Challenge", "GTC", "LEAP", "EAP-SIM", "EAP-AKA"]


@dataclass
class EapPacket:
    code: int
    ident: int
    etype: int          # 0 for Success/Failure
    data: bytes         # type-data (after the type byte)


def method_name(etype: int) -> str:
    return EAP_TYPES.get(etype, f"type{etype}")


EAPOL_TYPES = {0: "EAP-Packet", 1: "EAPOL-Start", 2: "EAPOL-Logoff",
               3: "EAPOL-Key", 4: "EAPOL-Alert"}
_TLS_EAP_TYPES = {13, 21, 25, 43}      # EAP-TLS, TTLS, PEAP, FAST


def parse_eapol(payload: bytes):
    """Parse an 802.1X EAPOL frame -> (eapol_type, body). ``None`` if invalid."""
    if len(payload) < 4:
        return None
    typ = payload[1]
    blen = struct.unpack("!H", payload[2:4])[0]
    body = payload[4:4 + blen] if 0 < blen <= len(payload) - 4 else payload[4:]
    return typ, body


def _eaptls_payload(data: bytes) -> bytes:
    """Strip the EAP-TLS flags (+ optional 4-byte length) -> raw TLS fragment."""
    if not data:
        return b""
    flags = data[0]
    off = 1 + (4 if flags & 0x80 else 0)     # L bit -> 4-byte TLS-Message-Length
    return data[off:]


def parse(buf: bytes) -> EapPacket | None:
    if len(buf) < 4:
        return None
    code, ident, length = struct.unpack("!BBH", buf[:4])
    if code not in EAP_CODES:
        return None
    if code in (3, 4):                       # Success / Failure carry no type
        return EapPacket(code, ident, 0, b"")
    if len(buf) < 5:
        return None
    end = length if 4 < length <= len(buf) else len(buf)
    return EapPacket(code, ident, buf[4], buf[5:end])


def analyze_conversation(eaps: list, identity_hint: str = "") -> dict:
    """Summarise an ordered list of EapPacket from one EAP exchange."""
    info = {"identity": identity_hint, "method": "", "methods": [], "result": "",
            "tunnelled": False, "hashcat": "", "mode": "", "version": "", "nak_to": "",
            "sni": "", "tls_version": "", "cert_subject": "", "cert_issuer": "",
            "cert_sans": [], "not_after": ""}
    md5_chal = {}      # eap-ident -> challenge
    ms_chal = {}       # ms-chap-id -> authenticator challenge
    methods = []
    client_tls = bytearray()
    server_tls = bytearray()

    for e in eaps:
        if e.code == 3:
            info["result"] = "Success"
        elif e.code == 4:
            info["result"] = "Failure"
        if e.code in (1, 2) and e.etype not in (1, 2, 3):
            mn = method_name(e.etype)
            if mn not in methods:
                methods.append(mn)
        if e.etype in _TLS_EAP_TYPES:                      # collect TLS fragments
            frag = _eaptls_payload(e.data)
            if e.code == 1:
                server_tls += frag
            elif e.code == 2:
                client_tls += frag
        if e.code == 2 and e.etype == 1 and not info["identity"]:
            info["identity"] = e.data.split(b"\x00")[0].decode("utf-8", "replace")
        if e.code == 2 and e.etype == 3 and e.data:        # Nak -> desired method
            info["nak_to"] = method_name(e.data[0])
        # EAP-MD5
        if e.etype == 4 and e.data:
            vs = e.data[0]
            val = e.data[1:1 + vs]
            if e.code == 1:
                md5_chal[e.ident] = val
            elif e.code == 2 and e.ident in md5_chal and len(val) == 16:
                chal = md5_chal[e.ident]
                info["hashcat"] = f"{val.hex()}:{chal.hex()}:{e.ident:02x}"
                info["mode"], info["version"] = "4800", "EAP-MD5"
        # EAP-MSCHAPv2
        if e.etype == 26 and len(e.data) >= 2:
            opcode, msid = e.data[0], e.data[1]
            if opcode == 1 and len(e.data) >= 21:
                ms_chal[msid] = e.data[5:21]
            elif opcode == 2 and len(e.data) >= 53 and msid in ms_chal:
                peer, nt = e.data[5:21], e.data[29:53]
                name = e.data[54:].split(b"\x00")[0].decode("utf-8", "replace") if len(e.data) > 54 else info["identity"]
                user = (name.split("\\")[-1].split("@")[0]) or info["identity"] or "unknown"
                ch = hashlib.sha1(peer + ms_chal[msid] + user.encode()).digest()[:8]
                info["hashcat"] = f"{user}::::{nt.hex()}:{ch.hex()}"
                info["mode"], info["version"] = "5500", "EAP-MSCHAPv2"

    info["methods"] = methods
    info["method"] = next((m for m in _METHOD_PRIORITY if m in methods),
                          (methods[0] if methods else "Identity-only"))
    info["tunnelled"] = bool(set(methods) & TUNNELLED)

    # EAP-TLS / PEAP / TTLS: the outer TLS handshake (incl. the RADIUS server
    # certificate) is in cleartext - reassemble the fragments and parse it.
    if client_tls or server_tls:
        from . import tls
        ti = tls.analyze_stream(bytes(client_tls), bytes(server_tls))
        if ti is not None and ti.is_tls:
            info["sni"] = ti.sni
            info["tls_version"] = ti.server_version or ti.client_version
            info["cert_subject"] = ti.cert_subject
            info["cert_issuer"] = ti.cert_issuer
            info["cert_sans"] = ti.cert_sans
            info["not_after"] = ti.not_after
    return info
