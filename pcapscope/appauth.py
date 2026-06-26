"""Challenge-response application auth: DB, VoIP, remote-access, mail CRAM-MD5.

Extracts crackable material from protocols that use a challenge/response instead
of sending the password directly:

  * CRAM-MD5  (SMTP/POP3/IMAP)   -> hashcat -m 10200  ($cram_md5$chal$resp)
  * PostgreSQL MD5 (5432)        -> hashcat -m 11100  ($postgres$user*salt*md5)
  * MySQL native (3306)          -> hashcat -m 11200  ($mysqlna$scramble*resp)
  * SIP digest (5060)            -> hashcat -m 11400  ($sip$*...)
  * VNC / RFB (5900)             -> john  $vnc$*challenge*response
  * HTTP Digest                  -> components surfaced (crackable; no clean -m)
  * RDP (3389)                   -> mstshash username (cleartext) + negotiated security

Best-effort parsers over reassembled streams; every function returns ``None`` or
``[]`` rather than raising.
"""

from __future__ import annotations

import base64
import re
import struct

from . import asn1


# ---------------------------------------------------------------------------
# CRAM-MD5 (mail) -> hashcat 10200
# ---------------------------------------------------------------------------
def cram_md5(client: bytes, server: bytes):
    if not re.search(rb"AUTH(?:ENTICATE)?\s+CRAM-MD5", client, re.I):
        return None
    mc = re.search(rb"(?:^|\n)334\s+([A-Za-z0-9+/=]+)", server) or \
        re.search(rb"(?:^|\n)\+\s+([A-Za-z0-9+/=]+)", server)
    if not mc:
        return None
    chal = mc.group(1)
    lines = client.replace(b"\r\n", b"\n").split(b"\n")
    resp = b""
    for i, l in enumerate(lines):
        if re.search(rb"AUTH(?:ENTICATE)?\s+CRAM-MD5", l, re.I):
            for j in range(i + 1, len(lines)):
                if lines[j].strip():
                    resp = lines[j].strip()
                    break
            break
    if not resp:
        return None
    try:
        user = base64.b64decode(resp + b"===").split(b" ")[0].decode("utf-8", "replace")
    except Exception:
        user = ""
    return {"protocol": "CRAM-MD5", "account": user, "tool": "hashcat", "mode": "10200",
            "hashcat": "$cram_md5$" + chal.decode() + "$" + resp.decode(), "note": ""}


# ---------------------------------------------------------------------------
# PostgreSQL md5 -> hashcat 11100
# ---------------------------------------------------------------------------
def postgres(client: bytes, server: bytes):
    pm = re.search(rb"md5([0-9a-fA-F]{32})\x00", client)
    sm = re.search(rb"R\x00\x00\x00\x0c\x00\x00\x00\x05(....)", server, re.S)
    if not (pm and sm):
        return None
    um = re.search(rb"user\x00([^\x00]+)\x00", client)
    user = um.group(1).decode("utf-8", "replace") if um else ""
    md5 = pm.group(1).decode()
    salt = sm.group(1).hex()
    return {"protocol": "PostgreSQL", "account": user, "tool": "hashcat", "mode": "11100",
            "hashcat": f"$postgres${user}*{salt}*{md5}", "note": ""}


# ---------------------------------------------------------------------------
# MySQL native password -> hashcat 11200
# ---------------------------------------------------------------------------
def mysql(client: bytes, server: bytes):
    try:
        if len(server) < 5 or server[4] != 10:           # greeting: protocol v10
            return None
        pl = server[4:]
        end = pl.index(b"\x00", 1)                        # end of server version
        i = end + 1 + 4                                   # skip thread id
        auth1 = pl[i:i + 8]
        i += 8 + 1 + 2 + 1 + 2 + 2                         # filler,cap_low,charset,status,cap_high
        i += 1 + 10                                       # auth_plugin_data_len + reserved(10)
        auth2 = pl[i:i + 12]
        scramble = (auth1 + auth2)[:20]
        if len(scramble) != 20:
            return None
        cp = client[4:]                                   # client handshake response
        j = 4 + 4 + 1 + 23                                # caps,maxpkt,charset,reserved
        uend = cp.index(b"\x00", j)
        user = cp[j:uend].decode("utf-8", "replace")
        rlen = cp[uend + 1]
        resp = cp[uend + 2:uend + 2 + rlen]
        if len(resp) != 20:
            return None
        return {"protocol": "MySQL", "account": user, "tool": "hashcat", "mode": "11200",
                "hashcat": f"$mysqlna${scramble.hex()}*{resp.hex()}", "note": ""}
    except (ValueError, IndexError):
        return None


# ---------------------------------------------------------------------------
# VNC / RFB -> john $vnc$
# ---------------------------------------------------------------------------
def vnc(client: bytes, server: bytes):
    if not (server.startswith(b"RFB 00") and client.startswith(b"RFB 00")):
        return None
    try:
        ver = server[4:11]
        if ver >= b"003.007":
            count = server[12]
            challenge = server[13 + count:13 + count + 16]
            response = client[13:29]
        else:
            challenge = server[16:32]
            response = client[12:28]
        if len(challenge) == 16 and len(response) == 16:
            return {"protocol": "VNC", "account": "", "tool": "john", "mode": "",
                    "hashcat": f"$vnc$*{challenge.hex()}*{response.hex()}",
                    "note": "crack with john --format=vnc"}
    except IndexError:
        pass
    return None


# ---------------------------------------------------------------------------
# SIP / HTTP digest
# ---------------------------------------------------------------------------
def _parse_digest(value: str) -> dict:
    params = {}
    for m in re.finditer(r'(\w+)=(?:"([^"]*)"|([^,\s]+))', value):
        params[m.group(1).lower()] = m.group(2) if m.group(2) is not None else m.group(3)
    return params


def digest_scan(blob: bytes, proto: str):
    out = []
    text = blob.decode("latin-1", "replace")
    method_m = re.search(r"(?m)^(\w+)\s+\S+\s+(?:SIP|HTTP)/", text)
    method = method_m.group(1) if method_m else ("REGISTER" if proto == "SIP" else "GET")
    for m in re.finditer(r"(?im)^(?:Authorization|Proxy-Authorization):\s*Digest\s+(.+)$", text):
        p = _parse_digest(m.group(1))
        if "response" not in p or "username" not in p:
            continue
        if proto == "SIP":
            uri = p.get("uri", "")
            uproto, uhost = (uri.split(":", 1) + [""])[:2] if ":" in uri else ("sip", uri)
            h = (f"$sip$*{uhost}*{uhost}*{p.get('username','')}*{p.get('realm','')}*{method}*"
                 f"{uproto}*{uhost}**{p.get('nonce','')}*{p.get('cnonce','')}*{p.get('nc','')}*"
                 f"{p.get('qop','')}*MD5*{p.get('response','')}")
            out.append({"protocol": "SIP", "account": p.get("username", ""), "tool": "hashcat",
                        "mode": "11400", "hashcat": h, "note": "SIP digest (verify -m 11400 fields)"})
        else:
            out.append({"protocol": "HTTP-Digest", "account": p.get("username", ""), "tool": "",
                        "mode": "", "hashcat": "",
                        "note": (f"realm={p.get('realm','')} nonce={p.get('nonce','')} "
                                 f"uri={p.get('uri','')} response={p.get('response','')} (crackable: john hdaa)")})
    return out


# ---------------------------------------------------------------------------
# SNMPv3 USM -> hashcat 25100 (MD5) / 25200 (SHA1) / 267xx (SHA-2)
# ---------------------------------------------------------------------------
_SNMP3_MODE = {12: "25100", 16: "26700", 24: "26800", 32: "26900", 48: "27300"}


def snmpv3(payload: bytes):
    msg = asn1.parse_one(payload)
    if msg is None or msg.num != asn1.U_SEQUENCE or len(msg.children) < 4:
        return None
    if msg.children[0].as_int() != 3:
        return None
    header = msg.children[1]
    if len(header.children) < 4:
        return None
    msg_id = header.children[0].as_int()
    flags = header.children[2].content
    if not flags or not (flags[0] & 0x01):              # authFlag not set -> noAuth
        return None
    secparams = msg.children[2]
    usm_buf = secparams.content
    usm_abs = secparams.end - len(usm_buf)               # offset of USM bytes in payload
    usm = asn1.parse_one(usm_buf)
    if usm is None or len(usm.children) < 6:
        return None
    user = usm.children[3].as_str()
    authnode = usm.children[4]
    ap = authnode.content
    if not ap:
        return None
    auth_abs = usm_abs + (authnode.end - len(ap))        # offset of auth params in payload
    zeroed = payload[:auth_abs] + b"\x00" * len(ap) + payload[auth_abs + len(ap):]
    mode = _SNMP3_MODE.get(len(ap), "25100")
    note = "try -m 25100 (MD5) or -m 25200 (SHA1)" if len(ap) == 12 else ""
    return {"protocol": "SNMPv3", "account": user, "tool": "hashcat", "mode": mode, "note": note,
            "hashcat": f"$SNMPv3$1${msg_id}${zeroed.hex()}${ap.hex()}"}


# ---------------------------------------------------------------------------
# RDP (3389) - mstshash username + negotiated security
# ---------------------------------------------------------------------------
_RDP_PROTO = {0: "Standard RDP (no TLS!)", 1: "TLS", 2: "CredSSP/NLA", 8: "RDSTLS", 16: "CredSSP-EX"}


def rdp(client: bytes, server: bytes):
    m = re.search(rb"mstshash=([^\r\n\x00]+)", client)
    user = m.group(1).decode("latin-1", "replace") if m else ""
    sel = None
    nm = re.search(rb"\x02.\x08\x00(....)", server, re.S)     # RDP_NEG_RSP
    if nm:
        sel = struct.unpack("<I", nm.group(1))[0]
        if sel not in _RDP_PROTO:
            sel = None
    if not user and sel is None:
        return None
    parts = []
    if user:
        parts.append(f"mstshash={user} (username in cleartext connection request)")
    if sel is not None:
        parts.append("security=" + _RDP_PROTO.get(sel, str(sel)))
    return {"protocol": "RDP", "account": user, "tool": "", "mode": "", "hashcat": "",
            "note": "; ".join(parts)}
