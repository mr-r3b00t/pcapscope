"""Cleartext / legacy application-protocol authentication.

Recovers credentials sent in the clear (or trivially encoded) by FTP, TELNET,
SMTP, POP3 and IMAP, and SNMP v1/v2c community strings. These are the protocols
that simply hand over the password on the wire - high value for both
troubleshooting and an "is this exposed?" assurance check.

Operates on reassembled TCP streams (client/server) and per-datagram SNMP.
"""

from __future__ import annotations

import base64
import re

from . import asn1


def _lines(buf: bytes) -> list[bytes]:
    return buf.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n")


def _b64(s: bytes) -> str:
    try:
        return base64.b64decode(bytes(s) + b"===").decode("utf-8", "replace")
    except Exception:
        return ""


def _txt(b: bytes) -> str:
    return b.decode("latin-1", "replace").strip()


# ---------------------------------------------------------------------------
# FTP (21)
# ---------------------------------------------------------------------------
def analyze_ftp(client: bytes, server: bytes) -> list[dict]:
    user = pwd = ""
    for line in _lines(client):
        if line[:5].upper() == b"USER ":
            user = _txt(line[5:])
        elif line[:5].upper() == b"PASS ":
            pwd = _txt(line[5:])
    if not (user or pwd):
        return []
    result = "success" if b"230 " in server else ("failed" if b"530 " in server else "")
    return [{"mechanism": "USER/PASS", "username": user, "password": pwd, "result": result}]


# ---------------------------------------------------------------------------
# SASL helper shared by SMTP / POP3 / IMAP (AUTH / AUTHENTICATE PLAIN|LOGIN)
# ---------------------------------------------------------------------------
def _scan_sasl(lines: list[bytes]) -> list[dict]:
    creds = []
    i = 0
    while i < len(lines):
        up = lines[i].upper()
        if re.search(rb"AUTH(?:ENTICATE)?\s+PLAIN", up):
            m = re.search(rb"(?i)PLAIN\s+([A-Za-z0-9+/=]+)", lines[i])
            arg = m.group(1) if m else b""
            if not arg and i + 1 < len(lines):
                i += 1
                arg = lines[i].strip()
            try:
                parts = base64.b64decode(arg + b"===").split(b"\x00")
            except Exception:
                parts = []
            if len(parts) >= 3:
                creds.append({"mechanism": "AUTH PLAIN",
                              "username": parts[1].decode("utf-8", "replace"),
                              "password": parts[2].decode("utf-8", "replace"), "result": ""})
        elif re.search(rb"AUTH(?:ENTICATE)?\s+LOGIN", up):
            u = _b64(lines[i + 1].strip()) if i + 1 < len(lines) else ""
            p = _b64(lines[i + 2].strip()) if i + 2 < len(lines) else ""
            i += 2
            creds.append({"mechanism": "AUTH LOGIN", "username": u, "password": p, "result": ""})
        i += 1
    return creds


def analyze_smtp(client: bytes, server: bytes) -> list[dict]:
    creds = _scan_sasl(_lines(client))
    res = "success" if b"235 " in server else ("failed" if (b"535 " in server or b"535-" in server) else "")
    for c in creds:
        c["result"] = c["result"] or res
    return creds


def analyze_pop3(client: bytes, server: bytes) -> list[dict]:
    creds = []
    lines = _lines(client)
    user = pwd = ""
    for line in lines:
        up = line.upper()
        if up.startswith(b"USER "):
            user = _txt(line[5:])
        elif up.startswith(b"PASS "):
            pwd = _txt(line[5:])
        elif up.startswith(b"APOP "):
            parts = line.split(b" ")
            if len(parts) >= 3:
                creds.append({"mechanism": "APOP", "username": _txt(parts[1]), "password": "",
                              "result": "", "note": "APOP MD5 digest " + _txt(parts[2])})
    if user or pwd:
        res = "success" if b"+OK" in server else ""
        creds.append({"mechanism": "USER/PASS", "username": user, "password": pwd, "result": res})
    creds += _scan_sasl(lines)
    return creds


def _imap_args(rest: bytes) -> list[str]:
    text = rest.decode("latin-1", "replace")
    return [a or b for a, b in re.findall(r'"([^"]*)"|(\S+)', text)]


def analyze_imap(client: bytes, server: bytes) -> list[dict]:
    creds = []
    for line in _lines(client):
        m = re.match(rb"^\S+\s+LOGIN\s+(.+)$", line, re.I)
        if m:
            args = _imap_args(m.group(1))
            if len(args) >= 2:
                creds.append({"mechanism": "LOGIN", "username": args[0], "password": args[1], "result": ""})
    creds += _scan_sasl(_lines(client))
    return creds


# ---------------------------------------------------------------------------
# TELNET (23)
# ---------------------------------------------------------------------------
def strip_telnet(data: bytes) -> bytes:
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if b == 0xFF and i + 1 < n:
            cmd = data[i + 1]
            if cmd == 0xFA:                       # subnegotiation .. IAC SE
                j = i + 2
                while j < n and data[j] != 0xF0:
                    j += 1
                i = j + 1
                continue
            if cmd in (0xFB, 0xFC, 0xFD, 0xFE):    # WILL/WONT/DO/DONT + option
                i += 3
                continue
            i += 2
            continue
        out.append(b)
        i += 1
    return bytes(out)


def analyze_telnet(client: bytes, server: bytes) -> list[dict]:
    s = strip_telnet(server)
    if not re.search(rb"(?i)(login|user\s*name|user)\s*:", s):
        return []
    c = strip_telnet(client).replace(b"\x00", b"")
    lines = [l for l in _lines(c) if l.strip()]
    if not lines:
        return []
    user = _txt(lines[0])
    pwd = _txt(lines[1]) if len(lines) > 1 else ""
    if not user:
        return []
    return [{"mechanism": "login", "username": user, "password": pwd, "result": ""}]


# ---------------------------------------------------------------------------
# SNMP (UDP 161/162) - community strings
# ---------------------------------------------------------------------------
_DEFAULT_COMMUNITIES = {"public", "private", "manager", "cisco", "admin"}


def analyze_snmp(payload: bytes) -> dict | None:
    msg = asn1.parse_one(payload)
    if msg is None or msg.num != asn1.U_SEQUENCE or len(msg.children) < 2:
        return None
    ver = msg.children[0].as_int()
    if ver in (0, 1):                              # v1 / v2c
        if msg.children[1].num != asn1.U_OCTET_STRING:
            return None
        community = msg.children[1].as_str()
        return {"version": "v1" if ver == 0 else "v2c", "community": community,
                "default": community.lower() in _DEFAULT_COMMUNITIES}
    if ver == 3:
        return {"version": "v3", "community": "", "default": False}
    return None
