"""Hostname / name-intelligence extraction.

Parsers for the protocols that reveal host identities: DNS (and the
DNS-formatted mDNS / LLMNR), and DHCP. Combined in the analyzer with TLS SNI,
TLS certificate names and HTTP Host headers to produce a per-host name map -
useful for "what is this host?" and asset discovery.
"""

from __future__ import annotations

import socket
import struct

DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
             16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}


def _read_name(data: bytes, off: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name. Returns (name, next_offset)."""
    labels = []
    jumped = False
    next_off = off
    hops = 0
    while 0 <= off < len(data):
        ln = data[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:                     # compression pointer
            if off + 1 >= len(data):
                break
            ptr = ((ln & 0x3F) << 8) | data[off + 1]
            if not jumped:
                next_off = off + 2
            off = ptr
            jumped = True
            hops += 1
            if hops > 32:
                break
            continue
        labels.append(data[off + 1:off + 1 + ln].decode("latin-1", "replace"))
        off += 1 + ln
    return ".".join(labels), (next_off if jumped else off)


def _rdata(rtype: int, rdata: bytes, data: bytes, off: int) -> str:
    try:
        if rtype == 1 and len(rdata) == 4:
            return socket.inet_ntoa(rdata)
        if rtype == 28 and len(rdata) == 16:
            return socket.inet_ntop(socket.AF_INET6, rdata)
        if rtype in (5, 12, 2):                   # CNAME / PTR / NS
            return _read_name(data, off)[0]
        if rtype == 33 and len(rdata) >= 6:       # SRV -> target
            return _read_name(data, off + 6)[0]
    except (OSError, ValueError, IndexError):
        pass
    return ""


RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
               4: "NOTIMP", 5: "REFUSED", 8: "NOTZONE"}


def _parse_rr_section(data: bytes, off: int, count: int):
    records = []
    for _ in range(count):
        if off >= len(data):
            break
        name, off = _read_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _rc, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        val = _rdata(rtype, data[off:off + rdlen], data, off)
        off += rdlen
        records.append((name, DNS_TYPES.get(rtype, str(rtype)), val))
    return records, off


def parse_dns(data: bytes) -> dict | None:
    r = parse_dns_full(data)
    if r is None:
        return None
    return {"queries": r["queries"], "answers": r["answers"]}


def parse_dns_full(data: bytes) -> dict | None:
    """Full DNS message decode including QR, RCODE, AA, TC flags."""
    if len(data) < 12:
        return None
    try:
        qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    except struct.error:
        return None
    if qd > 64 or an > 256:
        return None
    qr     = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    aa     = bool((flags >> 10) & 1)
    tc     = bool((flags >> 9) & 1)
    rcode  = flags & 0xF
    off = 12
    queries = []
    for _ in range(qd):
        name, off = _read_name(data, off)
        if off + 4 > len(data):
            break
        qtype = struct.unpack("!H", data[off:off + 2])[0]
        off += 4
        if name:
            queries.append((name, DNS_TYPES.get(qtype, str(qtype))))
    answers, off = _parse_rr_section(data, off, an)
    authority, off = _parse_rr_section(data, off, ns)
    additional, _  = _parse_rr_section(data, off, ar)
    return {
        "qid": qid, "qr": qr, "opcode": opcode, "aa": aa, "tc": tc,
        "rcode": rcode, "rcode_name": RCODE_NAMES.get(rcode, str(rcode)),
        "queries": queries, "answers": answers,
        "authority": authority, "additional": additional,
    }


def parse_dhcp(data: bytes) -> dict | None:
    """BOOTP/DHCP -> client hostname, FQDN, MAC, requested IP, message type."""
    if len(data) < 240 or data[236:240] != b"\x63\x82\x53\x63":   # magic cookie
        return None
    mac = ":".join(f"{b:02x}" for b in data[28:34])
    out = {"mac": mac, "hostname": "", "fqdn": "", "requested_ip": "", "msg_type": 0}
    opts = data[240:]
    i = 0
    while i < len(opts):
        code = opts[i]
        if code == 0xFF:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(opts):
            break
        ln = opts[i + 1]
        val = opts[i + 2:i + 2 + ln]
        i += 2 + ln
        if code == 12:
            out["hostname"] = val.decode("latin-1", "replace")
        elif code == 81 and len(val) > 3:
            out["fqdn"] = val[3:].decode("latin-1", "replace").rstrip(".")
        elif code == 50 and len(val) == 4:
            out["requested_ip"] = socket.inet_ntoa(val)
        elif code == 53 and val:
            out["msg_type"] = val[0]
    return out
