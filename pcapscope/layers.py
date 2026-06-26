"""Link / network / transport layer decoders.

Just enough of L2-L4 to drive flow accounting and to hand transport payloads
to the authentication-protocol analyzers. Pure standard library; defensive
against truncated frames (every decoder returns ``None`` rather than raising).
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

from .reader import (
    LINKTYPE_ETHERNET,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_LINUX_SLL2,
    LINKTYPE_NULL,
    LINKTYPE_LOOP,
    LINKTYPE_RAW,
    LINKTYPE_RAW_ALT1,
    LINKTYPE_RAW_ALT2,
    LINKTYPE_IPV4,
    LINKTYPE_IPV6,
)

ETH_P_IPV4 = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_ARP = 0x0806
ETH_P_EAPOL = 0x888E
ETH_P_VLAN = 0x8100
ETH_P_QINQ = 0x88A8
ETH_P_QINQ2 = 0x9100

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 2: "IGMP", 47: "GRE", 50: "ESP", 51: "AH", 132: "SCTP"}


@dataclass
class Decoded:
    """Flat view of one packet's L2-L4 fields used by the analyzer."""

    l3: str = ""               # "IPv4" | "IPv6" | "ARP" | "" (non-IP)
    l4: str = ""               # "TCP" | "UDP" | "ICMP" | "ICMPv6" | ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    proto: int = 0             # IP protocol number
    ttl: int = 0
    tos: int = 0               # IPv4 ToS / IPv6 traffic class
    tcp_flags: int = 0
    tcp_seq: int = 0
    tcp_ack: int = 0
    tcp_window: int = 0
    payload: bytes = b""       # L4 payload (TCP/UDP data)
    payload_offset: int = 0    # absolute offset of payload within frame
    vlan: int = 0
    eth_src: str = ""
    eth_dst: str = ""
    icmp_type: int = -1
    icmp_code: int = -1
    arp_op: int = 0
    note: str = ""             # decode caveat (truncation etc.)


# TCP flag bits
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


def tcp_flag_str(flags: int) -> str:
    out = []
    for bit, name in ((SYN, "SYN"), (ACK, "ACK"), (FIN, "FIN"), (RST, "RST"),
                      (PSH, "PSH"), (URG, "URG"), (ECE, "ECE"), (CWR, "CWR")):
        if flags & bit:
            out.append(name)
    return "-".join(out) if out else "none"


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def decode(data: bytes, linktype: int) -> Decoded | None:
    """Peel a frame down to L4. Returns ``None`` if nothing useful decodes."""
    try:
        if linktype == LINKTYPE_ETHERNET:
            return _eth(data)
        if linktype in (LINKTYPE_RAW, LINKTYPE_RAW_ALT1, LINKTYPE_RAW_ALT2, LINKTYPE_IPV4, LINKTYPE_IPV6):
            return _rawip(data)
        if linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
            return _loopback(data, linktype)
        if linktype == LINKTYPE_LINUX_SLL:
            return _sll(data)
        if linktype == LINKTYPE_LINUX_SLL2:
            return _sll2(data)
        # Unknown link type: try to guess raw IP from the version nibble.
        if data and data[0] >> 4 in (4, 6):
            return _rawip(data)
    except (struct.error, IndexError):
        return None
    return None


def _eth(data: bytes) -> Decoded | None:
    if len(data) < 14:
        return None
    d = Decoded(eth_dst=_mac(data[0:6]), eth_src=_mac(data[6:12]))
    etype = struct.unpack("!H", data[12:14])[0]
    off = 14
    # peel any stack of VLAN tags
    while etype in (ETH_P_VLAN, ETH_P_QINQ, ETH_P_QINQ2) and len(data) >= off + 4:
        tci = struct.unpack("!H", data[off : off + 2])[0]
        d.vlan = tci & 0x0FFF
        etype = struct.unpack("!H", data[off + 2 : off + 4])[0]
        off += 4
    return _l3(d, etype, data, off)


def _loopback(data: bytes, linktype: int) -> Decoded | None:
    if len(data) < 4:
        return None
    d = Decoded()
    # 4-byte address family, host or network order depending on platform.
    fam = struct.unpack("<I", data[:4])[0]
    if fam not in (2, 24, 28, 30):
        fam = struct.unpack(">I", data[:4])[0]
    if fam == 2:
        return _ipv4(d, data, 4)
    if fam in (24, 28, 30):
        return _ipv6(d, data, 4)
    return None


def _sll(data: bytes) -> Decoded | None:
    if len(data) < 16:
        return None
    d = Decoded()
    etype = struct.unpack("!H", data[14:16])[0]
    return _l3(d, etype, data, 16)


def _sll2(data: bytes) -> Decoded | None:
    if len(data) < 20:
        return None
    d = Decoded()
    etype = struct.unpack("!H", data[0:2])[0]
    return _l3(d, etype, data, 20)


def _rawip(data: bytes) -> Decoded | None:
    if not data:
        return None
    ver = data[0] >> 4
    d = Decoded()
    if ver == 4:
        return _ipv4(d, data, 0)
    if ver == 6:
        return _ipv6(d, data, 0)
    return None


def _l3(d: Decoded, etype: int, data: bytes, off: int) -> Decoded | None:
    if etype == ETH_P_IPV4:
        return _ipv4(d, data, off)
    if etype == ETH_P_IPV6:
        return _ipv6(d, data, off)
    if etype == ETH_P_ARP:
        return _arp(d, data, off)
    if etype == ETH_P_EAPOL:
        d.l3 = "EAPOL"
        d.payload = data[off:]
        return d
    d.l3 = ""
    return d  # non-IP frame still counts toward stats


def _arp(d: Decoded, data: bytes, off: int) -> Decoded:
    d.l3 = "ARP"
    if len(data) >= off + 8:
        d.arp_op = struct.unpack("!H", data[off + 6 : off + 8])[0]
    return d


def _ipv4(d: Decoded, data: bytes, off: int) -> Decoded | None:
    if len(data) < off + 20:
        return None
    ihl = (data[off] & 0x0F) * 4
    if ihl < 20:
        return None
    total_len = struct.unpack("!H", data[off + 2 : off + 4])[0]
    d.tos = data[off + 1]
    d.ttl = data[off + 8]
    proto = data[off + 9]
    d.l3 = "IPv4"
    d.proto = proto
    d.src_ip = socket.inet_ntoa(data[off + 12 : off + 16])
    d.dst_ip = socket.inet_ntoa(data[off + 16 : off + 20])
    frag = struct.unpack("!H", data[off + 6 : off + 8])[0]
    more_frags = bool(frag & 0x2000)
    frag_off = frag & 0x1FFF
    l4_off = off + ihl
    # Trust total_len to bound payload when sane (strips Ethernet padding).
    end = off + total_len if 20 <= total_len <= len(data) - off else len(data)
    if frag_off != 0:
        d.note = "ip-fragment"
        return d  # non-first fragment: no usable L4 header
    return _l4(d, proto, data, l4_off, end, more_frags)


def _ipv6(d: Decoded, data: bytes, off: int) -> Decoded | None:
    if len(data) < off + 40:
        return None
    payload_len = struct.unpack("!H", data[off + 4 : off + 6])[0]
    nh = data[off + 6]
    d.l3 = "IPv6"
    d.ttl = data[off + 7]  # hop limit
    d.src_ip = socket.inet_ntop(socket.AF_INET6, data[off + 8 : off + 24])
    d.dst_ip = socket.inet_ntop(socket.AF_INET6, data[off + 24 : off + 40])
    end = off + 40 + payload_len if payload_len and (off + 40 + payload_len) <= len(data) else len(data)
    p = off + 40
    # walk a few extension headers
    ext = {0, 43, 44, 60, 51, 50, 135}
    for _ in range(8):
        if nh in ext and len(data) >= p + 2:
            if nh == 44:  # fragment header is fixed 8 bytes
                nh = data[p]
                p += 8
            else:
                hdr_len = (data[p + 1] + 1) * 8
                nh = data[p]
                p += hdr_len
        else:
            break
    d.proto = nh
    return _l4(d, nh, data, p, end, False)


def _l4(d: Decoded, proto: int, data: bytes, off: int, end: int, more_frags: bool) -> Decoded:
    end = min(end, len(data))
    if proto == IPPROTO_TCP and len(data) >= off + 20:
        sport, dport, seq, ack = struct.unpack("!HHII", data[off : off + 12])
        off12 = data[off + 12]
        data_off = (off12 >> 4) * 4
        flags = data[off + 13]
        window = struct.unpack("!H", data[off + 14 : off + 16])[0]
        d.l4 = "TCP"
        d.src_port, d.dst_port = sport, dport
        d.tcp_seq, d.tcp_ack = seq, ack
        d.tcp_flags, d.tcp_window = flags, window
        payload_start = off + max(20, data_off)
        d.payload_offset = payload_start
        if payload_start < end:
            d.payload = data[payload_start:end]
        return d
    if proto == IPPROTO_UDP and len(data) >= off + 8:
        sport, dport, ulen = struct.unpack("!HHH", data[off : off + 6])
        d.l4 = "UDP"
        d.src_port, d.dst_port = sport, dport
        payload_start = off + 8
        d.payload_offset = payload_start
        udp_end = off + ulen if 8 <= ulen <= end - off else end
        if payload_start < udp_end:
            d.payload = data[payload_start:udp_end]
        return d
    if proto == IPPROTO_ICMP and len(data) >= off + 2:
        d.l4 = "ICMP"
        d.icmp_type, d.icmp_code = data[off], data[off + 1]
        return d
    if proto == IPPROTO_ICMPV6 and len(data) >= off + 2:
        d.l4 = "ICMPv6"
        d.icmp_type, d.icmp_code = data[off], data[off + 1]
        return d
    return d


# ---------------------------------------------------------------------------
# TCP stream reassembly (lightweight, bounded).
# ---------------------------------------------------------------------------
def conn_key(d: Decoded) -> tuple:
    """Bidirectional connection key (order-independent) for TCP/UDP."""
    a = (d.src_ip, d.src_port)
    b = (d.dst_ip, d.dst_port)
    lo, hi = (a, b) if a <= b else (b, a)
    return (d.l4, lo, hi)


class TCPStream:
    """Accumulates per-direction TCP payload for one connection.

    We reorder by sequence number and stitch a contiguous buffer per direction,
    capped at ``cap`` bytes (auth handshakes live at the start of a connection,
    so a small cap keeps memory bounded while still capturing what matters).
    """

    __slots__ = ("segs", "base", "cap", "_done")

    def __init__(self, cap: int = 131072):
        # direction key -> list of (seq, payload)
        self.segs: dict[tuple, list[tuple[int, bytes]]] = {}
        self.base: dict[tuple, int] = {}
        self.cap = cap
        self._done: dict[tuple, bool] = {}

    def add(self, direction: tuple, seq: int, payload: bytes, is_syn: bool) -> None:
        if not payload and not is_syn:
            return
        if self._done.get(direction):
            return
        if is_syn and direction not in self.base:
            self.base[direction] = (seq + 1) & 0xFFFFFFFF
        if payload:
            self.segs.setdefault(direction, []).append((seq, payload))
            total = sum(len(p) for _, p in self.segs[direction])
            if total >= self.cap:
                self._done[direction] = True

    def assemble(self, direction: tuple) -> bytes:
        segs = self.segs.get(direction)
        if not segs:
            return b""
        segs.sort(key=lambda s: s[0])
        out = bytearray()
        next_seq = self.base.get(direction, segs[0][0])
        # If we never saw the SYN, anchor on the lowest seq present.
        if direction not in self.base:
            next_seq = segs[0][0]
        for seq, payload in segs:
            if seq == next_seq:
                out += payload
                next_seq = (seq + len(payload)) & 0xFFFFFFFF
            elif seq > next_seq:
                # gap (missing segment) - record what we have, then jump.
                out += payload
                next_seq = (seq + len(payload)) & 0xFFFFFFFF
            else:
                # overlap / retransmit: append only the new tail if any
                overlap = next_seq - seq
                if overlap < len(payload):
                    out += payload[overlap:]
                    next_seq = (seq + len(payload)) & 0xFFFFFFFF
        return bytes(out)

    def directions(self):
        return list(self.segs.keys())
