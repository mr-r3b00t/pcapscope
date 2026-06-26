"""Capture file reader and validator for classic PCAP and PCAPNG formats.

Pure standard library. Yields decoded link-layer frames with timestamps and
collects validation findings (truncation, corruption, format issues) along the
way so callers can both *validate* and *analyze* in a single pass.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterator


# ---------------------------------------------------------------------------
# Link-layer types (DLT / LINKTYPE) we know how to peel.
# ---------------------------------------------------------------------------
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_RAW_ALT1 = 12
LINKTYPE_RAW_ALT2 = 14
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LOOP = 108

LINKTYPE_NAMES = {
    0: "NULL/BSD-loopback",
    1: "Ethernet",
    12: "Raw-IP",
    14: "Raw-IP",
    101: "Raw-IP",
    108: "OpenBSD-loopback",
    113: "Linux-cooked (SLL)",
    276: "Linux-cooked-v2 (SLL2)",
    228: "Raw-IPv4",
    229: "Raw-IPv6",
    127: "802.11-radiotap",
}

PCAP_MAGIC_LE = 0xA1B2C3D4          # little-endian, microsecond
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D       # little-endian, nanosecond
PCAP_MAGIC_NS_BE = 0x4D3CB2A1
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D


@dataclass
class Packet:
    """One captured frame, ready to hand to the layer decoders."""

    index: int                 # 0-based ordinal in the file
    ts: float                  # epoch seconds (float), 0.0 if unknown
    incl_len: int              # bytes actually captured
    orig_len: int              # bytes on the wire
    linktype: int              # how to peel the link layer
    data: bytes                # the captured bytes (length == incl_len)

    @property
    def truncated(self) -> bool:
        return self.orig_len > self.incl_len


@dataclass
class CaptureInfo:
    """File-level metadata + validation findings."""

    path: str
    fmt: str = "unknown"                # "pcap" | "pcapng" | "unknown"
    byte_order: str = ""               # "little" | "big"
    version: str = ""
    snaplen: int = 0
    linktypes: list[int] = field(default_factory=list)
    ts_resolution: str = ""            # human description
    os_info: str = ""                  # SHB os/app options if present (pcapng)
    app_info: str = ""

    packet_count: int = 0
    truncated_count: int = 0           # frames where orig_len > incl_len
    snap_truncated_count: int = 0      # frames clipped to snaplen
    total_bytes_on_wire: int = 0
    total_bytes_captured: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    min_frame: int | None = None
    max_frame: int | None = None

    errors: list[str] = field(default_factory=list)     # fatal / structural
    warnings: list[str] = field(default_factory=list)    # non-fatal anomalies

    @property
    def duration(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return max(0.0, self.last_ts - self.first_ts)

    @property
    def avg_frame(self) -> float:
        if not self.packet_count:
            return 0.0
        return self.total_bytes_on_wire / self.packet_count

    @property
    def avg_rate_bps(self) -> float:
        d = self.duration
        if d <= 0:
            return 0.0
        return (self.total_bytes_on_wire * 8) / d

    def linktype_names(self) -> list[str]:
        return [LINKTYPE_NAMES.get(lt, f"DLT-{lt}") for lt in self.linktypes]


class CaptureError(Exception):
    """Raised when a file cannot be recognised as a capture at all."""


class CaptureReader:
    """Reads a PCAP or PCAPNG file and yields :class:`Packet` objects.

    Usage::

        reader = CaptureReader(path)
        for pkt in reader:
            ...
        info = reader.info   # populated as packets are consumed
    """

    def __init__(self, path: str):
        self.path = path
        self.info = CaptureInfo(path=path)
        with open(path, "rb") as fh:
            self._raw = fh.read()
        if not self._raw:
            raise CaptureError("file is empty (0 bytes)")
        self._detect()

    # -- format detection ---------------------------------------------------
    def _detect(self) -> None:
        if len(self._raw) < 4:
            raise CaptureError("file too small to contain a capture header")
        head = self._raw[:4]
        # PCAPNG section header block type is byte-order independent here.
        if struct.unpack(">I", head)[0] == PCAPNG_SHB:
            self.info.fmt = "pcapng"
            return
        # Classic pcap: the magic is written in the writer's native byte order,
        # so the on-disk byte sequence tells us both endianness and ts units.
        # A little-endian (microsecond) file therefore starts D4 C3 B2 A1.
        pcap_magics = {
            b"\xd4\xc3\xb2\xa1": ("<", False),   # little-endian, microsecond
            b"\xa1\xb2\xc3\xd4": (">", False),   # big-endian,    microsecond
            b"\x4d\x3c\xb2\xa1": ("<", True),    # little-endian, nanosecond
            b"\xa1\xb2\x3c\x4d": (">", True),    # big-endian,    nanosecond
        }
        if head in pcap_magics:
            self._endian, self._pcap_ns = pcap_magics[head]
            self.info.fmt = "pcap"
            self.info.byte_order = "little" if self._endian == "<" else "big"
            return
        magic = struct.unpack(">I", head)[0]
        raise CaptureError(
            f"unrecognised magic 0x{magic:08x} - not a pcap/pcapng file "
            f"(maybe gzip-compressed or a different capture format)"
        )

    # -- iteration ----------------------------------------------------------
    def __iter__(self) -> Iterator[Packet]:
        if self.info.fmt == "pcap":
            yield from self._iter_pcap()
        elif self.info.fmt == "pcapng":
            yield from self._iter_pcapng()
        else:  # pragma: no cover - guarded by _detect
            raise CaptureError("unknown format")

    # -- classic pcap -------------------------------------------------------
    def _iter_pcap(self) -> Iterator[Packet]:
        raw = self._raw
        e = self._endian
        if len(raw) < 24:
            self.info.errors.append("truncated global header (<24 bytes)")
            return
        (_magic, vmaj, vmin, _tz, _sig, snaplen, network) = struct.unpack(
            e + "IHHiIII", raw[:24]
        )
        self.info.version = f"{vmaj}.{vmin}"
        self.info.snaplen = snaplen
        self.info.linktypes = [network]
        self.info.ts_resolution = "nanosecond" if self._pcap_ns else "microsecond"
        ts_div = 1_000_000_000.0 if self._pcap_ns else 1_000_000.0

        off = 24
        idx = 0
        n = len(raw)
        while off + 16 <= n:
            ts_sec, ts_frac, incl, orig = struct.unpack(e + "IIII", raw[off : off + 16])
            off += 16
            if incl > 0xFFFFFF or incl > (snaplen + 65536 if snaplen else 0x40000):
                # incl_len wildly out of range -> structural corruption
                self.info.errors.append(
                    f"frame {idx}: implausible captured length {incl} "
                    f"(snaplen {snaplen}); file likely corrupt at offset {off-16}"
                )
                break
            avail = n - off
            data = raw[off : off + incl]
            if incl > avail:
                self.info.warnings.append(
                    f"frame {idx}: captured length {incl} exceeds remaining "
                    f"{avail} bytes - file truncated mid-frame"
                )
                # still emit what we have for best-effort decode
                pkt = Packet(idx, ts_sec + ts_frac / ts_div, len(data), orig, network, data)
                self._account(pkt, snaplen)
                yield pkt
                break
            off += incl
            pkt = Packet(idx, ts_sec + ts_frac / ts_div, incl, orig, network, data)
            self._account(pkt, snaplen)
            yield pkt
            idx += 1
        else:
            if off != n:
                self.info.warnings.append(
                    f"{n - off} trailing byte(s) after last full frame "
                    f"(partial record at EOF)"
                )

    # -- pcapng -------------------------------------------------------------
    def _iter_pcapng(self) -> Iterator[Packet]:
        raw = self._raw
        n = len(raw)
        off = 0
        idx = 0
        endian = "<"          # set per section header
        interfaces: list[dict] = []   # per-interface {linktype, tsresol, tsoffset}

        while off + 8 <= n:
            btype, blen = struct.unpack(endian + "II", raw[off : off + 8])
            # Section Header Block resets endianness and interface table.
            if btype == PCAPNG_SHB:
                if off + 12 > n:
                    self.info.errors.append("truncated section header block")
                    break
                bom = struct.unpack("<I", raw[off + 8 : off + 12])[0]
                if bom == PCAPNG_BYTE_ORDER_MAGIC:
                    endian = "<"
                    self.info.byte_order = "little"
                else:
                    endian = ">"
                    self.info.byte_order = "big"
                btype, blen = struct.unpack(endian + "II", raw[off : off + 8])
            if blen < 12 or off + blen > n:
                self.info.errors.append(
                    f"block at offset {off}: invalid/truncated length {blen} "
                    f"(remaining {n - off}) - capture corrupt or cut short"
                )
                break
            body = raw[off + 8 : off + blen - 4]
            trailer = struct.unpack(endian + "I", raw[off + blen - 4 : off + blen])[0]
            if trailer != blen:
                self.info.warnings.append(
                    f"block at offset {off}: trailing length {trailer} != "
                    f"leading {blen} (block boundary mismatch)"
                )

            if btype == PCAPNG_SHB:
                self._parse_shb(body, endian)
            elif btype == 0x00000001:  # Interface Description Block
                interfaces.append(self._parse_idb(body, endian))
            elif btype == 0x00000006:  # Enhanced Packet Block
                pkt = self._parse_epb(body, endian, interfaces, idx)
                if pkt is not None:
                    self._account(pkt, self.info.snaplen)
                    yield pkt
                    idx += 1
            elif btype == 0x00000003:  # Simple Packet Block
                pkt = self._parse_spb(body, endian, interfaces, idx)
                if pkt is not None:
                    self._account(pkt, self.info.snaplen)
                    yield pkt
                    idx += 1
            elif btype == 0x00000002:  # obsolete Packet Block
                pkt = self._parse_obsolete_pb(body, endian, interfaces, idx)
                if pkt is not None:
                    self._account(pkt, self.info.snaplen)
                    yield pkt
                    idx += 1
            # other block types (NRB, ISB, DSB, custom) are skipped silently.
            off += blen

        if not interfaces and idx == 0 and not self.info.errors:
            self.info.warnings.append("no interface/packet blocks found in pcapng")

    def _parse_shb(self, body: bytes, endian: str) -> None:
        if len(body) < 16:
            return
        vmaj, vmin = struct.unpack(endian + "HH", body[4:8])
        self.info.version = f"{vmaj}.{vmin}"
        # options follow the 16-byte fixed area
        for code, val in self._iter_options(body[16:], endian):
            text = self._opt_text(val)
            if code == 2:
                self.info.os_info = text
            elif code == 3:
                self.info.app_info = text
            elif code == 4 and not self.info.os_info:
                self.info.os_info = text

    def _parse_idb(self, body: bytes, endian: str) -> dict:
        iface = {"linktype": 0, "tsresol": 1e-6, "tsoffset": 0}
        if len(body) >= 8:
            linktype, _reserved, snaplen = struct.unpack(endian + "HHI", body[:8])
            iface["linktype"] = linktype
            if linktype not in self.info.linktypes:
                self.info.linktypes.append(linktype)
            if snaplen and snaplen > self.info.snaplen:
                self.info.snaplen = snaplen
            for code, val in self._iter_options(body[8:], endian):
                if code == 9 and len(val) >= 1:  # if_tsresol
                    b = val[0]
                    if b & 0x80:
                        iface["tsresol"] = 2.0 ** -(b & 0x7F)
                    else:
                        iface["tsresol"] = 10.0 ** -(b & 0x7F)
                elif code == 14 and len(val) >= 8:  # if_tsoffset
                    iface["tsoffset"] = struct.unpack(endian + "q", val[:8])[0]
        if not self.info.ts_resolution:
            self.info.ts_resolution = "nanosecond" if iface["tsresol"] <= 1e-9 else "microsecond"
        return iface

    def _parse_epb(self, body, endian, interfaces, idx) -> Packet | None:
        if len(body) < 20:
            self.info.warnings.append(f"frame {idx}: short enhanced packet block")
            return None
        iface_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(endian + "IIIII", body[:20])
        data = body[20 : 20 + cap_len]
        iface = interfaces[iface_id] if iface_id < len(interfaces) else {"linktype": 1, "tsresol": 1e-6, "tsoffset": 0}
        ts = ((ts_hi << 32) | ts_lo) * iface["tsresol"] + iface["tsoffset"]
        return Packet(idx, ts, len(data), orig_len, iface["linktype"], data)

    def _parse_spb(self, body, endian, interfaces, idx) -> Packet | None:
        if len(body) < 4:
            return None
        (orig_len,) = struct.unpack(endian + "I", body[:4])
        iface = interfaces[0] if interfaces else {"linktype": 1}
        # captured length = block-derived; SPB stores full body after the field
        data = body[4:]
        return Packet(idx, 0.0, len(data), orig_len, iface.get("linktype", 1), data)

    def _parse_obsolete_pb(self, body, endian, interfaces, idx) -> Packet | None:
        if len(body) < 20:
            return None
        iface_id, _drops, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(
            endian + "HHIIII", body[:20]
        )
        data = body[20 : 20 + cap_len]
        iface = interfaces[iface_id] if iface_id < len(interfaces) else {"linktype": 1, "tsresol": 1e-6, "tsoffset": 0}
        ts = ((ts_hi << 32) | ts_lo) * iface.get("tsresol", 1e-6) + iface.get("tsoffset", 0)
        return Packet(idx, ts, len(data), orig_len, iface["linktype"], data)

    @staticmethod
    def _iter_options(buf: bytes, endian: str):
        off = 0
        n = len(buf)
        while off + 4 <= n:
            code, length = struct.unpack(endian + "HH", buf[off : off + 4])
            off += 4
            if code == 0:  # opt_endofopt
                break
            val = buf[off : off + length]
            off += length
            off += (-length) % 4  # pad to 32-bit boundary
            yield code, val

    @staticmethod
    def _opt_text(val: bytes) -> str:
        try:
            return val.decode("utf-8", "replace").rstrip("\x00")
        except Exception:
            return val.hex()

    # -- accounting ---------------------------------------------------------
    def _account(self, pkt: Packet, snaplen: int) -> None:
        info = self.info
        info.packet_count += 1
        info.total_bytes_on_wire += pkt.orig_len
        info.total_bytes_captured += pkt.incl_len
        if pkt.truncated:
            info.truncated_count += 1
            if snaplen and pkt.incl_len >= snaplen:
                info.snap_truncated_count += 1
        if pkt.ts:
            if info.first_ts is None or pkt.ts < info.first_ts:
                info.first_ts = pkt.ts
            if info.last_ts is None or pkt.ts > info.last_ts:
                info.last_ts = pkt.ts
        fl = pkt.orig_len
        if info.min_frame is None or fl < info.min_frame:
            info.min_frame = fl
        if info.max_frame is None or fl > info.max_frame:
            info.max_frame = fl


def read_packets(path: str) -> tuple[list[Packet], CaptureInfo]:
    """Convenience: read an entire capture into memory.

    Returns ``(packets, info)``. ``info`` carries validation findings even when
    the file is partially corrupt (best-effort decode of what is readable).
    """
    reader = CaptureReader(path)
    packets = list(reader)
    return packets, reader.info
