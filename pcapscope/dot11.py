"""802.11 (Wi-Fi) + WPA/WPA2 handshake analysis.

Handles radiotap- and raw-802.11-framed captures: pulls SSIDs from beacons/probe
responses, finds the EAPOL-Key 4-way handshake, and builds hashcat **-m 22000**
hashes - both the **PMKID** (from message 1, no full handshake needed) and the
**EAPOL** M1+M2 form.

Pure standard library; defensive against short/garbled frames.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

# capture link types that carry 802.11
LINKTYPE_IEEE80211 = 105
LINKTYPE_RADIOTAP = 127
LINKTYPE_AVS = 163
LINKTYPE_PPI = 192
WIFI_LINKTYPES = {105, 127, 163, 192}


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def strip_radiotap(data: bytes, linktype: int) -> bytes:
    """Return the bare 802.11 MAC frame for the given link type."""
    if linktype == LINKTYPE_RADIOTAP:
        if len(data) < 4:
            return b""
        rtlen = struct.unpack("<H", data[2:4])[0]
        return data[rtlen:] if rtlen <= len(data) else b""
    if linktype == LINKTYPE_PPI:
        if len(data) < 8:
            return b""
        plen = struct.unpack("<H", data[2:4])[0]
        return data[plen:] if plen <= len(data) else b""
    if linktype == LINKTYPE_AVS:
        return data[64:] if len(data) > 64 else b""
    return data                                       # raw 802.11


@dataclass
class Dot11:
    ftype: int = 0
    subtype: int = 0
    bssid: bytes = b""
    sta: bytes = b""
    tods: bool = False
    fromds: bool = False
    hdr_len: int = 0
    body: bytes = b""


def parse(frame: bytes) -> Dot11 | None:
    if len(frame) < 24:
        return None
    fc = struct.unpack("<H", frame[0:2])[0]
    d = Dot11()
    d.ftype = (fc >> 2) & 0x3
    d.subtype = (fc >> 4) & 0xF
    d.tods = bool(fc & 0x0100)
    d.fromds = bool(fc & 0x0200)
    a1, a2, a3 = frame[4:10], frame[10:16], frame[16:22]
    hdr = 24
    if d.tods and d.fromds:
        hdr = 30
    if d.ftype == 2 and (d.subtype & 0x8):            # QoS data
        hdr += 2
    d.hdr_len = hdr
    # addressing: derive BSSID + the STA (non-AP)
    if d.tods and not d.fromds:
        d.bssid, d.sta = a1, a2
    elif d.fromds and not d.tods:
        d.bssid, d.sta = a2, a1
    else:
        d.bssid, d.sta = a3, a2
    d.body = frame[hdr:]
    return d


def beacon_ssid(d: Dot11) -> str | None:
    """SSID from a beacon (subtype 8) or probe response (5)."""
    if d.ftype != 0 or d.subtype not in (5, 8):
        return None
    tags = d.body[12:]                                # skip fixed params (12 bytes)
    i = 0
    while i + 2 <= len(tags):
        num, ln = tags[i], tags[i + 1]
        val = tags[i + 2:i + 2 + ln]
        if num == 0:                                  # SSID
            return val.decode("utf-8", "replace") if val else ""
        i += 2 + ln
    return None


# ---------------------------------------------------------------------------
# EAPOL-Key (WPA 4-way handshake)
# ---------------------------------------------------------------------------
SNAP_EAPOL = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"


@dataclass
class EapolKey:
    msg: int = 0                  # 1..4
    key_info: int = 0
    replay: bytes = b""
    nonce: bytes = b""
    mic: bytes = b""
    key_data: bytes = b""
    eapol: bytes = b""            # full EAPOL frame (header + key body)
    mic_offset: int = 0          # offset of the 16-byte MIC within eapol
    pmkid: bytes = b""


def extract_eapol_key(d: Dot11) -> EapolKey | None:
    body = d.body
    if d.ftype != 2 or not body.startswith(SNAP_EAPOL):
        return None
    eapol = body[8:]                                  # after LLC/SNAP
    if len(eapol) < 4 or eapol[1] != 3:               # EAPOL type 3 = Key
        return None
    kb = eapol[4:]
    if len(kb) < 95:
        return None
    k = EapolKey()
    k.key_info = struct.unpack("!H", kb[1:3])[0]
    k.replay = kb[5:13]
    k.nonce = kb[13:45]
    k.mic = kb[77:93]
    kd_len = struct.unpack("!H", kb[93:95])[0]
    k.key_data = kb[95:95 + kd_len]
    k.eapol = eapol[:4 + 95 + kd_len]
    k.mic_offset = 4 + 77
    info = k.key_info
    ack = bool(info & 0x0080)
    mic_p = bool(info & 0x0100)
    install = bool(info & 0x0040)
    secure = bool(info & 0x0200)
    zero_nonce = (k.nonce == b"\x00" * 32)
    if ack and not mic_p:
        k.msg = 1
    elif ack and mic_p and install:
        k.msg = 3
    elif mic_p and not ack and (secure or zero_nonce):
        k.msg = 4
    elif mic_p and not ack:
        k.msg = 2
    # PMKID KDE in M1 key data: ... 00 0F AC 04 <pmkid 16>
    idx = k.key_data.find(b"\x00\x0f\xac\x04")
    if idx >= 0 and len(k.key_data) >= idx + 4 + 16:
        pmkid = k.key_data[idx + 4:idx + 20]
        if pmkid != b"\x00" * 16:
            k.pmkid = pmkid
    return k


def eapol_hash(mic, ap, sta, essid, anonce, eapol_m2_zeroed) -> str:
    return (f"WPA*02*{mic.hex()}*{ap.hex()}*{sta.hex()}*{essid.encode().hex()}*"
            f"{anonce.hex()}*{eapol_m2_zeroed.hex()}*00")


def pmkid_hash(pmkid, ap, sta, essid) -> str:
    return f"WPA*01*{pmkid.hex()}*{ap.hex()}*{sta.hex()}*{essid.encode().hex()}***"


def zero_mic(k: EapolKey) -> bytes:
    return k.eapol[:k.mic_offset] + b"\x00" * 16 + k.eapol[k.mic_offset + 16:]
