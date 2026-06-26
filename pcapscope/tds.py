"""MSSQL TDS protocol analysis (pre-login + Login7).

Surfaces what matters when troubleshooting SQL Server authentication:

* whether the connection negotiated **encryption** (ENCRYPT_OFF means the login
  and data are on the wire in clear),
* SQL logins (username + the trivially-reversible Login7 password obfuscation),
* whether the client used **integrated security** (Windows auth -> NTLM/Kerberos
  in the SSPI field, which the NTLM/Kerberos analyzers then pick up),
* app name, host name, server name and target database for context.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# TDS message types
TDS_SQL_BATCH = 0x01
TDS_RPC = 0x03
TDS_RESPONSE = 0x04
TDS_LOGIN7 = 0x10
TDS_SSPI = 0x11
TDS_PRELOGIN = 0x12

ENCRYPTION = {
    0x00: "ENCRYPT_OFF (only login encrypted, data clear)",
    0x01: "ENCRYPT_ON (whole session encrypted)",
    0x02: "ENCRYPT_NOT_SUP (no encryption)",
    0x03: "ENCRYPT_REQ (encryption required)",
}

PRELOGIN_OPT = {0: "VERSION", 1: "ENCRYPTION", 2: "INSTOPT", 3: "THREADID", 4: "MARS", 5: "TRACEID", 6: "FEDAUTHREQUIRED"}


@dataclass
class TdsLogin:
    hostname: str = ""
    username: str = ""
    password: str = ""
    appname: str = ""
    servername: str = ""
    database: str = ""
    client_mac: str = ""
    integrated_security: bool = False
    sspi_present: bool = False
    tds_version: str = ""

    @property
    def auth_type(self) -> str:
        if self.integrated_security or self.sspi_present:
            return "Windows/Integrated (NTLM or Kerberos)"
        if self.username:
            return "SQL Server authentication (username/password)"
        return "unknown"


@dataclass
class TdsInfo:
    encryption: str = ""           # from pre-login (server response preferred)
    encryption_raw: int = -1
    login: TdsLogin | None = None
    saw_prelogin: bool = False
    saw_login7: bool = False


def iter_messages(stream: bytes):
    """Reassemble TDS messages from a directional byte stream.

    Yields ``(msg_type, body)`` where *body* is the concatenated data of all
    packets up to and including the one with the EOM status bit.
    """
    off = 0
    n = len(stream)
    cur_type = None
    buf = bytearray()
    guard = 0
    while off + 8 <= n and guard < 4096:
        guard += 1
        mtype = stream[off]
        status = stream[off + 1]
        length = struct.unpack("!H", stream[off + 2 : off + 4])[0]
        if length < 8 or off + length > n:
            break
        body = stream[off + 8 : off + length]
        if cur_type is None:
            cur_type = mtype
        buf += body
        if status & 0x01:  # EOM
            yield cur_type, bytes(buf)
            buf = bytearray()
            cur_type = None
        off += length
    if cur_type is not None and buf:
        yield cur_type, bytes(buf)


def parse_prelogin(body: bytes) -> int:
    """Return the ENCRYPTION option value, or -1 if absent."""
    off = 0
    n = len(body)
    options = []
    while off + 5 <= n:
        token = body[off]
        if token == 0xFF:
            break
        opt_off, opt_len = struct.unpack("!HH", body[off + 1 : off + 5])
        options.append((token, opt_off, opt_len))
        off += 5
    for token, opt_off, opt_len in options:
        if token == 1 and opt_off < n and opt_len >= 1:  # ENCRYPTION
            return body[opt_off]
    return -1


def _read_str(body: bytes, ib: int, cch: int) -> str:
    raw = body[ib : ib + cch * 2]
    try:
        return raw.decode("utf-16-le", "replace")
    except Exception:
        return raw.hex()


def _decode_password(body: bytes, ib: int, cch: int) -> str:
    raw = body[ib : ib + cch * 2]
    out = bytearray()
    for b in raw:
        t = b ^ 0xA5
        out.append(((t & 0x0F) << 4) | ((t & 0xF0) >> 4))
    try:
        return bytes(out).decode("utf-16-le", "replace")
    except Exception:
        return bytes(out).hex()


def parse_login7(body: bytes) -> TdsLogin | None:
    # body begins with the Login7 record (Length first). Offsets in the
    # OffsetLength block are relative to the start of this record.
    if len(body) < 94:
        return None
    login = TdsLogin()
    try:
        tds_ver = struct.unpack("<I", body[4:8])[0]
        login.tds_version = f"0x{tds_ver:08x}"
        opt2 = body[37]
        login.integrated_security = bool(opt2 & 0x80)  # fIntSecurity
        # OffsetLength block starts at byte 36? Per MS-TDS the fixed header is
        # 36 bytes, then OptionFlags etc. The variable OffsetLength block
        # starts at offset 36. Field pairs are (offset:2, length:2).
        base = 36
        def pair(i):
            o = base + i * 4
            return struct.unpack("<HH", body[o : o + 4])

        ib_host, cch_host = pair(0)
        ib_user, cch_user = pair(1)
        ib_pass, cch_pass = pair(2)
        ib_app, cch_app = pair(3)
        ib_srv, cch_srv = pair(4)
        # pair(5) = extension/unused
        # pair(6) = CltIntName
        # pair(7) = Language
        ib_db, cch_db = pair(8)
        # ClientID (MAC) is 6 bytes right after pair(8)
        cid_off = base + 9 * 4
        mac = body[cid_off : cid_off + 6]
        if len(mac) == 6:
            login.client_mac = ":".join(f"{x:02x}" for x in mac)
        ib_sspi, cb_sspi = struct.unpack("<HH", body[cid_off + 6 : cid_off + 10])

        login.hostname = _read_str(body, ib_host, cch_host)
        login.username = _read_str(body, ib_user, cch_user)
        login.password = _decode_password(body, ib_pass, cch_pass)
        login.appname = _read_str(body, ib_app, cch_app)
        login.servername = _read_str(body, ib_srv, cch_srv)
        login.database = _read_str(body, ib_db, cch_db)
        login.sspi_present = cb_sspi > 0
    except (struct.error, IndexError):
        pass
    return login


def analyze_stream(client_bytes: bytes, server_bytes: bytes) -> TdsInfo | None:
    """Analyze both directions of a TDS connection. Returns ``None`` if no TDS."""
    info = TdsInfo()
    found = False
    enc_client = enc_server = -1
    for stream, is_server in ((client_bytes, False), (server_bytes, True)):
        for mtype, body in iter_messages(stream):
            if mtype == TDS_PRELOGIN:
                found = True
                info.saw_prelogin = True
                ev = parse_prelogin(body)
                if ev >= 0:
                    if is_server:
                        enc_server = ev
                    else:
                        enc_client = ev
            elif mtype == TDS_LOGIN7:
                found = True
                info.saw_login7 = True
                lg = parse_login7(body)
                if lg is not None:
                    info.login = lg
    enc = enc_server if enc_server >= 0 else enc_client
    if enc >= 0:
        info.encryption_raw = enc
        info.encryption = ENCRYPTION.get(enc, f"unknown({enc})")
    return info if found else None
