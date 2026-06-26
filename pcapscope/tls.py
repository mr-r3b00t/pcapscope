"""TLS handshake analysis for encrypted services (LDAPS 636/3269, HTTPS 443,
TDS-over-TLS, etc.).

The payload is encrypted, but the early handshake is not: we extract the
client's SNI, the negotiated TLS version and cipher, and - crucially for LDAPS
troubleshooting - the **server certificate** (subject CN, SANs, issuer,
validity). Cert problems (wrong name, expired, untrusted issuer) are the most
common LDAPS failure, and they're all visible here.

X.509 parsing reuses the project's DER decoder; cleartext certs are available in
TLS 1.2 (in TLS 1.3 the certificate is encrypted, so only SNI/version show).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import asn1

TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
                0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}

OID_CN = bytes([0x55, 0x04, 0x03])        # 2.5.4.3  commonName
OID_O = bytes([0x55, 0x04, 0x0A])         # 2.5.4.10 organizationName
OID_SAN = bytes([0x55, 0x1D, 0x11])       # 2.5.29.17 subjectAltName


@dataclass
class TlsInfo:
    is_tls: bool = False
    sni: str = ""
    client_version: str = ""
    server_version: str = ""
    cipher: int = 0
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_org: str = ""
    cert_sans: list[str] = field(default_factory=list)
    not_before: str = ""
    not_after: str = ""
    truncated: bool = False        # handshake clipped (e.g. small snaplen)

    @property
    def has_cert(self) -> bool:
        return bool(self.cert_subject or self.cert_sans)


def looks_like_tls(buf: bytes) -> bool:
    # handshake record (0x16) with a 0x03xx version
    return len(buf) >= 3 and buf[0] == 0x16 and buf[1] == 0x03


def _handshake_blob(stream: bytes) -> tuple[bytes, bool]:
    """Concatenate cleartext TLS handshake fragments. Returns (blob, truncated).

    Stops at the first record whose declared length exceeds the captured bytes
    (e.g. a snaplen-clipped ServerHello) rather than reading past the capture
    into adjacent data - which would otherwise yield garbage cipher/version.
    """
    out = bytearray()
    truncated = False
    off, n = 0, len(stream)
    guard = 0
    while off + 5 <= n and guard < 4096:
        guard += 1
        ctype = stream[off]
        ver_major = stream[off + 1]
        rlen = int.from_bytes(stream[off + 3:off + 5], "big")
        if ver_major != 0x03 or ctype not in (20, 21, 22, 23) or rlen == 0 or rlen > 16640:
            break
        if ctype == 23:        # application data => encrypted from here on
            break
        avail = n - (off + 5)
        if rlen > avail:       # record clipped by the capture (snaplen)
            truncated = True
            if ctype == 22:
                out += stream[off + 5: off + 5 + avail]
            break
        if ctype == 22:        # handshake
            out += stream[off + 5: off + 5 + rlen]
        off += 5 + rlen
    return bytes(out), truncated


def _messages(blob: bytes):
    i, n = 0, len(blob)
    while i + 4 <= n:
        mtype = blob[i]
        mlen = int.from_bytes(blob[i + 1:i + 4], "big")
        body = blob[i + 4:i + 4 + mlen]
        trunc = len(body) < mlen
        yield mtype, body, trunc
        if trunc:
            return
        i += 4 + mlen


def analyze_stream(client_bytes: bytes, server_bytes: bytes) -> TlsInfo | None:
    if not (looks_like_tls(client_bytes) or looks_like_tls(server_bytes)):
        return None
    info = TlsInfo(is_tls=True)
    cblob, ctrunc = _handshake_blob(client_bytes)
    for mtype, body, mtrunc in _messages(cblob):
        if mtype == 1:
            _client_hello(body, info)
        info.truncated = info.truncated or mtrunc
    sblob, strunc = _handshake_blob(server_bytes)
    for mtype, body, mtrunc in _messages(sblob):
        if mtype == 2:
            _server_hello(body, info)
        elif mtype == 11:
            _certificate(body, info)
        info.truncated = info.truncated or mtrunc
    info.truncated = info.truncated or ctrunc or strunc
    return info


def _client_hello(b: bytes, info: TlsInfo) -> None:
    try:
        info.client_version = TLS_VERSIONS.get(int.from_bytes(b[0:2], "big"), "")
        off = 2 + 32                       # version + random
        sid_len = b[off]; off += 1 + sid_len
        cs_len = int.from_bytes(b[off:off + 2], "big"); off += 2 + cs_len
        comp_len = b[off]; off += 1 + comp_len
        if off + 2 > len(b):
            return
        ext_total = int.from_bytes(b[off:off + 2], "big"); off += 2
        end = min(len(b), off + ext_total)
        while off + 4 <= end:
            etype = int.from_bytes(b[off:off + 2], "big")
            elen = int.from_bytes(b[off + 2:off + 4], "big")
            edata = b[off + 4:off + 4 + elen]
            off += 4 + elen
            if etype == 0:                 # server_name
                info.sni = _parse_sni(edata)
    except (IndexError, ValueError):
        pass


def _parse_sni(ext: bytes) -> str:
    try:
        # ServerNameList: list_len(2), then entries type(1) len(2) name
        if len(ext) < 5:
            return ""
        off = 2
        if ext[off] != 0:                  # host_name type
            return ""
        nlen = int.from_bytes(ext[off + 1:off + 3], "big")
        return ext[off + 3:off + 3 + nlen].decode("idna", "replace") if nlen else ""
    except (IndexError, ValueError, UnicodeError):
        try:
            return ext[5:].decode("latin-1", "replace")
        except Exception:
            return ""


def _server_hello(b: bytes, info: TlsInfo) -> None:
    try:
        legacy = int.from_bytes(b[0:2], "big")
        off = 2 + 32
        sid_len = b[off]; off += 1 + sid_len
        if off + 2 <= len(b):
            info.cipher = int.from_bytes(b[off:off + 2], "big")
        else:
            info.truncated = True          # ServerHello clipped before the cipher
        off += 2
        off += 1                           # compression
        ver = legacy
        if off + 2 <= len(b):
            ext_total = int.from_bytes(b[off:off + 2], "big"); off += 2
            end = min(len(b), off + ext_total)
            while off + 4 <= end:
                etype = int.from_bytes(b[off:off + 2], "big")
                elen = int.from_bytes(b[off + 2:off + 4], "big")
                edata = b[off + 4:off + 4 + elen]
                off += 4 + elen
                if etype == 43 and len(edata) >= 2:   # supported_versions
                    ver = int.from_bytes(edata[:2], "big")
        info.server_version = TLS_VERSIONS.get(ver, TLS_VERSIONS.get(legacy, f"0x{ver:04x}"))
    except (IndexError, ValueError):
        pass


def _certificate(b: bytes, info: TlsInfo) -> None:
    try:
        # Certificate: certificate_list_len(3), then cert_len(3)+cert_der ...
        total = int.from_bytes(b[0:3], "big")
        off = 3
        if off + 3 > len(b):
            return
        clen = int.from_bytes(b[off:off + 3], "big"); off += 3
        cert_der = b[off:off + clen]
        _parse_cert(cert_der, info)
    except (IndexError, ValueError):
        pass


def _parse_cert(der: bytes, info: TlsInfo) -> None:
    cert = asn1.parse_one(der)
    if cert is None or not cert.children:
        return
    tbs = cert.children[0]                  # TBSCertificate SEQUENCE
    kids = tbs.children
    # optional [0] version shifts the field positions
    base = 1 if (kids and kids[0].cls == asn1.CLASS_CONTEXT and kids[0].num == 0) else 0
    # order: [ver?] serial, sigAlg, issuer, validity, subject, spki, ...
    try:
        issuer = kids[base + 2]
        validity = kids[base + 3]
        subject = kids[base + 4]
        info.cert_issuer = _name_attr(issuer, OID_CN)
        info.cert_subject = _name_attr(subject, OID_CN)
        info.cert_org = _name_attr(subject, OID_O)
        if validity and len(validity.children) >= 2:
            info.not_before = validity.children[0].as_str()
            info.not_after = validity.children[1].as_str()
    except IndexError:
        pass
    # SAN extension lives in [3] extensions
    for c in kids:
        if c.cls == asn1.CLASS_CONTEXT and c.num == 3:
            info.cert_sans = _extract_sans(c)
            break


def _name_attr(name_node, oid: bytes) -> str:
    """Return the first attribute value matching *oid* in an X.509 Name."""
    if name_node is None:
        return ""
    for rdn in name_node.children:         # SET OF
        for atv in rdn.children:           # SEQUENCE {type, value}
            if len(atv.children) >= 2 and atv.children[0].content == oid:
                return atv.children[1].as_str()
    return ""


def _extract_sans(ext_ctx) -> list[str]:
    sans: list[str] = []
    # [3] -> SEQUENCE OF Extension {extnID OID, critical?, extnValue OCTET STRING}
    seq = ext_ctx.children[0] if ext_ctx.children else None
    if seq is None:
        return sans
    for ext in seq.children:
        if not ext.children:
            continue
        if ext.children[0].content == OID_SAN:
            octet = ext.children[-1]       # extnValue OCTET STRING
            names = asn1.parse_one(octet.content)
            if names is None:
                continue
            for gn in names.children:      # GeneralName, dNSName = [2] IA5String
                if gn.cls == asn1.CLASS_CONTEXT and gn.num == 2:
                    try:
                        sans.append(gn.content.decode("ascii", "replace"))
                    except Exception:
                        pass
    return sans
