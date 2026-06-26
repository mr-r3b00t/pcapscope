#!/usr/bin/env python3
"""Generate a synthetic .pcap exercising every analyzer.

Crafts on-wire-correct payloads for Kerberos (AS-REQ/AS-REP/KRB-ERROR with weak
+ strong etypes), NTLMv2 over SMB, MSSQL/TDS (pre-login ENCRYPT_OFF + SQL
Login7), an LDAP cleartext simple bind, and HTTP Basic auth - plus a refused TCP
connection. Useful as a self-test and demo fixture.

    python tools/make_sample.py sample.pcap
"""

from __future__ import annotations

import base64
import hashlib
import struct
import sys

# --------------------------------------------------------------------------- DER
def L(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + L(len(content)) + content


def D_INT(v: int) -> bytes:
    if v == 0:
        return tlv(0x02, b"\x00")
    b = v.to_bytes((v.bit_length() + 8) // 8, "big", signed=True)
    return tlv(0x02, b)


def D_ENUM(v: int) -> bytes:
    return tlv(0x0A, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True))


def D_GENSTR(s: str) -> bytes:
    return tlv(0x1B, s.encode())


def D_GENTIME(s: str) -> bytes:
    return tlv(0x18, s.encode())


def D_OCTET(b: bytes) -> bytes:
    return tlv(0x04, b)


def D_SEQ(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def D_BITSTR(b: bytes) -> bytes:
    return tlv(0x03, b"\x00" + b)


def ctx(n: int, content: bytes, constructed=True) -> bytes:
    tag = (0xA0 if constructed else 0x80) | n
    return tlv(tag, content)


def app(n: int, content: bytes) -> bytes:
    return tlv(0x60 | n, content)


def principal(name_type: int, parts: list[str]) -> bytes:
    name_string = D_SEQ(*[D_GENSTR(p) for p in parts])
    return D_SEQ(ctx(0, D_INT(name_type)), ctx(1, name_string))


def enc_data(etype: int, cipher: bytes) -> bytes:
    return D_SEQ(ctx(0, D_INT(etype)), ctx(2, D_OCTET(cipher)))


REALM = "EXAMPLE.COM"


def as_req() -> bytes:
    body = D_SEQ(
        ctx(0, D_BITSTR(b"\x00\x00\x00\x00")),                 # kdc-options
        ctx(1, principal(1, ["alice"])),                        # cname
        ctx(2, D_GENSTR(REALM)),                                # realm
        ctx(3, principal(2, ["krbtgt", REALM])),                # sname
        ctx(5, D_GENTIME("20260101000000Z")),                   # till
        ctx(7, D_INT(123456)),                                  # nonce
        ctx(8, D_SEQ(D_INT(18), D_INT(17), D_INT(23))),         # etype (AES256,AES128,RC4)
    )
    kdc_req = D_SEQ(ctx(1, D_INT(5)), ctx(2, D_INT(10)), ctx(4, body))
    return app(10, kdc_req)


def krb_error(code: int) -> bytes:
    seq = D_SEQ(
        ctx(0, D_INT(5)), ctx(1, D_INT(30)),
        ctx(4, D_GENTIME("20260101000005Z")), ctx(5, D_INT(0)),
        ctx(6, D_INT(code)),
        ctx(7, D_GENSTR(REALM)), ctx(8, principal(1, ["alice"])),
        ctx(9, D_GENSTR(REALM)), ctx(10, principal(2, ["krbtgt", REALM])),
    )
    return app(30, seq)


def as_req_preauth() -> bytes:
    """AS-REQ carrying a PA-ENC-TIMESTAMP (yields a crackable pre-auth hash)."""
    pa_ts = D_SEQ(ctx(1, D_INT(2)), ctx(2, D_OCTET(enc_data(18, b"\xcc" * 44))))
    padata = ctx(3, D_SEQ(pa_ts))
    body = D_SEQ(
        ctx(0, D_BITSTR(b"\x00\x00\x00\x00")),
        ctx(1, principal(1, ["alice"])),
        ctx(2, D_GENSTR(REALM)),
        ctx(3, principal(2, ["krbtgt", REALM])),
        ctx(5, D_GENTIME("20260101000000Z")),
        ctx(7, D_INT(123457)),
        ctx(8, D_SEQ(D_INT(18), D_INT(17), D_INT(23))),
    )
    kdc_req = D_SEQ(ctx(1, D_INT(5)), ctx(2, D_INT(10)), padata, ctx(4, body))
    return app(10, kdc_req)


def tgs_rep() -> bytes:
    """TGS-REP for a service SPN with an RC4 service ticket (Kerberoastable)."""
    ticket = app(1, D_SEQ(
        ctx(0, D_INT(5)), ctx(1, D_GENSTR(REALM)),
        ctx(2, principal(2, ["cifs", "demodc1.lab.local"])),
        ctx(3, enc_data(23, b"\xdd" * 200)),   # service ticket, RC4 -> hashcat 13100
    ))
    rep = D_SEQ(
        ctx(0, D_INT(5)), ctx(1, D_INT(13)),
        ctx(3, D_GENSTR(REALM)), ctx(4, principal(1, ["alice"])),
        ctx(5, ticket),
        ctx(6, enc_data(18, b"\xee" * 16)),
    )
    return app(13, rep)


def as_rep() -> bytes:
    ticket = app(1, D_SEQ(
        ctx(0, D_INT(5)), ctx(1, D_GENSTR(REALM)),
        ctx(2, principal(2, ["krbtgt", REALM])),
        ctx(3, enc_data(23, b"\xaa" * 16)),     # ticket encrypted with RC4 (weak)
    ))
    rep = D_SEQ(
        ctx(0, D_INT(5)), ctx(1, D_INT(11)),
        ctx(3, D_GENSTR(REALM)), ctx(4, principal(1, ["alice"])),
        ctx(5, ticket),
        ctx(6, enc_data(18, b"\xbb" * 16)),     # enc-part AES256
    )
    return app(11, rep)


# --------------------------------------------------------------------------- NTLM
def _secbuf(length, offset):
    return struct.pack("<HHI", length, length, offset)


def ntlm_type2(challenge: bytes, target="EXAMPLE") -> bytes:
    tname = target.encode("utf-16-le")
    tinfo = b"\x02\x00" + struct.pack("<H", len(tname)) + tname + b"\x00\x00\x00\x00"
    flags = 0x00000001 | 0x00000200 | 0x00800000 | 0x00080000   # Unicode|NTLM|TargetInfo|ExtSessSec
    payload_off = 48
    msg = bytearray()
    msg += b"NTLMSSP\x00" + struct.pack("<I", 2)
    msg += _secbuf(len(tname), payload_off)
    msg += struct.pack("<I", flags)
    msg += challenge
    msg += b"\x00" * 8
    msg += _secbuf(len(tinfo), payload_off + len(tname))
    msg += tname + tinfo
    return bytes(msg)


def ntlm_type3(domain, user, workstation, nt_resp, lm_resp=b"\x00" * 24) -> bytes:
    flags = 0x00000001 | 0x00000200
    dom = domain.encode("utf-16-le")
    usr = user.encode("utf-16-le")
    ws = workstation.encode("utf-16-le")
    base = 64
    parts = []
    off = base
    lm_off = off; off += len(lm_resp)
    nt_off = off; off += len(nt_resp)
    dom_off = off; off += len(dom)
    usr_off = off; off += len(usr)
    ws_off = off; off += len(ws)
    msg = bytearray()
    msg += b"NTLMSSP\x00" + struct.pack("<I", 3)
    msg += _secbuf(len(lm_resp), lm_off)
    msg += _secbuf(len(nt_resp), nt_off)
    msg += _secbuf(len(dom), dom_off)
    msg += _secbuf(len(usr), usr_off)
    msg += _secbuf(len(ws), ws_off)
    msg += _secbuf(0, off)              # session key
    msg += struct.pack("<I", flags)
    msg += lm_resp + nt_resp + dom + usr + ws
    return bytes(msg)


# --------------------------------------------------------------------------- TDS
def tds_packet(ptype: int, body: bytes) -> bytes:
    return struct.pack("!BBHHBB", ptype, 0x01, 8 + len(body), 0, 1, 0) + body


def tds_prelogin_off() -> bytes:
    # options: VERSION(0), ENCRYPTION(1), TERMINATOR(0xFF)
    hdr = bytearray()
    data = bytearray()
    data_base = 11  # 2 options * 5 + 1 terminator
    ver = b"\x10\x00\x00\x00\x00\x00"
    hdr += bytes([0x00]) + struct.pack("!HH", data_base, len(ver))
    enc = bytes([0x00])  # ENCRYPT_OFF
    hdr += bytes([0x01]) + struct.pack("!HH", data_base + len(ver), len(enc))
    hdr += b"\xff"
    body = bytes(hdr) + ver + enc
    return tds_packet(0x12, body)


def tds_login7(host, user, password, app_, server, database) -> bytes:
    def enc_pw(p):
        out = bytearray()
        for b in p.encode("utf-16-le"):
            b = ((b << 4) | (b >> 4)) & 0xFF
            out.append(b ^ 0xA5)
        return bytes(out)

    fixed = bytearray(94)
    struct.pack_into("<I", fixed, 4, 0x74000004)  # TDS 7.4
    struct.pack_into("<I", fixed, 8, 4096)
    # OffsetLength block starts at 36; pairs (ib,cch)
    data = bytearray()
    base = 94
    fields = []

    def add(s, transform=None):
        raw = transform(s) if transform else s.encode("utf-16-le")
        ib = base + len(data)
        data.extend(raw)
        return ib, len(s)  # cch in characters

    ib_host, cch_host = add(host)
    ib_user, cch_user = add(user)
    ib_pass, cch_pass = add(password, enc_pw)
    ib_app, cch_app = add(app_)
    ib_srv, cch_srv = add(server)
    # extension(unused), cltintname, language
    ib_db, cch_db = add(database)

    def put(idx, ib, cch):
        struct.pack_into("<HH", fixed, 36 + idx * 4, ib, cch)

    put(0, ib_host, cch_host)
    put(1, ib_user, cch_user)
    put(2, ib_pass, cch_pass)
    put(3, ib_app, cch_app)
    put(4, ib_srv, cch_srv)
    put(5, 0, 0)
    put(6, 0, 0)
    put(7, 0, 0)
    put(8, ib_db, cch_db)
    # ClientID (6) at 72, ibSSPI/cbSSPI at 78
    struct.pack_into("<HH", fixed, 78, 0, 0)
    record = bytes(fixed) + bytes(data)
    record = struct.pack("<I", len(record)) + record[4:]
    return tds_packet(0x10, record)


# --------------------------------------------------------------------------- LDAP
def ldap_bind_request() -> bytes:
    # LDAP uses IMPLICIT tagging: [APPLICATION 0] replaces the SEQUENCE tag,
    # so the fields sit directly inside the application-tagged value.
    bind = app(0,
        D_INT(3)
        + D_OCTET(b"cn=admin,dc=example,dc=com")
        + ctx(0, b"Secret123!", constructed=False),    # simple auth = cleartext
    )
    return D_SEQ(D_INT(1), bind)


def ldap_bind_response(code=0) -> bytes:
    resp = app(1, D_ENUM(code) + D_OCTET(b"") + D_OCTET(b""))
    return D_SEQ(D_INT(1), resp)


# --------------------------------------------------------------------------- RADIUS
def radius_attr(t, val):
    return bytes([t, len(val) + 2]) + val


def radius_vsa(vendor, vtype, vval):
    inner = bytes([vtype, len(vval) + 2]) + vval
    return radius_attr(26, struct.pack("!I", vendor) + inner)


def radius_packet(code, ident, attrs):
    body = b"".join(attrs)
    return struct.pack("!BBH", code, ident, 20 + len(body)) + (b"\x11" * 16) + body


def radius_eap_attrs(eap_bytes):
    """Split an EAP packet across one or more EAP-Message (79) attributes (<=253)."""
    return [radius_attr(79, eap_bytes[i:i + 253]) for i in range(0, len(eap_bytes), 253)]


def eth_eapol(src_mac, dst_mac, eap_bytes):
    """An 802.1X EAPOL EAP-Packet Ethernet frame (ethertype 0x888e)."""
    eapol = bytes([1, 0]) + struct.pack("!H", len(eap_bytes)) + eap_bytes
    return dst_mac + src_mac + b"\x88\x8e" + eapol


def radius_mschapv2_request():
    authchal = b"\xaa" * 16
    peer = b"\xbb" * 16
    nt = b"\xcc" * 24
    attrs = [
        radius_attr(1, b"rad-user"),                      # User-Name
        radius_attr(31, b"00-11-22-33-44-55"),            # Calling-Station-Id
        radius_attr(4, bytes([10, 0, 0, 5])),             # NAS-IP-Address
        radius_vsa(311, 11, authchal),                    # MS-CHAP-Challenge
        radius_vsa(311, 25, bytes([0, 0]) + peer + b"\x00" * 8 + nt),  # MS-CHAP2-Response
    ]
    return radius_packet(1, 66, attrs)


def radius_accept():
    return radius_packet(2, 66, [radius_attr(18, b"Welcome")])


RADIUS_SECRET = b"testing123"


def radius_encrypt_pw(secret, authenticator, password):
    pw = password.encode()
    if len(pw) % 16:
        pw += b"\x00" * (16 - len(pw) % 16)
    out, prev = b"", authenticator
    for i in range(0, len(pw), 16):
        b = hashlib.md5(secret + prev).digest()
        block = bytes(x ^ y for x, y in zip(pw[i:i + 16], b))
        out += block
        prev = block
    return out


def radius_packet_auth(code, ident, authenticator, attrs):
    body = b"".join(attrs)
    return struct.pack("!BBH", code, ident, 20 + len(body)) + authenticator + body


def radius_response(code, ident, req_auth, attrs, secret):
    body = b"".join(attrs)
    head = struct.pack("!BBH", code, ident, 20 + len(body))
    auth = hashlib.md5(head + req_auth + body + secret).digest()    # Response Authenticator
    return head + auth + body


def eap_packet(code, ident, etype=None, data=b""):
    if code in (3, 4):                                   # Success / Failure: no type
        return struct.pack("!BBH", code, ident, 4)
    body = bytes([etype]) + data
    return struct.pack("!BBH", code, ident, 4 + len(body)) + body


def eap_md5_exchange(p, nas, srv):
    """EAP-MD5 (crackable, hashcat -m 4800): Identity -> MD5 challenge/response -> Success."""
    def req(code, rid, attrs):
        return radius_packet_auth(code, rid, bytes([rid]) * 16, attrs)
    e_id = eap_packet(2, 1, 1, b"eap-user")
    e_chal = eap_packet(1, 2, 4, bytes([16]) + b"\x10" * 16)
    e_resp = eap_packet(2, 2, 4, bytes([16]) + b"\x20" * 16)
    e_succ = eap_packet(3, 2)
    p.add(eth_ip(nas, srv, 17, udp(46000, 1812, req(1, 10, [radius_attr(1, b"eap-user")] + radius_eap_attrs(e_id)))))
    p.add(eth_ip(srv, nas, 17, udp(1812, 46000, req(11, 10, radius_eap_attrs(e_chal)))))
    p.add(eth_ip(nas, srv, 17, udp(46000, 1812, req(1, 11, [radius_attr(1, b"eap-user")] + radius_eap_attrs(e_resp)))))
    p.add(eth_ip(srv, nas, 17, udp(1812, 46000, req(2, 11, radius_eap_attrs(e_succ)))))


def eap_peap_exchange(p, nas, srv):
    """PEAP: anonymous outer identity + a real (cleartext) server certificate."""
    def req(code, rid, attrs):
        return radius_packet_auth(code, rid, bytes([rid]) * 16, attrs)
    cert = make_x509("radius.lab.local", "LAB-CA", ["radius.lab.local"])
    server_tls = tls_server_hello() + tls_certificate(cert)
    client_tls = tls_client_hello("radius.lab.local")
    e_id = eap_packet(2, 1, 1, b"anonymous")
    e_start = eap_packet(1, 2, 25, b"\x20")                                  # PEAP start (S)
    e_ch = eap_packet(2, 2, 25, b"\x00" + client_tls)                        # ClientHello
    e_sh = eap_packet(1, 3, 25, b"\x80" + struct.pack("!I", len(server_tls)) + server_tls)  # ServerHello+Cert
    e_ack = eap_packet(2, 3, 25, b"\x00")
    e_succ = eap_packet(3, 4)
    p.add(eth_ip(nas, srv, 17, udp(46010, 1812, req(1, 20, [radius_attr(1, b"anonymous")] + radius_eap_attrs(e_id)))))
    p.add(eth_ip(srv, nas, 17, udp(1812, 46010, req(11, 20, radius_eap_attrs(e_start)))))
    p.add(eth_ip(nas, srv, 17, udp(46010, 1812, req(1, 21, [radius_attr(1, b"anonymous")] + radius_eap_attrs(e_ch)))))
    p.add(eth_ip(srv, nas, 17, udp(1812, 46010, req(11, 21, radius_eap_attrs(e_sh)))))
    p.add(eth_ip(nas, srv, 17, udp(46010, 1812, req(1, 22, [radius_attr(1, b"anonymous")] + radius_eap_attrs(e_ack)))))
    p.add(eth_ip(srv, nas, 17, udp(1812, 46010, req(2, 22, radius_eap_attrs(e_succ)))))


def eapol_md5_exchange(p):
    """Wired 802.1X (EAPOL) EAP-MD5 between a supplicant and a switch."""
    sup, sw = mac(0x10), mac(0x20)
    e_idreq = eap_packet(1, 1, 1, b"")                  # Request/Identity (switch)
    e_id = eap_packet(2, 1, 1, b"wired-user")           # Response/Identity (supplicant)
    e_chal = eap_packet(1, 2, 4, bytes([16]) + b"\x30" * 16)
    e_resp = eap_packet(2, 2, 4, bytes([16]) + b"\x40" * 16)
    e_succ = eap_packet(3, 2)
    p.add(eth_eapol(sw, sup, e_idreq))                  # switch -> supplicant
    p.add(eth_eapol(sup, sw, e_id))                     # supplicant -> switch
    p.add(eth_eapol(sw, sup, e_chal))
    p.add(eth_eapol(sup, sw, e_resp))
    p.add(eth_eapol(sw, sup, e_succ))


def radius_pap_request():
    req_auth = bytes(range(16))
    pwenc = radius_encrypt_pw(RADIUS_SECRET, req_auth, "S3cret!")
    attrs = [radius_attr(1, b"ppp-user"), radius_attr(2, pwenc),
             radius_attr(31, b"aa-bb-cc-dd-ee-ff")]
    return req_auth, radius_packet_auth(1, 88, req_auth, attrs)


# --------------------------------------------------------------------------- X.509 / TLS
def _oid(b):
    return tlv(0x06, b)


def _name(cn, org=None):
    rdns = [tlv(0x31, D_SEQ(_oid(bytes([0x55, 0x04, 0x03])) + tlv(0x13, cn.encode())))]
    if org:
        rdns.append(tlv(0x31, D_SEQ(_oid(bytes([0x55, 0x04, 0x0A])) + tlv(0x13, org.encode()))))
    return D_SEQ(*rdns)


def make_x509(subject_cn, issuer_cn, sans, org="LAB"):
    sig_alg = D_SEQ(_oid(bytes.fromhex("2a864886f70d01010b")), tlv(0x05, b""))  # sha256WithRSA
    spki = D_SEQ(
        D_SEQ(_oid(bytes.fromhex("2a864886f70d010101")), tlv(0x05, b"")),       # rsaEncryption
        D_BITSTR(b"\x00" * 32),
    )
    validity = D_SEQ(tlv(0x17, b"250101000000Z"), tlv(0x17, b"270101000000Z"))   # UTCTime
    gen_names = D_SEQ(*[tlv(0x82, s.encode()) for s in sans])                     # dNSName [2]
    san_ext = D_SEQ(_oid(bytes([0x55, 0x1D, 0x11])), D_OCTET(gen_names))
    extensions = ctx(3, D_SEQ(san_ext))
    tbs = D_SEQ(
        ctx(0, D_INT(2)), D_INT(4096), sig_alg,
        _name(issuer_cn), validity, _name(subject_cn, org), spki, extensions,
    )
    return D_SEQ(tbs, sig_alg, D_BITSTR(b"\x00" * 32))


def tls_record(htype, body):
    hs = bytes([htype]) + body.__len__().to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def tls_client_hello(sni):
    name = sni.encode()
    sni_list = b"\x00" + struct.pack("!H", len(name)) + name
    sni_ext = struct.pack("!H", len(sni_list)) + sni_list
    ext = struct.pack("!HH", 0x0000, len(sni_ext)) + sni_ext
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00" + struct.pack("!H", len(ext)) + ext
    return tls_record(1, body)


def tls_server_hello():
    body = b"\x03\x03" + b"\x22" * 32 + b"\x00" + b"\x13\x01" + b"\x00" + struct.pack("!H", 0)
    return tls_record(2, body)


def tls_certificate(cert_der):
    one = cert_der.__len__().to_bytes(3, "big") + cert_der
    body = one.__len__().to_bytes(3, "big") + one
    return tls_record(11, body)


# --------------------------------------------------------------------------- pcap
def ipv4_checksum(hdr: bytes) -> int:
    s = 0
    for i in range(0, len(hdr), 2):
        s += (hdr[i] << 8) | hdr[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def mac(n):
    return bytes([0x02, 0, 0, 0, 0, n])


def eth_ip(src, dst, proto, l4):
    ihl = 5
    total = ihl * 4 + len(l4)
    hdr = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0x4000, 64, proto, 0,
                                bytes(map(int, src.split("."))), bytes(map(int, dst.split(".")))))
    chk = ipv4_checksum(hdr)
    struct.pack_into("!H", hdr, 10, chk)
    eth = mac(2) + mac(1) + b"\x08\x00"
    return eth + bytes(hdr) + l4


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, seq, ack, flags, payload=b""):
    off = (5 << 4)
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, off, flags, 64240, 0, 0) + payload


class Pcap:
    def __init__(self):
        self.frames = []
        self.t = 1_700_000_000.0

    def add(self, frame):
        self.t += 0.001
        self.frames.append((self.t, frame))

    def write(self, path, network=1):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, network))
            for ts, frame in self.frames:
                sec = int(ts)
                usec = int((ts - sec) * 1_000_000)
                f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
                f.write(frame)


SYN, ACK, RST, PSH, FIN = 0x02, 0x10, 0x04, 0x08, 0x01


def dns_name(n):
    return b"".join(bytes([len(x)]) + x.encode() for x in n.split(".")) + b"\x00"


def dns_query(qid, qname, qtype=1):
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + dns_name(qname) + struct.pack("!HH", qtype, 1)


def dns_response(qid, qname, ip):
    q = dns_name(qname) + struct.pack("!HH", 1, 1)
    ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes(map(int, ip.split(".")))
    return struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0) + q + ans


def dns_nxdomain(qid, qname, qtype=1):
    """NXDOMAIN response - authoritative, no answers."""
    q = dns_name(qname) + struct.pack("!HH", qtype, 1)
    return struct.pack("!HHHHHH", qid, 0x8583, 1, 0, 0, 0) + q


def dns_cname_response(qid, qname, cname, ip):
    """A response with a CNAME chain then an A record."""
    q = dns_name(qname) + struct.pack("!HH", 1, 1)
    cname_b = dns_name(cname)
    rr1 = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 300, len(cname_b)) + cname_b
    ip_b = bytes(map(int, ip.split(".")))
    rr2 = dns_name(cname) + struct.pack("!HHIH", 1, 1, 300, 4) + ip_b
    return struct.pack("!HHHHHH", qid, 0x8180, 1, 2, 0, 0) + q + rr1 + rr2


def dns_ptr_response(qid, arpa, fqdn):
    q = dns_name(arpa) + struct.pack("!HH", 12, 1)
    fqdn_b = dns_name(fqdn)
    rr = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 300, len(fqdn_b)) + fqdn_b
    return struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0) + q + rr


def dhcp_request(client_mac, hostname):
    pkt = bytearray(240)
    pkt[0], pkt[1], pkt[2] = 1, 1, 6                 # op BOOTREQUEST, htype ether, hlen 6
    pkt[28:34] = client_mac
    pkt[236:240] = b"\x63\x82\x53\x63"               # magic cookie
    opts = bytes([53, 1, 3]) + bytes([12, len(hostname)]) + hostname + bytes([255])
    return bytes(pkt) + opts


def tcp_conn(p, cip, sip, cport, sport, client_msgs, server_msgs):
    c0, s0 = 1000, 5000
    p.add(eth_ip(cip, sip, 6, tcp(cport, sport, c0, 0, SYN)))
    p.add(eth_ip(sip, cip, 6, tcp(sport, cport, s0, c0 + 1, SYN | ACK)))
    cseq, sseq = c0 + 1, s0 + 1
    for i in range(max(len(client_msgs), len(server_msgs))):
        if i < len(server_msgs):
            m = server_msgs[i]
            p.add(eth_ip(sip, cip, 6, tcp(sport, cport, sseq, cseq, PSH | ACK, m)))
            sseq += len(m)
        if i < len(client_msgs):
            m = client_msgs[i]
            p.add(eth_ip(cip, sip, 6, tcp(cport, sport, cseq, sseq, PSH | ACK, m)))
            cseq += len(m)
    p.add(eth_ip(cip, sip, 6, tcp(cport, sport, cseq, sseq, FIN | ACK)))


def kerb_tcp_msg(blob):
    return struct.pack("!I", len(blob)) + blob


def build(path):
    p = Pcap()
    CLIENT, KDC, SMB, SQL, LDAPS, WEB = "10.0.0.10", "10.0.0.1", "10.0.0.5", "10.0.0.6", "10.0.0.1", "10.0.0.7"

    # Kerberos over UDP/88: AS-REQ (no preauth) then KRB-ERROR PREAUTH_REQUIRED
    p.add(eth_ip(CLIENT, KDC, 17, udp(49152, 88, as_req())))
    p.add(eth_ip(KDC, CLIENT, 17, udp(88, 49152, krb_error(25))))
    # Kerberos over TCP/88: AS-REQ (with preauth) then AS-REP + TGS-REP
    tcp_conn(p, CLIENT, KDC, 49160, 88,
             [kerb_tcp_msg(as_req_preauth())],
             [kerb_tcp_msg(as_rep()), kerb_tcp_msg(tgs_rep())])

    # NTLMv2 over SMB/445
    chal = bytes.fromhex("1122334455667788")
    nt_resp = bytes.fromhex("00112233445566778899aabbccddeeff") + b"\x01\x01" + b"\x00" * 26
    tcp_conn(p, CLIENT, SMB, 50001, 445,
             [b"\x00SMBnego", ntlm_type3("EXAMPLE", "alice", "WS01", nt_resp)],
             [b"\x00SMBresp", ntlm_type2(chal)])

    # MSSQL/TDS 1433: pre-login ENCRYPT_OFF + Login7 SQL auth
    tcp_conn(p, CLIENT, SQL, 50010, 1433,
             [tds_prelogin_off(), tds_login7("WS01", "sa", "P@ssw0rd!", "OurApp", "SQL01", "master")],
             [tds_prelogin_off()])

    # LDAP 389: cleartext simple bind + success response
    tcp_conn(p, CLIENT, LDAPS, 50020, 389,
             [ldap_bind_request()], [ldap_bind_response(0)])

    # LDAPS 636: TLS handshake with server certificate (encrypted bind)
    cert = make_x509("demodc1.lab.local", "LAB-CA", ["demodc1.lab.local", "lab.local"])
    tcp_conn(p, CLIENT, LDAPS, 50021, 636,
             [tls_client_hello("demodc1.lab.local")],
             [tls_server_hello(), tls_certificate(cert)])

    # HTTP Basic on 80 + 401 NTLM challenge
    http_req = (b"GET /secure HTTP/1.1\r\nHost: web.example.com\r\n"
                b"Authorization: Basic YWxpY2U6UGFzc3dvcmQx\r\n\r\n")
    http_resp = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\n\r\n"
    tcp_conn(p, CLIENT, WEB, 50030, 80, [http_req], [http_resp])

    # RADIUS MS-CHAPv2 over UDP/1812 (NAS -> RADIUS), then Access-Accept
    p.add(eth_ip("10.0.0.5", "10.0.0.9", 17, udp(45000, 1812, radius_mschapv2_request())))
    p.add(eth_ip("10.0.0.9", "10.0.0.5", 17, udp(1812, 45000, radius_accept())))

    # RADIUS PAP with a real shared secret 'testing123' + correct Response
    # Authenticator (so the secret is recoverable and the password decryptable).
    req_auth, pap_req = radius_pap_request()
    pap_acc = radius_response(2, 88, req_auth, [radius_attr(18, b"OK")], RADIUS_SECRET)
    p.add(eth_ip("10.0.0.5", "10.0.0.9", 17, udp(45001, 1812, pap_req)))
    p.add(eth_ip("10.0.0.9", "10.0.0.5", 17, udp(1812, 45001, pap_acc)))

    # EAP-MD5 (crackable) and PEAP (anonymous identity + server cert) over RADIUS
    eap_md5_exchange(p, "10.0.0.7", "10.0.0.9")
    eap_peap_exchange(p, "10.0.0.8", "10.0.0.9")
    # Wired 802.1X (EAPOL) EAP-MD5 directly on the LAN
    eapol_md5_exchange(p)

    # Cleartext / legacy auth: FTP, TELNET, SMTP, POP3, IMAP, SNMP
    tcp_conn(p, CLIENT, "10.0.0.30", 50100, 21,
             [b"USER bob\r\nPASS s3cr3t\r\n"], [b"220 FTP ready\r\n331 pw\r\n230 OK\r\n"])
    tcp_conn(p, CLIENT, "10.0.0.31", 50101, 23,
             [b"telnetuser\r\ntelnetpass\r\n"], [b"\xff\xfd\x18login: telnetuser\r\nPassword: \r\n"])
    smtp_plain = base64.b64encode(b"\x00bob\x00smtppass")
    tcp_conn(p, CLIENT, "10.0.0.32", 50102, 25,
             [b"EHLO me\r\nAUTH PLAIN " + smtp_plain + b"\r\n"], [b"220 mail\r\n235 2.7.0 OK\r\n"])
    tcp_conn(p, CLIENT, "10.0.0.33", 50103, 110,
             [b"USER alice\r\nPASS popsecret\r\n"], [b"+OK POP3\r\n+OK\r\n+OK logged in\r\n"])
    tcp_conn(p, CLIENT, "10.0.0.34", 50104, 143,
             [b"a1 LOGIN imapuser imappass\r\n"], [b"* OK IMAP\r\na1 OK LOGIN completed\r\n"])
    snmp = D_SEQ(D_INT(1), D_OCTET(b"public"),
                 ctx(0, D_SEQ(D_INT(12345), D_INT(0), D_INT(0), D_SEQ())))
    p.add(eth_ip(CLIENT, "10.0.0.35", 17, udp(50105, 161, snmp)))
    # SNMPv3 USM authNoPriv (HMAC, 12-byte auth params) -> hashcat 25100/25200
    engine = b"\x80\x00\x1f\x88\x80\x01\x02\x03\x04\x05"
    usm = D_SEQ(D_OCTET(engine), D_INT(5), D_INT(123), D_OCTET(b"snmpv3user"),
                D_OCTET(b"\xaa" * 12), D_OCTET(b""))
    hdr3 = D_SEQ(D_INT(40000), D_INT(65507), D_OCTET(b"\x01"), D_INT(3))
    scoped = D_SEQ(D_OCTET(engine), D_OCTET(b""), ctx(0, D_SEQ(D_INT(1), D_INT(0), D_INT(0), D_SEQ())))
    snmp3 = D_SEQ(D_INT(3), hdr3, D_OCTET(usm), scoped)
    p.add(eth_ip(CLIENT, "10.0.0.36", 17, udp(50107, 161, snmp3)))

    # ----- Database / VoIP / remote-access / CRAM-MD5 challenge-response -----
    # PostgreSQL md5 (5432)
    startup = struct.pack("!I", 0x00030000) + b"user\x00pguser\x00database\x00testdb\x00\x00"
    pg_c = struct.pack("!I", 4 + len(startup)) + startup
    pw = b"md5" + b"5f4dcc3b5aa765d61d8327deb882cf99" + b"\x00"
    pg_c += b"p" + struct.pack("!I", 4 + len(pw)) + pw
    pg_s = b"R" + struct.pack("!I", 12) + struct.pack("!I", 5) + b"\x01\x02\x03\x04"
    tcp_conn(p, CLIENT, "10.0.0.40", 50200, 5432, [pg_c], [pg_s])

    # CRAM-MD5 over SMTP submission (587)
    chal = base64.b64encode(b"<1234@mail>")
    resp = base64.b64encode(b"cramuser 0123456789abcdef0123456789abcdef")
    tcp_conn(p, CLIENT, "10.0.0.32", 50210, 587,
             [b"EHLO me\r\nAUTH CRAM-MD5\r\n" + resp + b"\r\n"],
             [b"220 mail\r\n334 " + chal + b"\r\n235 OK\r\n"])

    # MySQL native (3306)
    spl = (b"\x0a" + b"5.7.40\x00" + b"\x01\x00\x00\x00" + b"AAAAAAAA" + b"\x00" +
           b"\xff\xf7" + b"\x21" + b"\x02\x00" + b"\xff\x81" + b"\x15" + b"\x00" * 10 +
           b"BBBBBBBBBBBB" + b"\x00" + b"mysql_native_password\x00")
    my_s = struct.pack("<I", len(spl))[:3] + b"\x00" + spl
    cpl = (b"\x05\xa6\x0f\x00" + b"\x00\x00\x00\x01" + b"\x21" + b"\x00" * 23 +
           b"mysqluser\x00" + b"\x14" + b"\xcc" * 20 + b"mysql_native_password\x00")
    my_c = struct.pack("<I", len(cpl))[:3] + b"\x01" + cpl
    tcp_conn(p, CLIENT, "10.0.0.45", 50211, 3306, [my_c], [my_s])

    # VNC / RFB 3.8 (5900)
    vnc_s = b"RFB 003.008\n" + b"\x01\x02" + b"\xaa" * 16
    vnc_c = b"RFB 003.008\n" + b"\x02" + b"\xbb" * 16
    tcp_conn(p, CLIENT, "10.0.0.41", 50201, 5900, [vnc_c], [vnc_s])

    # RDP (3389): mstshash username + NLA negotiation
    rdp_c = b"\x03\x00\x00\x2a\x25\xe0\x00\x00\x00\x00\x00Cookie: mstshash=rdpuser\r\n\x01\x00\x08\x00\x00\x00\x00\x00"
    rdp_s = b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x00\x08\x00\x02\x00\x00\x00"
    tcp_conn(p, CLIENT, "10.0.0.42", 50202, 3389, [rdp_c], [rdp_s])

    # HTTP Digest (80)
    http_d = (b'GET /secure HTTP/1.1\r\nHost: web\r\nAuthorization: Digest username="httpuser", '
              b'realm="test", nonce="abc123", uri="/secure", '
              b'response="0123456789abcdef0123456789abcdef", qop=auth, nc=00000001, cnonce="xyz"\r\n\r\n')
    tcp_conn(p, CLIENT, "10.0.0.43", 50203, 80, [http_d], [b"HTTP/1.1 401 Unauthorized\r\n\r\n"])

    # SIP digest over UDP (5060)
    sip = (b'REGISTER sip:lab.local SIP/2.0\r\nAuthorization: Digest username="sipuser", '
           b'realm="asterisk", nonce="1d6cf4", uri="sip:lab.local", '
           b'response="aabbccddeeff00112233445566778899", qop=auth, nc=00000001, cnonce="9876"\r\n\r\n')
    p.add(eth_ip(CLIENT, "10.0.0.44", 17, udp(5062, 5060, sip)))

    # DNS Q/R pairs - various record types and outcomes
    p.add(eth_ip(CLIENT, "10.0.0.53", 17, udp(50300, 53, dns_query(0x1234, "www.lab.local"))))
    p.add(eth_ip("10.0.0.53", CLIENT, 17, udp(53, 50300, dns_response(0x1234, "www.lab.local", "10.0.0.50"))))

    # CNAME chain: webmail -> webmail-cname.lab.local -> 10.0.0.51
    p.add(eth_ip(CLIENT, "10.0.0.53", 17, udp(50301, 53, dns_query(0x1235, "webmail.lab.local"))))
    p.add(eth_ip("10.0.0.53", CLIENT, 17, udp(53, 50301, dns_cname_response(0x1235, "webmail.lab.local", "webmail-cname.lab.local", "10.0.0.51"))))

    # NXDOMAIN - non-existent host
    p.add(eth_ip(CLIENT, "10.0.0.53", 17, udp(50302, 53, dns_query(0x1236, "nohost.lab.local"))))
    p.add(eth_ip("10.0.0.53", CLIENT, 17, udp(53, 50302, dns_nxdomain(0x1236, "nohost.lab.local"))))

    # AAAA query for a host that has no IPv6 -> NXDOMAIN
    p.add(eth_ip(CLIENT, "10.0.0.53", 17, udp(50303, 53, dns_query(0x1237, "www.lab.local", 28))))
    p.add(eth_ip("10.0.0.53", CLIENT, 17, udp(53, 50303, dns_nxdomain(0x1237, "www.lab.local", 28))))

    # PTR / reverse lookup
    p.add(eth_ip(CLIENT, "10.0.0.53", 17, udp(50304, 53, dns_query(0x1238, "50.0.0.10.in-addr.arpa", 12))))
    p.add(eth_ip("10.0.0.53", CLIENT, 17, udp(53, 50304, dns_ptr_response(0x1238, "50.0.0.10.in-addr.arpa", "www.lab.local"))))

    # NXDOMAIN from second server
    p.add(eth_ip(CLIENT, "10.0.0.54", 17, udp(50305, 53, dns_query(0x1239, "badhost.corp.local"))))
    p.add(eth_ip("10.0.0.54", CLIENT, 17, udp(53, 50305, dns_nxdomain(0x1239, "badhost.corp.local"))))

    # Unanswered query -> timeout (no response packet)
    p.add(eth_ip(CLIENT, "10.0.0.53", 17, udp(50306, 53, dns_query(0x1240, "timeout.lab.local"))))

    p.add(eth_ip("0.0.0.0", "255.255.255.255", 17, udp(68, 67, dhcp_request(mac(0x30), b"laptop-01"))))
    p.add(eth_ip(CLIENT, "224.0.0.251", 17, udp(5353, 5353, dns_query(0, "printer.local"))))

    # Refused connection: SYN then RST
    p.add(eth_ip(CLIENT, "10.0.0.99", 6, tcp(50040, 3389, 1000, 0, SYN)))
    p.add(eth_ip("10.0.0.99", CLIENT, 6, tcp(3389, 50040, 0, 1001, RST | ACK)))

    p.write(path)
    print(f"[+] wrote {path} with {len(p.frames)} frames")


# --------------------------------------------------------------------------- 802.11 / WPA
_RADIOTAP = b"\x00\x00\x08\x00\x00\x00\x00\x00"       # minimal radiotap header


def dot11_beacon(bssid, ssid):
    fixed = b"\x00" * 8 + b"\x64\x00" + b"\x11\x04"   # timestamp, interval, capabilities
    tags = bytes([0, len(ssid)]) + ssid               # SSID element
    return (struct.pack("<H", 0x0080) + b"\x00\x00" + b"\xff\xff\xff\xff\xff\xff" +
            bssid + bssid + b"\x00\x00" + fixed + tags)


def eapol_key(key_info, replay, nonce, mic, key_data=b""):
    body = (bytes([2]) + struct.pack("!H", key_info) + struct.pack("!H", 16) + replay +
            nonce + b"\x00" * 16 + b"\x00" * 8 + b"\x00" * 8 + mic +
            struct.pack("!H", len(key_data)) + key_data)
    return bytes([2, 3]) + struct.pack("!H", len(body)) + body


def dot11_data(fc, a1, a2, a3, eapol):
    snap = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
    return struct.pack("<H", fc) + b"\x00\x00" + a1 + a2 + a3 + b"\x00\x00" + snap + eapol


def build_wifi(path):
    p = Pcap()
    bssid = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    sta = bytes([0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB])
    replay = b"\x00\x00\x00\x00\x00\x00\x00\x01"
    anonce = b"\xaa" * 32
    snonce = b"\xbb" * 32
    pmkid_kde = b"\xdd\x14\x00\x0f\xac\x04" + b"\xcc" * 16
    p.add(_RADIOTAP + dot11_beacon(bssid, b"TestNet"))
    # M1 (AP->STA): ACK + pairwise + ver2 = 0x008a, ANonce, PMKID KDE
    m1 = eapol_key(0x008a, replay, anonce, b"\x00" * 16, pmkid_kde)
    p.add(_RADIOTAP + dot11_data(0x0208, sta, bssid, bssid, m1))
    # M2 (STA->AP): MIC + pairwise + ver2 = 0x010a, SNonce, MIC
    m2 = eapol_key(0x010a, replay, snonce, b"\xdd" * 16)
    p.add(_RADIOTAP + dot11_data(0x0108, bssid, sta, bssid, m2))
    p.write(path, network=127)                        # LINKTYPE_IEEE802_11_RADIOTAP
    print(f"[+] wrote {path} with {len(p.frames)} frames (802.11/radiotap)")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "sample.pcap"
    build(out)
    if len(sys.argv) <= 1:
        build_wifi("sample_wifi.pcap")
