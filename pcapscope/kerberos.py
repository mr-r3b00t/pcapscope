"""Kerberos (RFC 4120) message analysis from raw ASN.1.

Identifies AS-REQ/REP, TGS-REQ/REP, AP-REQ/REP and KRB-ERROR; extracts the
client/service principals, realm, requested/used **encryption types**, pre-auth
state and KDC error codes. Flags weak crypto (RC4/DES) and classic auth-failure
errors - the things you actually chase when troubleshooting Kerberos.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from . import asn1
from .asn1 import CLASS_APPLICATION, CLASS_CONTEXT


# Application tag -> message name (the first identifier octet of a KRB message).
APP_TAG = {
    10: "AS-REQ",
    11: "AS-REP",
    12: "TGS-REQ",
    13: "TGS-REP",
    14: "AP-REQ",
    15: "AP-REP",
    30: "KRB-ERROR",
}
APP_FIRST_BYTE = {0x60 | n: name for n, name in APP_TAG.items()}

# Encryption types (etype). https://www.iana.org/assignments/kerberos-parameters
ETYPE_NAMES = {
    1: "des-cbc-crc",
    2: "des-cbc-md4",
    3: "des-cbc-md5",
    5: "des3-cbc-md5",
    16: "des3-cbc-sha1-kd",
    17: "aes128-cts-hmac-sha1-96",
    18: "aes256-cts-hmac-sha1-96",
    19: "aes128-cts-hmac-sha256-128",
    20: "aes256-cts-hmac-sha384-192",
    23: "rc4-hmac",
    24: "rc4-hmac-exp",
    25: "camellia128-cts-cmac",
    26: "camellia256-cts-cmac",
    -128: "rc4-hmac-old-exp",
    -133: "rc4-plain",
    -135: "rc4-plain-exp",
}
WEAK_ETYPES = {1, 2, 3, 5, 23, 24, -128, -133, -135}   # DES + RC4 family
STRONG_ETYPES = {17, 18, 19, 20}

# Pre-authentication data types of interest.
PA_ENC_TIMESTAMP = 2
PA_PK_AS_REQ = 16
PA_ETYPE_INFO2 = 19
PA_PAC_REQUEST = 128

# KDC error codes (RFC 4120 7.5.9) - the ones that matter for troubleshooting.
ERROR_NAMES = {
    0: "KDC_ERR_NONE",
    6: "KDC_ERR_C_PRINCIPAL_UNKNOWN",     # username / client not found
    7: "KDC_ERR_S_PRINCIPAL_UNKNOWN",     # SPN / service not found
    8: "KDC_ERR_PRINCIPAL_NOT_UNIQUE",
    9: "KDC_ERR_NULL_KEY",
    11: "KDC_ERR_CANNOT_POSTDATE",
    12: "KDC_ERR_POLICY",                 # logon-hours / workstation restriction
    13: "KDC_ERR_BADOPTION",
    14: "KDC_ERR_ETYPE_NOSUPP",           # no common encryption type
    15: "KDC_ERR_SUMTYPE_NOSUPP",
    18: "KDC_ERR_CLIENT_REVOKED",         # account disabled / locked / expired
    22: "KDC_ERR_SERVICE_REVOKED",
    23: "KDC_ERR_KEY_EXPIRED",            # password expired
    24: "KDC_ERR_PREAUTH_FAILED",         # wrong password
    25: "KDC_ERR_PREAUTH_REQUIRED",       # normal: ask for pre-auth
    26: "KDC_ERR_SERVER_NOMATCH",
    31: "KRB_AP_ERR_BAD_INTEGRITY",
    32: "KRB_AP_ERR_TKT_EXPIRED",
    37: "KRB_AP_ERR_SKEW",                # clock skew too great
    41: "KRB_AP_ERR_MODIFIED",
    52: "KRB_ERR_RESPONSE_TOO_BIG",
    68: "KDC_ERR_WRONG_REALM",
}
# Errors that usually signal a real problem (25 is expected during normal flow).
FAILURE_ERRORS = {6, 7, 12, 14, 18, 23, 24, 37, 68}


@dataclass
class KerberosMsg:
    kind: str = ""                       # AS-REQ, TGS-REP, KRB-ERROR, ...
    realm: str = ""
    cname: str = ""                      # client principal (user)
    sname: str = ""                      # service principal (SPN)
    etypes: list[int] = field(default_factory=list)   # requested etypes (REQ)
    enc_etype: int | None = None         # enc-part etype (REP)
    ticket_etype: int | None = None      # service-ticket etype (REP) -> roasting
    enc_cipher: bytes = b""              # KDC-REP enc-part ciphertext (AS-REP roast)
    ticket_cipher: bytes = b""           # service-ticket ciphertext (Kerberoast)
    preauth_etype: int | None = None     # PA-ENC-TIMESTAMP etype (AS-REQ)
    preauth_cipher: bytes = b""          # encrypted timestamp ciphertext (crackable)
    padata_types: list[int] = field(default_factory=list)
    preauth: bool = False
    error_code: int | None = None
    error_name: str = ""
    src: str = ""
    dst: str = ""
    transport: str = ""                  # "udp" | "tcp"
    ts: float = 0.0

    @property
    def weak_etypes(self) -> list[int]:
        used = list(self.etypes)
        for e in (self.enc_etype, self.ticket_etype):
            if e is not None:
                used.append(e)
        return sorted({e for e in used if e in WEAK_ETYPES})

    def etype_label(self, e: int | None) -> str:
        if e is None:
            return ""
        return ETYPE_NAMES.get(e, f"etype-{e}")

    def extractable_hashes(self) -> list[dict]:
        """Crackable Kerberos hashes recoverable from this message.

        - TGS-REP  -> Kerberoast hash (service ticket, encrypted w/ service key)
        - AS-REP   -> AS-REP roast hash (encrypted w/ the user's key)
        - AS-REQ   -> pre-auth timestamp (encrypted w/ the user's key)
        Formats follow impacket conventions; hashcat mode is noted per etype.
        """
        out: list[dict] = []
        user = self.cname or "unknown"
        realm = self.realm or ""
        if self.kind == "TGS-REP" and self.ticket_cipher and self.ticket_etype is not None:
            h = _fmt_tgs(self.ticket_etype, user, realm, self.sname or "unknown/spn", self.ticket_cipher)
            if h:
                out.append(h)
        if self.kind == "AS-REP" and self.enc_cipher and self.enc_etype is not None:
            h = _fmt_asrep(self.enc_etype, user, realm, self.enc_cipher)
            if h:
                out.append(h)
        if self.kind == "AS-REQ" and self.preauth_cipher and self.preauth_etype is not None:
            h = _fmt_preauth(self.preauth_etype, user, realm, self.preauth_cipher)
            if h:
                out.append(h)
        return out


def looks_like_kerberos(payload: bytes) -> bool:
    return bool(payload) and payload[0] in APP_FIRST_BYTE


def iter_messages(payload: bytes, transport: str):
    """Yield raw Kerberos message blobs from a UDP datagram or TCP stream.

    TCP frames each message with a 4-byte big-endian length prefix; UDP carries
    a single message per datagram.
    """
    if not payload:
        return
    if transport == "udp":
        if looks_like_kerberos(payload):
            yield payload
        return
    # TCP: walk length-prefixed records.
    off = 0
    n = len(payload)
    guard = 0
    while off + 4 <= n and guard < 64:
        guard += 1
        (length,) = struct.unpack("!I", payload[off : off + 4])
        if length == 0 or length > n - off - 4 + 1:
            # Either not length-prefixed or truncated; try a bare message once.
            if off == 0 and looks_like_kerberos(payload):
                yield payload
            return
        blob = payload[off + 4 : off + 4 + length]
        if looks_like_kerberos(blob):
            yield blob
        off += 4 + length


def parse(blob: bytes, transport: str = "udp") -> KerberosMsg | None:
    node = asn1.parse_one(blob)
    if node is None or node.cls != CLASS_APPLICATION:
        return None
    kind = APP_TAG.get(node.num)
    if not kind:
        return None
    msg = KerberosMsg(kind=kind, transport=transport)
    body = node.children[0] if node.children else None
    if body is None:
        return msg
    try:
        if kind in ("AS-REQ", "TGS-REQ"):
            _parse_req(body, msg)
        elif kind in ("AS-REP", "TGS-REP"):
            _parse_rep(body, msg)
        elif kind == "KRB-ERROR":
            _parse_error(body, msg)
        elif kind == "AP-REQ":
            _parse_apreq(body, msg)
    except Exception:
        pass  # best-effort; keep whatever fields we managed to fill
    return msg


# -- field helpers ----------------------------------------------------------
def _principal(field_node) -> str:
    """A [n] PrincipalName -> 'comp1/comp2' string."""
    if field_node is None:
        return ""
    pn = field_node.unwrap()             # SEQUENCE PrincipalName
    name_string = pn.child(1)            # [1] name-string SEQUENCE OF
    if name_string is None:
        return ""
    seq = name_string.unwrap()
    parts = [c.as_str() for c in seq.children]
    return "/".join(p for p in parts if p)


def _string(field_node) -> str:
    if field_node is None:
        return ""
    return field_node.unwrap().as_str()


def _int(field_node) -> int | None:
    if field_node is None:
        return None
    return field_node.unwrap().as_int()


def _parse_req(seq, msg: KerberosMsg) -> None:
    padata = seq.child(3)
    if padata is not None:
        for pa in padata.unwrap().children:
            t = _int(pa.child(1))
            if t is not None:
                msg.padata_types.append(t)
            if t == PA_ENC_TIMESTAMP:
                val = pa.child(2)         # padata-value [2] OCTET STRING
                if val is not None:
                    ed = asn1.parse_one(val.unwrap().content)  # EncryptedData
                    if ed is not None:
                        msg.preauth_etype = _int(ed.child(0))
                        cf = ed.child(2)
                        msg.preauth_cipher = cf.unwrap().content if cf is not None else b""
        msg.preauth = PA_ENC_TIMESTAMP in msg.padata_types
    body = seq.child(4)
    if body is None:
        return
    kb = body.unwrap()
    msg.cname = _principal(kb.child(1))
    msg.realm = _string(kb.child(2))
    msg.sname = _principal(kb.child(3))
    etype = kb.child(8)
    if etype is not None:
        for e in etype.unwrap().children:
            v = e.as_int()
            if v is not None:
                msg.etypes.append(v)


def _enc_etype(encdata_field) -> int | None:
    """[k] EncryptedData -> etype int."""
    if encdata_field is None:
        return None
    ed = encdata_field.unwrap()          # SEQUENCE EncryptedData
    return _int(ed.child(0))


def _enc_parts(encdata_field) -> tuple[int | None, bytes]:
    """[k] EncryptedData -> (etype, cipher bytes)."""
    if encdata_field is None:
        return None, b""
    ed = encdata_field.unwrap()
    etype = _int(ed.child(0))
    cipher_field = ed.child(2)           # [2] cipher OCTET STRING
    cipher = cipher_field.unwrap().content if cipher_field is not None else b""
    return etype, cipher


# hashcat mode lookups per encryption type
_TGS_MODE = {23: "13100", 17: "19600", 18: "19700"}
_PREAUTH_MODE = {23: "7500", 17: "19800", 18: "19900"}


def _fmt_tgs(etype, user, realm, spn, cipher) -> dict | None:
    if etype == 23 and len(cipher) >= 16:
        s = f"$krb5tgs$23$*{user}${realm}${spn}*${cipher[:16].hex()}${cipher[16:].hex()}"
    elif etype in (17, 18) and len(cipher) >= 12:
        s = f"$krb5tgs${etype}${user}${realm}$*{spn}*${cipher[-12:].hex()}${cipher[:-12].hex()}"
    else:
        return None
    return {"type": "Kerberoast (TGS-REP)", "mode": _TGS_MODE.get(etype, "?"),
            "etype": ETYPE_NAMES.get(etype, etype), "user": user, "spn": spn, "hash": s}


_ASREP_MODE = {23: "18200", 17: "18200", 18: "18200"}   # 18200 historically RC4; AES needs a current hashcat


def _fmt_asrep(etype, user, realm, cipher) -> dict | None:
    # Salt for the user's key is UPPERCASE-REALM + user, so uppercase the realm.
    r = realm.upper()
    if etype == 23 and len(cipher) >= 16:
        s = f"$krb5asrep$23${user}@{r}:{cipher[:16].hex()}${cipher[16:].hex()}"
    elif etype in (17, 18) and len(cipher) >= 12:
        s = f"$krb5asrep${etype}${user}@{r}:{cipher[-12:].hex()}${cipher[:-12].hex()}"
    else:
        return None
    return {"type": "AS-REP roast", "mode": _ASREP_MODE.get(etype, "18200"),
            "etype": ETYPE_NAMES.get(etype, etype), "user": user, "spn": "", "hash": s}


def _fmt_preauth(etype, user, realm, cipher) -> dict | None:
    if not cipher:
        return None
    # $krb5pa$ wrapper; the ciphertext hex is the crackable material. AES key
    # salt is UPPERCASE-REALM + user, so uppercase the realm for hashcat.
    s = f"$krb5pa${etype}${user}${realm.upper()}${cipher.hex()}"
    return {"type": "AS-REQ pre-auth timestamp", "mode": _PREAUTH_MODE.get(etype, "?"),
            "etype": ETYPE_NAMES.get(etype, etype), "user": user, "spn": "", "hash": s}


def _parse_rep(seq, msg: KerberosMsg) -> None:
    msg.realm = _string(seq.child(3))    # crealm
    msg.cname = _principal(seq.child(4))
    ticket_field = seq.child(5)
    if ticket_field is not None:
        tk = ticket_field.unwrap()       # [APPLICATION 1] Ticket
        tseq = tk.children[0] if tk.children else tk
        msg.sname = _principal(tseq.child(2))
        if not msg.realm:
            msg.realm = _string(tseq.child(1))
        msg.ticket_etype, msg.ticket_cipher = _enc_parts(tseq.child(3))
    msg.enc_etype, msg.enc_cipher = _enc_parts(seq.child(6))


def _parse_error(seq, msg: KerberosMsg) -> None:
    msg.error_code = _int(seq.child(6))
    if msg.error_code is not None:
        msg.error_name = ERROR_NAMES.get(msg.error_code, f"error-{msg.error_code}")
    msg.realm = _string(seq.child(9))
    msg.sname = _principal(seq.child(10))
    msg.cname = _principal(seq.child(8))


def _parse_apreq(seq, msg: KerberosMsg) -> None:
    ticket_field = seq.child(3)
    if ticket_field is not None:
        tk = ticket_field.unwrap()
        tseq = tk.children[0] if tk.children else tk
        msg.sname = _principal(tseq.child(2))
        msg.realm = _string(tseq.child(1))
        msg.ticket_etype = _enc_etype(tseq.child(3))
