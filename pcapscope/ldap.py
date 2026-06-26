"""LDAP bind analysis (RFC 4511) from a reassembled stream.

Pulls out authentication binds: *simple* binds (cleartext DN + password on
plain 389 is a real finding) versus *SASL* binds (GSSAPI/GSS-SPNEGO/NTLM), and
the bind result codes (49 = invalidCredentials, 8 = strongerAuthRequired, ...).
"""

from __future__ import annotations

from dataclasses import dataclass

from . import asn1
from .asn1 import CLASS_APPLICATION, CLASS_CONTEXT, CLASS_UNIVERSAL

RESULT_CODES = {
    0: "success",
    1: "operationsError",
    7: "authMethodNotSupported",
    8: "strongerAuthRequired",     # server demands signing/sealing
    14: "saslBindInProgress",
    32: "noSuchObject",
    48: "inappropriateAuthentication",
    49: "invalidCredentials",       # wrong username/password
    50: "insufficientAccessRights",
    53: "unwillingToPerform",
}


@dataclass
class LdapBind:
    kind: str = ""                  # "request" | "response"
    version: int = 0
    dn: str = ""
    method: str = ""                # "simple" | "SASL"
    mechanism: str = ""             # SASL mechanism (GSSAPI, GSS-SPNEGO, ...)
    password: str = ""              # only for simple binds (cleartext)
    cleartext: bool = False
    result_code: int | None = None
    result_name: str = ""


def analyze_stream(stream: bytes) -> list[LdapBind]:
    binds: list[LdapBind] = []
    for msg in asn1.parse(stream):
        if msg.cls != CLASS_UNIVERSAL or msg.num != asn1.U_SEQUENCE:
            continue
        # LDAPMessage: messageID INTEGER, protocolOp [APPLICATION n]
        op = None
        for c in msg.children:
            if c.cls == CLASS_APPLICATION:
                op = c
                break
        if op is None:
            continue
        if op.num == 0:  # bindRequest
            binds.append(_bind_request(op))
        elif op.num == 1:  # bindResponse
            binds.append(_bind_response(op))
    return [b for b in binds if b is not None]


def _bind_request(op) -> LdapBind | None:
    b = LdapBind(kind="request")
    kids = op.children
    if len(kids) >= 1 and kids[0].cls == CLASS_UNIVERSAL and kids[0].num == asn1.U_INTEGER:
        b.version = kids[0].as_int() or 0
    if len(kids) >= 2:
        b.dn = kids[1].as_str()
    auth = None
    for c in kids[2:]:
        if c.cls == CLASS_CONTEXT:
            auth = c
            break
    if auth is None:
        return b
    if auth.num == 0:  # simple
        b.method = "simple"
        b.password = auth.as_str()
        b.cleartext = True
    elif auth.num == 3:  # SASL
        b.method = "SASL"
        if auth.children:
            b.mechanism = auth.children[0].as_str()
    return b


def _bind_response(op) -> LdapBind | None:
    b = LdapBind(kind="response")
    kids = op.children
    if kids and kids[0].num == asn1.U_ENUM or (kids and kids[0].num == asn1.U_INTEGER):
        b.result_code = kids[0].as_int()
        b.result_name = RESULT_CODES.get(b.result_code, f"code-{b.result_code}")
    return b
