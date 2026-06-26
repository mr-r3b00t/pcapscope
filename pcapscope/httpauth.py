"""HTTP authentication extraction from reassembled request/response streams.

Finds ``Authorization`` and ``WWW-Authenticate`` / ``Proxy-Authenticate``
headers and classifies the scheme: Basic (decoded user:pass), Bearer, NTLM and
Negotiate (Kerberos/NTLM via SPNEGO). The NTLM blobs are also handed to the
NTLM analyzer via the generic stream scan.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass

_REQ_LINE = re.compile(rb"^(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH|CONNECT|PROPFIND)\s+(\S+)\s+HTTP/(\d\.\d)", re.M)
_STATUS_LINE = re.compile(rb"^HTTP/(\d\.\d)\s+(\d{3})", re.M)
_AUTHZ = re.compile(rb"^Authorization:\s*(\S+)\s*([^\r\n]*)", re.I | re.M)
_WWW = re.compile(rb"^(?:WWW|Proxy)-Authenticate:\s*(\S+)\s*([^\r\n]*)", re.I | re.M)
_HOST = re.compile(rb"^Host:\s*([^\r\n]+)", re.I | re.M)


@dataclass
class HttpAuth:
    direction: str = ""             # "request" | "response"
    scheme: str = ""                # Basic | Bearer | NTLM | Negotiate | ...
    host: str = ""
    method: str = ""
    uri: str = ""
    status: str = ""
    username: str = ""              # decoded from Basic
    password: str = ""              # decoded from Basic
    token_preview: str = ""         # first chars of the credential token
    ntlm_present: bool = False


def analyze(client_bytes: bytes, server_bytes: bytes) -> list[HttpAuth]:
    out: list[HttpAuth] = []
    out.extend(_scan_request(client_bytes))
    out.extend(_scan_response(server_bytes))
    return out


def _scan_request(buf: bytes) -> list[HttpAuth]:
    results = []
    host = ""
    m = _HOST.search(buf)
    if m:
        host = m.group(1).decode("latin-1", "replace").strip()
    rl = _REQ_LINE.search(buf)
    method = rl.group(1).decode() if rl else ""
    uri = rl.group(2).decode("latin-1", "replace") if rl else ""
    for am in _AUTHZ.finditer(buf):
        scheme = am.group(1).decode("latin-1", "replace")
        token = am.group(2).decode("latin-1", "replace").strip()
        h = HttpAuth(direction="request", scheme=scheme, host=host, method=method, uri=uri)
        _fill_token(h, scheme, token)
        results.append(h)
    return results


def _scan_response(buf: bytes) -> list[HttpAuth]:
    results = []
    sl = _STATUS_LINE.search(buf)
    status = sl.group(2).decode() if sl else ""
    for wm in _WWW.finditer(buf):
        scheme = wm.group(1).decode("latin-1", "replace")
        token = wm.group(2).decode("latin-1", "replace").strip()
        h = HttpAuth(direction="response", scheme=scheme, status=status)
        _fill_token(h, scheme, token)
        results.append(h)
    return results


def _fill_token(h: HttpAuth, scheme: str, token: str) -> None:
    s = scheme.lower()
    if s == "basic" and token:
        try:
            raw = base64.b64decode(token + "===", validate=False)
            decoded = raw.decode("utf-8", "replace")
            if ":" in decoded:
                h.username, h.password = decoded.split(":", 1)
            else:
                h.username = decoded
        except Exception:
            h.token_preview = token[:24]
    elif s in ("ntlm", "negotiate") and token:
        h.token_preview = token[:24]
        try:
            raw = base64.b64decode(token + "===", validate=False)
            if b"NTLMSSP\x00" in raw:
                h.ntlm_present = True
        except Exception:
            pass
    elif token:
        h.token_preview = token[:24]
