"""Render :class:`AnalysisResult` to text (terminal) or JSON."""

from __future__ import annotations

import datetime as _dt
import os
from collections import Counter

from . import kerberos
from .analyze import AnalysisResult
from .layers import tcp_flag_str


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} TB"


def fmt_rate(bps: float) -> str:
    for unit in ("bit/s", "Kbit/s", "Mbit/s", "Gbit/s"):
        if bps < 1000 or unit == "Gbit/s":
            return f"{bps:.2f} {unit}"
        bps /= 1000
    return f"{bps:.2f} Gbit/s"


def fmt_ts(ts: float | None) -> str:
    if not ts:
        return "-"
    try:
        return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f UTC")
    except (OverflowError, OSError, ValueError):
        return f"{ts:.6f}"


def _hr(title: str) -> str:
    return f"\n{'=' * 70}\n {title}\n{'=' * 70}"


def _sub(title: str) -> str:
    return f"\n--- {title} ---"


# ---------------------------------------------------------------------------
# Validation / capinfos
# ---------------------------------------------------------------------------
def render_validation(result: AnalysisResult) -> str:
    info = result.info
    ok = not info.errors
    status = "VALID" if ok else "INVALID / CORRUPT"
    lines = [_hr(f"CAPTURE VALIDATION - {status}")]
    lines.append(f"  File              : {info.path}")
    lines.append(f"  Format            : {info.fmt}  (byte order: {info.byte_order or 'n/a'}, v{info.version or '?'})")
    lines.append(f"  Link type(s)      : {', '.join(info.linktype_names()) or 'unknown'}")
    lines.append(f"  Timestamp res.    : {info.ts_resolution or 'unknown'}")
    if info.os_info:
        lines.append(f"  Capture OS        : {info.os_info}")
    if info.app_info:
        lines.append(f"  Capture app       : {info.app_info}")
    lines.append(f"  Packets           : {info.packet_count}")
    lines.append(f"  Snap length       : {info.snaplen or 'n/a'}")
    lines.append(f"  Bytes (wire)      : {fmt_bytes(info.total_bytes_on_wire)}  ({info.total_bytes_on_wire})")
    lines.append(f"  Bytes (captured)  : {fmt_bytes(info.total_bytes_captured)}  ({info.total_bytes_captured})")
    if info.min_frame is not None:
        lines.append(f"  Frame size        : min {info.min_frame} / avg {info.avg_frame:.0f} / max {info.max_frame} bytes")
    lines.append(f"  First packet      : {fmt_ts(info.first_ts)}")
    lines.append(f"  Last packet       : {fmt_ts(info.last_ts)}")
    lines.append(f"  Duration          : {info.duration:.6f} s")
    lines.append(f"  Avg data rate     : {fmt_rate(info.avg_rate_bps)}")
    lines.append(f"  Truncated frames  : {info.truncated_count}  (snaplen-clipped: {info.snap_truncated_count})")
    if info.errors:
        lines.append("\n  ERRORS:")
        for e in info.errors:
            lines.append(f"    [x] {e}")
    if info.warnings:
        lines.append("\n  WARNINGS:")
        for w in info.warnings:
            lines.append(f"    [!] {w}")
    if ok and not info.warnings:
        lines.append("\n  No structural problems detected.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------
def render_protocols(result: AnalysisResult) -> str:
    lines = [_hr("PROTOCOL / SERVICE BREAKDOWN")]
    lines.append(_sub("Layer protocols"))
    for name, n in result.proto_stats.most_common():
        lines.append(f"  {name:<22} {n}")
    if result.service_stats:
        lines.append(_sub("Application services (by port)"))
        for name, n in result.service_stats.most_common():
            lines.append(f"  {name:<22} {n} packets")
    return "\n".join(lines)


def render_talkers(result: AnalysisResult, top: int = 10) -> str:
    lines = [_hr(f"TOP TALKERS (top {top} by bytes)")]
    lines.append(f"  {'Host':<40} {'Bytes':>14} {'Packets':>10}")
    for ip, b in result.talkers_bytes.most_common(top):
        lines.append(f"  {ip:<40} {fmt_bytes(b):>14} {result.talkers_pkts.get(ip, 0):>10}")
    return "\n".join(lines)


def render_conversations(result: AnalysisResult, top: int = 15) -> str:
    lines = [_hr(f"CONVERSATIONS (top {top} by bytes)")]
    lines.append(f"  {'Proto':<5} {'Service':<10} {'Endpoint A':<22} {'Endpoint B':<22} {'Pkts':>6} {'Bytes':>11} {'Dur(s)':>8}")
    for c in result.conversations[:top]:
        lines.append(
            f"  {c.proto:<5} {c.service or '-':<10} {c.a:<22} {c.b:<22} "
            f"{c.packets:>6} {fmt_bytes(c.bytes):>11} {c.duration:>8.2f}"
        )
    return "\n".join(lines)


def render_netflow(result: AnalysisResult, top: int = 40) -> str:
    lines = [_hr(f"NETFLOW (unidirectional 5-tuple flows, first {top} by start time)")]
    if not result.netflow:
        lines.append("  No flows.")
        return "\n".join(lines)
    lines.append(f"  {'Start':<26} {'Dur':>7}  {'Proto':<6} {'Source':<23} {'Destination':<23} "
                 f"{'Flags':<10} {'Pkts':>7} {'Bytes':>11}")
    for f in result.netflow[:top]:
        src = f"{f.src}:{f.sport}" if f.sport else f.src
        dst = f"{f.dst}:{f.dport}" if f.dport else f.dst
        flags = tcp_flag_str(f.flags) if f.proto == 6 else "-"
        lines.append(f"  {fmt_ts(f.first):<26} {f.duration:>7.2f}  {f.proto_name:<6} {src:<23} "
                     f"{dst:<23} {flags:<10} {f.packets:>7} {fmt_bytes(f.bytes):>11}")
    lines.append(f"\n  {len(result.netflow)} flows total.")
    return "\n".join(lines)


def netflow_csv(result: AnalysisResult) -> str:
    """nfdump-style CSV: ts,te,td,pr,sa,sp,da,dp,flg,ipkt,ibyt,tos."""
    rows = ["ts,te,td,pr,sa,sp,da,dp,flg,ipkt,ibyt,tos"]
    for f in result.netflow:
        flags = tcp_flag_str(f.flags) if f.proto == 6 else ""
        rows.append(",".join(str(x) for x in [
            fmt_ts(f.first), fmt_ts(f.last), f"{f.duration:.3f}", f.proto_name,
            f.src, f.sport, f.dst, f.dport, flags, f.packets, f.bytes, f.tos]))
    return "\n".join(rows) + "\n"


def render_tcp_health(result: AnalysisResult) -> str:
    lines = [_hr("TCP HEALTH")]
    lines.append(f"  SYN sent              : {result.tcp_syn}")
    lines.append(f"  SYN-ACK               : {result.tcp_synack}")
    lines.append(f"  RST                   : {result.tcp_rst}")
    lines.append(f"  FIN                   : {result.tcp_fin}")
    lines.append(f"  Retrans/out-of-order  : {result.tcp_retrans} (heuristic)")
    lines.append(f"  Failed handshakes     : {result.failed_handshakes}")
    lines.append(f"  Connections with RST  : {result.reset_conns}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Authentication findings
# ---------------------------------------------------------------------------
def render_kerberos(result: AnalysisResult) -> str:
    lines = [_hr("KERBEROS")]
    if not result.kerberos:
        lines.append("  No Kerberos traffic found (looked on TCP/UDP 88, 464).")
        return "\n".join(lines)

    kinds = Counter(f.msg.kind for f in result.kerberos)
    lines.append(_sub("Message counts"))
    for kind, n in kinds.most_common():
        lines.append(f"  {kind:<12} {n}")

    # encryption type histogram (requested + used)
    etype_req = Counter()
    etype_used = Counter()
    for f in result.kerberos:
        for e in f.msg.etypes:
            etype_req[e] += 1
        for e in (f.msg.enc_etype, f.msg.ticket_etype):
            if e is not None:
                etype_used[e] += 1
    if etype_req:
        lines.append(_sub("Requested encryption types (from REQ etype list)"))
        for e, n in etype_req.most_common():
            mark = "  <== WEAK" if e in kerberos.WEAK_ETYPES else ""
            lines.append(f"  {kerberos.ETYPE_NAMES.get(e, f'etype-{e}'):<28} x{n}{mark}")
    if etype_used:
        lines.append(_sub("Encryption types actually used (REP enc-part / ticket)"))
        for e, n in etype_used.most_common():
            mark = "  <== WEAK" if e in kerberos.WEAK_ETYPES else ""
            lines.append(f"  {kerberos.ETYPE_NAMES.get(e, f'etype-{e}'):<28} x{n}{mark}")

    # errors
    errs = [f for f in result.kerberos if f.msg.error_code]
    if errs:
        lines.append(_sub("KRB-ERROR messages"))
        for f in errs:
            m = f.msg
            lines.append(f"  {m.error_name} ({m.error_code})  user={m.cname or '-'} spn={m.sname or '-'} realm={m.realm or '-'}")

    lines.append(_sub("Requests / replies (detail)"))
    for f in result.kerberos[:60]:
        m = f.msg
        bits = [m.kind]
        if m.cname:
            bits.append(f"user={m.cname}")
        if m.sname:
            bits.append(f"spn={m.sname}")
        if m.realm:
            bits.append(f"realm={m.realm}")
        if m.etypes:
            bits.append("etypes=" + ",".join(kerberos.ETYPE_NAMES.get(e, str(e)) for e in m.etypes))
        if m.enc_etype is not None:
            bits.append("enc=" + kerberos.ETYPE_NAMES.get(m.enc_etype, str(m.enc_etype)))
        if m.ticket_etype is not None:
            bits.append("ticket=" + kerberos.ETYPE_NAMES.get(m.ticket_etype, str(m.ticket_etype)))
        if m.kind in ("AS-REQ",):
            bits.append("preauth=" + ("yes" if m.preauth else "NO"))
        lines.append("  " + "  ".join(bits))
    if len(result.kerberos) > 60:
        lines.append(f"  ... and {len(result.kerberos) - 60} more")

    # extracted usernames + crackable hashes
    hashes = []
    for f in result.kerberos:
        for hd in f.msg.extractable_hashes():
            hashes.append(hd)
    if hashes:
        lines.append(_sub("Extracted usernames + crackable hashes"))
        for hd in hashes:
            tgt = f" spn={hd['spn']}" if hd.get("spn") else ""
            lines.append(f"  [{hd['type']}] user={hd['user']}{tgt}  etype={hd['etype']}  (hashcat -m {hd['mode']})")
            lines.append(f"    {hd['hash']}")
    return "\n".join(lines)


def render_ntlm(result: AnalysisResult) -> str:
    lines = [_hr("NTLM / NetNTLM")]
    auths = [f for f in result.ntlm if f.auth]
    if not auths:
        if result.ntlm:
            lines.append(f"  Saw {len(result.ntlm)} NTLM challenge(s) but no completed authenticate message.")
        else:
            lines.append("  No NTLM (NTLMSSP) authentication found.")
        return "\n".join(lines)

    v = Counter(f.auth.ntlm_version for f in auths)
    lines.append(_sub("NetNTLM authentications"))
    lines.append(f"  Total: {len(auths)}   " + "  ".join(f"{k}={n}" for k, n in v.items()))
    for f in auths:
        a = f.auth
        who = f"{a.domain}\\{a.user}" if a.domain else a.user
        lines.append(
            f"\n  [{a.ntlm_version}] {who}  (workstation={a.workstation or '-'}, carrier={f.carrier}, "
            f"{f.client} -> {f.server})"
        )
        if f.hashcat:
            lines.append(f"    hashcat mode {f.mode}:")
            lines.append(f"    {f.hashcat}")
        elif not f.challenge:
            lines.append("    (no server challenge captured in this connection - hash incomplete)")
    return "\n".join(lines)


def render_tds(result: AnalysisResult) -> str:
    lines = [_hr("MSSQL / TDS")]
    if not result.tds:
        lines.append("  No MSSQL/TDS traffic found (looked on TCP 1433).")
        return "\n".join(lines)
    for f in result.tds:
        info = f.info
        lines.append(_sub(f"{f.client} -> {f.server}"))
        if info.encryption:
            lines.append(f"  Encryption negotiated : {info.encryption}")
        if info.login:
            lg = info.login
            lines.append(f"  Auth type             : {lg.auth_type}")
            if lg.username:
                lines.append(f"  Username              : {lg.username}")
            if lg.password:
                lines.append(f"  Password (recovered)  : {lg.password}")
            if lg.hostname:
                lines.append(f"  Client host           : {lg.hostname}  (mac {lg.client_mac or '-'})")
            if lg.appname:
                lines.append(f"  Application           : {lg.appname}")
            if lg.servername:
                lines.append(f"  Server name           : {lg.servername}")
            if lg.database:
                lines.append(f"  Database              : {lg.database}")
            if lg.sspi_present:
                lines.append("  SSPI/NTLM blob        : present (Windows auth - see NTLM section)")
        else:
            lines.append("  (pre-login only; no Login7 captured)")
    return "\n".join(lines)


def render_ldap(result: AnalysisResult) -> str:
    lines = [_hr("LDAP")]
    if not result.ldap:
        lines.append("  No LDAP bind traffic found (looked on TCP 389, 3268; LDAPS is encrypted).")
        return "\n".join(lines)
    for f in result.ldap:
        b = f.bind
        if b.kind == "request":
            extra = f"mech={b.mechanism}" if b.method == "SASL" else (f"password={b.password!r}" if b.password else "")
            lines.append(f"  BIND req  {f.client} -> {f.server}  method={b.method} dn='{b.dn}' {extra}")
        else:
            lines.append(f"  BIND resp {f.server}  result={b.result_name} ({b.result_code})")
    return "\n".join(lines)


def render_http_auth(result: AnalysisResult) -> str:
    lines = [_hr("HTTP AUTHENTICATION")]
    if not result.http_auth:
        lines.append("  No HTTP Authorization/WWW-Authenticate headers found (HTTPS is encrypted).")
        return "\n".join(lines)
    for f in result.http_auth:
        a = f.auth
        if a.direction == "request":
            cred = f" user={a.username}" + (f" pass={a.password}" if a.password else "") if a.username else (f" token={a.token_preview}..." if a.token_preview else "")
            lines.append(f"  -> {a.method} {a.uri} Host={a.host}  Authorization: {a.scheme}{cred}")
        else:
            lines.append(f"  <- {a.status} WWW-Authenticate: {a.scheme}" + (" (NTLM)" if a.ntlm_present else ""))
    return "\n".join(lines)


def render_tls(result: AnalysisResult) -> str:
    lines = [_hr("TLS / LDAPS")]
    if not result.tls:
        lines.append("  No TLS sessions found (looked on 636/3269/443 and any TLS stream).")
        return "\n".join(lines)
    for f in result.tls:
        i = f.info
        lines.append(_sub(f"{f.service or 'TLS'}  {f.client} -> {f.server}"))
        ver = i.server_version or i.client_version or "?"
        if i.truncated:
            ver += "+ (handshake truncated by snaplen - details below unreliable)"
        lines.append(f"  Version (negotiated) : {ver}")
        if i.sni:
            lines.append(f"  SNI (client asked)   : {i.sni}")
        if i.cipher and not i.truncated:
            lines.append(f"  Cipher suite         : 0x{i.cipher:04x}")
        if i.has_cert:
            lines.append(f"  Cert subject CN      : {i.cert_subject or '-'}")
            if i.cert_org:
                lines.append(f"  Cert org             : {i.cert_org}")
            if i.cert_sans:
                lines.append(f"  Cert SANs            : {', '.join(i.cert_sans)}")
            lines.append(f"  Cert issuer CN       : {i.cert_issuer or '-'}")
            lines.append(f"  Valid                : {i.not_before or '?'}  ..  {i.not_after or '?'}")
        elif i.truncated:
            lines.append("  Certificate          : (not captured - handshake clipped by snaplen)")
        else:
            lines.append("  Certificate          : (not in cleartext - TLS 1.3 encrypts it)")
    return "\n".join(lines)


def render_radius(result: AnalysisResult) -> str:
    lines = [_hr("RADIUS")]
    if not result.radius:
        lines.append("  No RADIUS traffic found (looked on UDP 1812/1813/1645/1646).")
        return "\n".join(lines)
    methods = Counter(f.method for f in result.radius)
    lines.append(_sub("Access-Requests by method"))
    for mth, n in methods.most_common():
        lines.append(f"  {mth:<14} {n}")
    secret = next((f.secret for f in result.radius if f.secret_valid), "")
    if secret:
        lines.append(f"\n  Shared secret: '{secret}'  (confirmed against captured authenticator)")
    elif any(f.can_recover_secret for f in result.radius):
        lines.append("\n  Shared secret: unknown - recoverable (try 'radius --recover-secret' or provide '--secret').")

    lines.append(_sub("Authentications"))
    for f in result.radius:
        bits = [f"user={f.username or '-'}", f"method={f.method}", f"result={f.result}"]
        if f.nas:
            bits.append(f"nas={f.nas}")
        if f.calling_station:
            bits.append(f"station={f.calling_station}")
        if f.password:
            bits.append(f"PASSWORD={f.password}")
        elif f.userpw_enc:
            bits.append("PAP(encrypted - needs shared secret)")
        lines.append(f"  {f.client} -> {f.server}  " + "  ".join(bits))
    hashes = [f for f in result.radius if f.hashcat]
    if hashes:
        lines.append(_sub("Extracted MS-CHAP(v2) hashes (hashcat -m 5500)"))
        for f in hashes:
            lines.append(f"  [{f.version}] user={f.username}")
            lines.append(f"    {f.hashcat}")
    return "\n".join(lines)


def render_eap(result: AnalysisResult) -> str:
    lines = [_hr("EAP / PEAP")]
    if not result.eap:
        lines.append("  No EAP traffic found (carried in RADIUS EAP-Message).")
        return "\n".join(lines)
    for f in result.eap:
        bits = [f"[{f.carrier}]", f"method={f.method}", f"identity={f.identity or '-'}", f"result={f.result or '-'}"]
        if f.tunnelled:
            bits.append("tunnelled(inner encrypted)")
        if f.nak_to:
            bits.append(f"client-wanted={f.nak_to}")
        lines.append(f"  {f.client} -> {f.server}  " + "  ".join(bits))
        if f.cert_subject or f.cert_sans:
            lines.append(f"      server cert: CN={f.cert_subject or '-'}  SAN={', '.join(f.cert_sans) or '-'}  "
                         f"issuer={f.cert_issuer or '-'}  ({f.tls_version}, expires {f.not_after or '?'})")
    hashes = [f for f in result.eap if f.hashcat]
    if hashes:
        lines.append(_sub("Extracted EAP hashes"))
        for f in hashes:
            mode = f.mode or ("4800" if f.version == "EAP-MD5" else "5500")
            lines.append(f"  [{f.version}] identity={f.identity or '-'}  (hashcat -m {mode})")
            lines.append(f"    {f.hashcat}")
    return "\n".join(lines)


def render_cleartext(result: AnalysisResult) -> str:
    lines = [_hr("CLEARTEXT / LEGACY AUTH")]
    if not result.cleartext:
        lines.append("  No cleartext-auth protocols found (FTP/TELNET/SMTP/POP3/IMAP/SNMP).")
        return "\n".join(lines)
    for f in result.cleartext:
        if f.protocol == "SNMP":
            mark = "  <== DEFAULT" if f.note == "DEFAULT community" else ""
            lines.append(f"  SNMP {f.mechanism}: '{f.password}'  ({f.client} -> {f.server}){mark}")
            continue
        cred = f"{f.username}:{f.password}" if f.password else (f.username or "-")
        extra = f"  [{f.note}]" if f.note else ""
        res = f"  result={f.result}" if f.result else ""
        lines.append(f"  {f.protocol:<7} {f.mechanism:<12} {cred}  ({f.client} -> {f.server}){res}{extra}")
    return "\n".join(lines)


def render_appauth(result: AnalysisResult) -> str:
    lines = [_hr("DATABASE / VOIP / REMOTE AUTH")]
    if not result.app_auth:
        lines.append("  None found (PostgreSQL/MySQL/SIP/VNC/RDP/CRAM-MD5/HTTP-Digest).")
        return "\n".join(lines)
    for f in result.app_auth:
        head = f"  {f.protocol:<12} {f.account or '-':<18} {f.client} -> {f.server}"
        if f.mode:
            head += f"   (hashcat -m {f.mode})"
        elif f.tool == "john":
            head += "   (john)"
        lines.append(head)
        if f.hashcat:
            lines.append(f"    {f.hashcat}")
        if f.note:
            lines.append(f"    note: {f.note}")
    return "\n".join(lines)


def render_dns(result: AnalysisResult) -> str:
    lines = [_hr("DNS TRAFFIC ANALYSIS")]
    txns = result.dns
    if not txns:
        lines.append("  No DNS traffic captured.")
        return "\n".join(lines)

    answered  = [t for t in txns if t.answered]
    nxd       = [t for t in txns if t.rcode == 3]
    servfail  = [t for t in txns if t.rcode == 2]
    refused   = [t for t in txns if t.rcode == 5]
    timeouts  = [t for t in txns if t.rcode == -1]
    errors    = [t for t in txns if t.rcode not in (-1, 0)]
    lats      = [t.latency_ms for t in answered if t.latency_ms is not None]

    lines.append(_sub("Summary"))
    lines.append(f"  Queries      : {len(txns)}")
    lines.append(f"  Answered     : {len(answered)}")
    lines.append(f"  NXDOMAIN     : {len(nxd)}")
    lines.append(f"  SERVFAIL     : {len(servfail)}")
    lines.append(f"  REFUSED      : {len(refused)}")
    lines.append(f"  Timeouts     : {len(timeouts)}")
    if lats:
        lines.append(f"  Latency      : avg {sum(lats)/len(lats):.1f} ms  "
                     f"min {min(lats):.1f} ms  max {max(lats):.1f} ms")

    # Query type breakdown
    qtype_c = Counter(t.qtype for t in txns)
    lines.append(_sub("Query types"))
    for qt, n in qtype_c.most_common():
        lines.append(f"  {qt:<8} {n}")

    # Per-server stats
    servers: dict[str, dict] = {}
    for t in txns:
        s = servers.setdefault(t.server, {"total": 0, "answered": 0, "nxd": 0, "fail": 0, "lats": []})
        s["total"] += 1
        if t.answered:
            s["answered"] += 1
            if t.latency_ms is not None:
                s["lats"].append(t.latency_ms)
        if t.rcode == 3:
            s["nxd"] += 1
        if t.rcode in (2, 5):
            s["fail"] += 1
    lines.append(_sub("DNS servers"))
    lines.append(f"  {'Server':<22} {'Queries':>7} {'Answered':>9} {'NXDOMAIN':>9} {'Errors':>7} {'Avg lat':>9}")
    for srv, s in sorted(servers.items(), key=lambda x: -x[1]["total"]):
        avg = f"{sum(s['lats'])/len(s['lats']):.0f} ms" if s["lats"] else "-"
        lines.append(f"  {srv:<22} {s['total']:>7} {s['answered']:>9} {s['nxd']:>9} {s['fail']:>7} {avg:>9}")

    # Top queried names
    qname_c = Counter(t.qname.lower() for t in txns)
    lines.append(_sub("Top queried names"))
    for name, cnt in qname_c.most_common(20):
        resolved = set()
        for t in txns:
            if t.qname.lower() == name:
                for _, _, v in t.answers:
                    if v:
                        resolved.add(v)
        lines.append(f"  {name:<45} {cnt:>3}x  {', '.join(sorted(resolved)[:3]) or '-'}")

    # Failures and errors
    if errors or timeouts:
        lines.append(_sub("Failures / errors"))
        for t in sorted(errors + timeouts, key=lambda t: t.ts_q):
            lines.append(f"  {fmt_ts(t.ts_q)}  {t.rcode_name:<10}  {t.qtype:<6}  {t.qname}  "
                         f"({t.client} -> {t.server})")

    return "\n".join(lines)


def render_hostnames(result: AnalysisResult) -> str:
    lines = [_hr("HOSTNAMES / NAMES")]
    if not result.hostnames:
        lines.append("  No hostnames found (DNS / SNI / HTTP Host / DHCP / certificate).")
        return "\n".join(lines)
    kinds = Counter(h.kind for h in result.hostnames)
    lines.append(_sub(f"{len(result.hostnames)} names, by source"))
    for k, n in kinds.most_common():
        lines.append(f"  {k:<14} {n}")
    # host inventory: IP -> the names that resolve to / are served from it
    by_ip: dict[str, set] = {}
    for h in result.hostnames:
        if h.ip:
            by_ip.setdefault(h.ip, set()).add(h.name)
    if by_ip:
        lines.append(_sub("Host inventory (IP -> names)"))
        for ip in sorted(by_ip):
            lines.append(f"  {ip:<20} {', '.join(sorted(by_ip[ip]))}")
    lines.append(_sub("All names"))
    for h in sorted(result.hostnames, key=lambda x: (x.name.lower(), x.kind)):
        loc = f"  -> {h.ip}" if h.ip else ""
        lines.append(f"  {h.name:<40} [{h.kind}]{loc}")
    return "\n".join(lines)


def render_wpa(result: AnalysisResult) -> str:
    lines = [_hr("WPA / Wi-Fi")]
    if not result.wpa:
        lines.append("  No WPA handshakes/PMKIDs found (802.11/radiotap captures only).")
        return "\n".join(lines)
    for f in result.wpa:
        lines.append(f"  [{f.kind}] SSID={f.essid or '?'}  BSSID={f.bssid}  STA={f.sta}"
                     + (f"  ({f.note})" if f.note else "") + "   (hashcat -m 22000)")
        lines.append(f"    {f.hashcat}")
    return "\n".join(lines)


def render_anomalies(result: AnalysisResult) -> str:
    lines = [_hr("TROUBLESHOOTING FINDINGS")]
    if not result.anomalies:
        lines.append("  Nothing notable flagged.")
    for x in result.anomalies:
        lines.append(f"  * {x}")
    return "\n".join(lines)


def render_full(result: AnalysisResult) -> str:
    parts = [
        render_validation(result),
        render_anomalies(result),
        render_protocols(result),
        render_talkers(result),
        render_conversations(result),
        render_tcp_health(result),
        render_kerberos(result),
        render_ntlm(result),
        render_tds(result),
        render_ldap(result),
        render_tls(result),
        render_radius(result),
        render_eap(result),
        render_cleartext(result),
        render_appauth(result),
        render_wpa(result),
        render_dns(result),
        render_hostnames(result),
        render_http_auth(result),
    ]
    return "\n".join(parts) + "\n"


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
def to_json(result: AnalysisResult) -> dict:
    info = result.info
    return {
        "file": info.path,
        "validation": {
            "valid": not info.errors,
            "format": info.fmt,
            "byte_order": info.byte_order,
            "version": info.version,
            "linktypes": info.linktype_names(),
            "snaplen": info.snaplen,
            "ts_resolution": info.ts_resolution,
            "packets": info.packet_count,
            "bytes_on_wire": info.total_bytes_on_wire,
            "bytes_captured": info.total_bytes_captured,
            "first_ts": info.first_ts,
            "last_ts": info.last_ts,
            "duration": info.duration,
            "avg_rate_bps": info.avg_rate_bps,
            "truncated_frames": info.truncated_count,
            "errors": info.errors,
            "warnings": info.warnings,
        },
        "protocols": dict(result.proto_stats),
        "services": dict(result.service_stats),
        "talkers": [
            {"host": ip, "bytes": b, "packets": result.talkers_pkts.get(ip, 0)}
            for ip, b in result.talkers_bytes.most_common(25)
        ],
        "conversations": [
            {
                "proto": c.proto, "service": c.service, "a": c.a, "b": c.b,
                "packets": c.packets, "bytes": c.bytes, "duration": c.duration,
                "syn": c.syn, "synack": c.synack, "rst": c.rst, "retrans": c.retrans,
            }
            for c in result.conversations[:100]
        ],
        "netflow": [
            {"src": f.src, "dst": f.dst, "sport": f.sport, "dport": f.dport,
             "proto": f.proto_name, "packets": f.packets, "bytes": f.bytes,
             "first": f.first, "last": f.last, "duration": f.duration,
             "flags": tcp_flag_str(f.flags) if f.proto == 6 else "", "tos": f.tos}
            for f in result.netflow[:2000]
        ],
        "tcp_health": {
            "syn": result.tcp_syn, "synack": result.tcp_synack, "rst": result.tcp_rst,
            "fin": result.tcp_fin, "retrans": result.tcp_retrans,
            "failed_handshakes": result.failed_handshakes, "reset_conns": result.reset_conns,
        },
        "kerberos": [_kerb_json(f) for f in result.kerberos],
        "ntlm": [_ntlm_json(f) for f in result.ntlm],
        "mssql": [_tds_json(f) for f in result.tds],
        "ldap": [_ldap_json(f) for f in result.ldap],
        "tls": [_tls_json(f) for f in result.tls],
        "radius": [_radius_json(f) for f in result.radius],
        "eap": [_eap_json(f) for f in result.eap],
        "cleartext": [_cleartext_json(f) for f in result.cleartext],
        "app_auth": [_appauth_json(f) for f in result.app_auth],
        "wpa": [_wpa_json(f) for f in result.wpa],
        "dns": [{"qid": t.qid, "qname": t.qname, "qtype": t.qtype,
                  "client": t.client, "server": t.server,
                  "ts_q": t.ts_q, "ts_r": t.ts_r or None,
                  "rcode": t.rcode, "rcode_name": t.rcode_name,
                  "latency_ms": t.latency_ms, "answers": t.answers,
                  "source": t.source, "aa": t.aa, "tc": t.tc}
                 for t in result.dns],
        "hostnames": [{"name": h.name, "kind": h.kind, "ip": h.ip or None,
                       "mac": h.mac or None, "source": h.source} for h in result.hostnames],
        "http_auth": [_http_json(f) for f in result.http_auth],
        "findings": result.anomalies,
    }


def _wpa_json(f) -> dict:
    return {"bssid": f.bssid, "sta": f.sta, "essid": f.essid or None,
            "kind": f.kind, "hashcat": f.hashcat, "mode": f.mode, "note": f.note or None}


def _appauth_json(f) -> dict:
    return {
        "protocol": f.protocol, "client": f.client, "server": f.server,
        "account": f.account or None, "hashcat": f.hashcat or None,
        "mode": f.mode or None, "tool": f.tool or None, "note": f.note or None,
    }


def _cleartext_json(f) -> dict:
    return {
        "protocol": f.protocol, "client": f.client, "server": f.server,
        "mechanism": f.mechanism, "username": f.username or None,
        "password": f.password or None, "result": f.result or None, "note": f.note or None,
    }


def _eap_json(f) -> dict:
    return {
        "client": f.client, "server": f.server, "carrier": f.carrier,
        "identity": f.identity, "method": f.method, "methods": f.methods,
        "result": f.result, "tunnelled": f.tunnelled, "nak_to": f.nak_to or None,
        "version": f.version or None, "hashcat": f.hashcat or None, "mode": f.mode or None,
        "sni": f.sni or None, "tls_version": f.tls_version or None,
        "cert_subject": f.cert_subject or None, "cert_issuer": f.cert_issuer or None,
        "cert_sans": f.cert_sans, "not_after": f.not_after or None,
    }


def _radius_json(f) -> dict:
    return {
        "client": f.client, "server": f.server, "username": f.username,
        "method": f.method, "result": f.result, "nas": f.nas,
        "calling_station": f.calling_station, "version": f.version or None,
        "hashcat": f.hashcat or None, "mode": f.mode or None,
        "has_pap": bool(f.userpw_enc), "password": f.password or None,
        "secret": f.secret or None, "secret_valid": f.secret_valid,
        "can_recover_secret": f.can_recover_secret,
    }


def _tls_json(f) -> dict:
    i = f.info
    return {
        "client": f.client, "server": f.server, "service": f.service,
        "version": i.server_version or i.client_version, "sni": i.sni,
        "truncated": i.truncated,
        "cipher": f"0x{i.cipher:04x}" if (i.cipher and not i.truncated) else None,
        "cert_subject": i.cert_subject or None, "cert_org": i.cert_org or None,
        "cert_issuer": i.cert_issuer or None, "cert_sans": i.cert_sans,
        "not_before": i.not_before or None, "not_after": i.not_after or None,
    }


def _kerb_json(f) -> dict:
    m = f.msg
    return {
        "kind": m.kind, "client": f.client, "server": f.server, "transport": m.transport,
        "realm": m.realm, "cname": m.cname, "sname": m.sname,
        "etypes": [kerberos.ETYPE_NAMES.get(e, e) for e in m.etypes],
        "enc_etype": kerberos.ETYPE_NAMES.get(m.enc_etype, m.enc_etype) if m.enc_etype is not None else None,
        "ticket_etype": kerberos.ETYPE_NAMES.get(m.ticket_etype, m.ticket_etype) if m.ticket_etype is not None else None,
        "weak_etypes": [kerberos.ETYPE_NAMES.get(e, e) for e in m.weak_etypes],
        "preauth": m.preauth, "error_code": m.error_code, "error": m.error_name,
        "hashes": m.extractable_hashes(),
        "ts": m.ts,
    }


def _ntlm_json(f) -> dict:
    a = f.auth
    return {
        "client": f.client, "server": f.server, "carrier": f.carrier, "target": f.target,
        "version": a.ntlm_version if a else None,
        "domain": a.domain if a else None,
        "user": a.user if a else None,
        "workstation": a.workstation if a else None,
        "challenge": f.challenge.hex() if f.challenge else None,
        "hashcat": f.hashcat or None,
        "hashcat_mode": f.mode or None,
    }


def _tds_json(f) -> dict:
    info = f.info
    d = {"client": f.client, "server": f.server, "encryption": info.encryption}
    if info.login:
        lg = info.login
        d["login"] = {
            "auth_type": lg.auth_type, "username": lg.username, "password": lg.password,
            "hostname": lg.hostname, "appname": lg.appname, "servername": lg.servername,
            "database": lg.database, "client_mac": lg.client_mac, "sspi_present": lg.sspi_present,
        }
    return d


def _ldap_json(f) -> dict:
    b = f.bind
    return {
        "client": f.client, "server": f.server, "kind": b.kind, "method": b.method,
        "dn": b.dn, "mechanism": b.mechanism, "cleartext": b.cleartext,
        "password": b.password or None, "result_code": b.result_code, "result": b.result_name,
    }


def _http_json(f) -> dict:
    a = f.auth
    return {
        "client": f.client, "server": f.server, "direction": a.direction, "scheme": a.scheme,
        "host": a.host, "method": a.method, "uri": a.uri, "status": a.status,
        "username": a.username or None, "password": a.password or None, "ntlm": a.ntlm_present,
    }


# ---------------------------------------------------------------------------
# Hashcat export
# ---------------------------------------------------------------------------
# SPN service classes whose owner is a computer/machine account (random,
# uncrackable password) rather than a user/service account.
_MACHINE_SPN = {
    "host", "cifs", "ldap", "gc", "dns", "restrictedkrbhost", "termsrv",
    "wsman", "rpcss", "exchangemdb", "exchangerfr", "exchangeab",
}
CRACKABLE_CLASSES = {"user", "service"}
CLASS_NOTE = {
    "user": "user account (best target)",
    "service": "service account (good target)",
    "machine": "computer/machine account - random pw, skip",
    "krbtgt": "krbtgt - random pw, skip",
    "system": "system account (e.g. HealthMailbox) - random pw, skip",
    "unknown": "unclassified",
}


def classify_account(name: str) -> str:
    """Classify the account behind a hash so we know if it's worth cracking."""
    n = (name or "").strip()
    if not n:
        return "unknown"
    low = n.lower()
    if n.endswith("$"):
        return "machine"
    if low.startswith("krbtgt"):
        return "krbtgt"
    if "healthmailbox" in low:
        return "system"
    if "/" in n:                                   # SPN: service-class/host...
        return "machine" if low.split("/", 1)[0] in _MACHINE_SPN else "service"
    return "user"


def hash_records(result: AnalysisResult) -> list[dict]:
    """All crackable hashes with their target account + classification.

    Each record: ``{format, mode, hash, account, klass, crackable}``.
    For Kerberoast the classification is keyed on the SPN (the ticket is
    encrypted with the SPN owner's key); for AS-REP/pre-auth on the user.
    """
    recs: list[dict] = []
    for f in result.ntlm:
        if f.hashcat and f.mode:
            mode = f.mode.split()[0]
            fmt = {"5600": "netntlmv2", "5500": "netntlmv1"}.get(mode, "netntlm")
            acct = f.auth.user if f.auth else ""
            recs.append({"format": fmt, "mode": mode, "hash": f.hashcat, "account": acct})
    for f in result.kerberos:
        for hd in f.msg.extractable_hashes():
            parts = hd["hash"].split("$")
            fmt = parts[1] if len(parts) > 1 and parts[1] else "krb5"
            acct = (hd["spn"] if fmt == "krb5tgs" and hd.get("spn") else hd["user"])
            recs.append({"format": fmt, "mode": hd["mode"], "hash": hd["hash"], "account": acct})
    for f in result.radius:
        if f.hashcat:
            fmt = "mschapv2" if "v2" in f.version else "mschap"
            recs.append({"format": fmt, "mode": f.mode or "5500", "hash": f.hashcat, "account": f.username})
    for f in result.eap:
        if f.hashcat:
            fmt = "eapmd5" if f.mode == "4800" else "eapmschapv2"
            recs.append({"format": fmt, "mode": f.mode, "hash": f.hashcat, "account": f.identity})
    _APP_FMT = {"10200": "crammd5", "11100": "postgres", "11200": "mysql", "11400": "sip",
                "25100": "snmpv3", "26700": "snmpv3", "26800": "snmpv3", "26900": "snmpv3", "27300": "snmpv3"}
    for f in result.app_auth:
        if f.hashcat and f.mode and f.tool == "hashcat":
            recs.append({"format": _APP_FMT.get(f.mode, f.protocol.lower()),
                         "mode": f.mode, "hash": f.hashcat, "account": f.account})
    for f in result.wpa:
        if f.hashcat:
            recs.append({"format": "wpa", "mode": "22000", "hash": f.hashcat,
                         "account": f.essid or f.bssid})
    seen, out = set(), []
    for r in recs:
        if r["hash"] in seen:
            continue
        seen.add(r["hash"])
        r["klass"] = classify_account(r["account"])
        r["crackable"] = r["klass"] in CRACKABLE_CLASSES
        out.append(r)
    return out


def collect_hashes(result: AnalysisResult) -> dict:
    """Group all hashes by (format, mode). ``{(format, mode): set(hashes)}``."""
    groups: dict[tuple, set] = {}
    for r in hash_records(result):
        groups.setdefault((r["format"], str(r["mode"])), set()).add(r["hash"])
    return groups


def export_hashcat(result: AnalysisResult, pcap_path: str, out_dir: str | None = None,
                   priority: bool = True) -> list[dict]:
    """Write hashcat files named ``<pcap-stem>_<hashtype>.txt``.

    One file per hashcat mode. When *priority* is set and a type contains a mix
    of crackable (user/service) and uncrackable (machine/krbtgt/system)
    accounts, an extra ``<stem>_<type>_priority.txt`` is written containing only
    the worth-cracking hashes. Returns ``{file, path, format, mode, count, kind}``
    (kind is "all" or "priority").
    """
    stem = os.path.splitext(os.path.basename(pcap_path))[0]
    if out_dir is None:
        out_dir = os.path.dirname(os.path.abspath(pcap_path)) or "."
    os.makedirs(out_dir, exist_ok=True)

    recs = hash_records(result)
    groups: dict[tuple, list] = {}
    for r in recs:
        groups.setdefault((r["format"], str(r["mode"])), []).append(r)
    modes_per_fmt: dict[str, set] = {}
    for fmt, mode in groups:
        modes_per_fmt.setdefault(fmt, set()).add(mode)

    def _write(name, hashes):
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            for h in sorted(hashes):
                fh.write(h + "\n")
        return path

    written = []
    for (fmt, mode), rs in sorted(groups.items()):
        suffix = f"_m{mode}" if len(modes_per_fmt[fmt]) > 1 else ""
        all_hashes = {r["hash"] for r in rs}
        name = f"{stem}_{fmt}{suffix}.txt"
        written.append({"file": name, "path": _write(name, all_hashes),
                        "format": fmt, "mode": mode, "count": len(all_hashes), "kind": "all"})
        if priority:
            crack = {r["hash"] for r in rs if r["crackable"]}
            if crack and len(crack) < len(all_hashes):
                pname = f"{stem}_{fmt}{suffix}_priority.txt"
                written.append({"file": pname, "path": _write(pname, crack),
                                "format": fmt, "mode": mode, "count": len(crack), "kind": "priority"})
    return written


def classify_report(result: AnalysisResult) -> dict:
    """Account classification summary: ``{klass: sorted([account, ...])}``."""
    by: dict[str, set] = {}
    for r in hash_records(result):
        by.setdefault(r["klass"], set()).add(r["account"] or "(unknown)")
    return {k: sorted(v) for k, v in by.items()}
