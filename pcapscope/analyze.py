"""The analysis engine: one pass over the capture, then per-connection auth
protocol analysis.

Produces an :class:`AnalysisResult` carrying validation info, protocol/flow
statistics, and the authentication findings (Kerberos, NTLM/NetNTLM, MSSQL/TDS,
LDAP, HTTP auth) plus a list of troubleshooting anomalies.
"""

from __future__ import annotations

import re
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from . import (appauth, cleartext, dot11, eap, httpauth, kerberos, ldap, names,
               ntlm, radius, tds, tls)
from .layers import (
    ACK, FIN, RST, SYN, Decoded, PROTO_NAMES, TCPStream, conn_key, decode, tcp_flag_str,
)
from .reader import CaptureInfo, CaptureReader

# Well-known ports -> service label (for flow labelling and analyzer routing).
SERVICE_PORTS = {
    53: "DNS", 67: "DHCP", 68: "DHCP", 88: "Kerberos", 135: "MS-RPC",
    137: "NetBIOS", 138: "NetBIOS", 139: "SMB", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 464: "Kerberos-kpasswd", 636: "LDAPS", 1433: "MSSQL",
    1812: "RADIUS", 1813: "RADIUS", 3268: "LDAP-GC", 3269: "LDAPS-GC",
    3389: "RDP", 5985: "WinRM", 5986: "WinRM-HTTPS", 80: "HTTP", 8080: "HTTP",
    8000: "HTTP", 8888: "HTTP", 3128: "HTTP-proxy", 88_64: "Kerberos",
}
KERBEROS_PORTS = {88, 464}
LDAP_PORTS = {389, 3268}
LDAPS_PORTS = {636, 3269}
TDS_PORTS = {1433}
HTTP_PORTS = {80, 8080, 8000, 8888, 3128, 5985}
HTTPS_PORTS = {443, 5986}
TLS_PORTS = {636, 3269, 443, 5986, 989, 990, 993, 995}
SMB_PORTS = {445, 139}
RADIUS_PORTS = {1812, 1813, 1645, 1646}
# cleartext / legacy app protocols (port -> analyzer name)
CLEARTEXT_TCP = {21: "ftp", 23: "telnet", 25: "smtp", 587: "smtp", 110: "pop3", 143: "imap"}
SNMP_PORTS = {161, 162}
DNS_PORTS = {53}
MDNS_PORTS = {5353}
LLMNR_PORTS = {5355}
DHCP_PORTS = {67, 68}
MAIL_PORTS = {25, 587, 110, 143}          # also try CRAM-MD5 here
POSTGRES_PORTS = {5432}
MYSQL_PORTS = {3306}
VNC_PORTS = {5900, 5901, 5902, 5903, 5904, 5905, 5906}
SIP_PORTS = {5060, 5061}
RDP_PORTS = {3389}
# TLS also on RDP (3389) for the server cert
TLS_PORTS = TLS_PORTS | {3389}


@dataclass
class NtlmFinding:
    client: str = ""
    server: str = ""
    carrier: str = ""              # SMB / HTTP / LDAP / MSSQL / RPC / unknown
    auth: ntlm.NtlmAuth | None = None
    challenge: bytes = b""
    target: str = ""
    hashcat: str = ""
    mode: str = ""
    ts: float = 0.0


@dataclass
class KerbFinding:
    msg: kerberos.KerberosMsg = None
    client: str = ""
    server: str = ""


@dataclass
class TdsFinding:
    client: str = ""
    server: str = ""
    info: tds.TdsInfo = None


@dataclass
class LdapFinding:
    client: str = ""
    server: str = ""
    bind: ldap.LdapBind = None


@dataclass
class TlsFinding:
    client: str = ""
    server: str = ""
    service: str = ""
    info: tls.TlsInfo = None


@dataclass
class RadiusFinding:
    client: str = ""              # NAS
    server: str = ""              # RADIUS server
    username: str = ""
    method: str = ""
    nas: str = ""
    calling_station: str = ""
    result: str = ""
    hashcat: str = ""
    mode: str = ""               # 5500 for MS-CHAP(v2)
    version: str = ""
    password: str = ""           # decrypted PAP password (once secret known)
    secret: str = ""             # the validated shared secret (once known)
    secret_valid: bool = False   # secret confirmed against an authenticator
    # internal crypto material (not serialised to JSON)
    req_authenticator: bytes = b""
    resp_raw: bytes = b""
    userpw_enc: bytes = b""
    msgauth: bytes = b""
    msgauth_packet: bytes = b""

    @property
    def can_recover_secret(self) -> bool:
        return bool((self.resp_raw and self.req_authenticator) or (self.msgauth and self.msgauth_packet))


@dataclass
class CleartextFinding:
    protocol: str = ""            # FTP / TELNET / SMTP / POP3 / IMAP / SNMP
    client: str = ""
    server: str = ""
    mechanism: str = ""
    username: str = ""
    password: str = ""
    result: str = ""
    note: str = ""


RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
               4: "NOTIMP", 5: "REFUSED", 8: "NOTZONE"}


@dataclass
class DnsTxn:
    """One DNS query + its response (or a timed-out query)."""
    qid: int = 0
    qname: str = ""
    qtype: str = ""
    client: str = ""
    server: str = ""
    ts_q: float = 0.0
    ts_r: float = 0.0          # 0 = no response seen
    rcode: int = -1            # -1 = timeout/no response
    answers: list = field(default_factory=list)   # (name, type, value)
    authority: list = field(default_factory=list)
    source: str = "DNS"        # DNS / mDNS / LLMNR
    aa: bool = False           # authoritative answer
    tc: bool = False           # truncated

    @property
    def rcode_name(self) -> str:
        if self.rcode == -1:
            return "TIMEOUT"
        return RCODE_NAMES.get(self.rcode, str(self.rcode))

    @property
    def latency_ms(self) -> float | None:
        if self.ts_r and self.ts_q:
            return (self.ts_r - self.ts_q) * 1000.0
        return None

    @property
    def answered(self) -> bool:
        return self.ts_r > 0


@dataclass
class HostName:
    name: str = ""
    kind: str = ""               # dns-query / A / AAAA / PTR / CNAME / SNI / cert-CN / cert-SAN / http-host / dhcp / mDNS / LLMNR / SPN
    ip: str = ""                 # associated IP (resolved value or the server)
    mac: str = ""
    source: str = ""


@dataclass
class WpaFinding:
    bssid: str = ""
    sta: str = ""
    essid: str = ""
    kind: str = ""               # EAPOL / PMKID
    hashcat: str = ""
    mode: str = "22000"
    note: str = ""


@dataclass
class AppAuthFinding:
    protocol: str = ""           # CRAM-MD5 / PostgreSQL / MySQL / SIP / VNC / HTTP-Digest / RDP
    client: str = ""
    server: str = ""
    account: str = ""
    hashcat: str = ""
    mode: str = ""               # hashcat -m (empty if none)
    tool: str = ""               # hashcat / john / ""
    note: str = ""


@dataclass
class EapFinding:
    client: str = ""              # NAS / supplicant
    server: str = ""              # RADIUS server / authenticator
    carrier: str = "RADIUS"       # "RADIUS" or "802.1X" (EAPOL)
    identity: str = ""            # outer identity
    method: str = ""
    methods: list = field(default_factory=list)
    result: str = ""
    tunnelled: bool = False       # PEAP/TTLS/TLS inner is encrypted
    nak_to: str = ""
    hashcat: str = ""
    mode: str = ""               # 4800 (EAP-MD5) or 5500 (EAP-MSCHAPv2)
    version: str = ""
    # server certificate from the (cleartext) EAP-TLS handshake
    sni: str = ""
    tls_version: str = ""
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_sans: list = field(default_factory=list)
    not_after: str = ""


@dataclass
class HttpAuthFinding:
    client: str = ""
    server: str = ""
    auth: httpauth.HttpAuth = None


@dataclass
class NetFlow:
    """A unidirectional 5-tuple flow record (NetFlow v5 style)."""
    src: str = ""
    dst: str = ""
    sport: int = 0
    dport: int = 0
    proto: int = 0
    packets: int = 0
    bytes: int = 0
    first: float = 0.0
    last: float = 0.0
    flags: int = 0               # cumulative TCP flags (OR)
    tos: int = 0

    @property
    def proto_name(self):
        return PROTO_NAMES.get(self.proto, str(self.proto))

    @property
    def duration(self):
        return max(0.0, self.last - self.first)


@dataclass
class Conversation:
    proto: str = ""
    a: str = ""
    b: str = ""
    service: str = ""
    packets: int = 0
    bytes: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    syn: int = 0
    synack: int = 0
    rst: int = 0
    fin: int = 0
    retrans: int = 0

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)


@dataclass
class AnalysisResult:
    info: CaptureInfo
    proto_stats: Counter = field(default_factory=Counter)
    service_stats: Counter = field(default_factory=Counter)
    talkers_bytes: Counter = field(default_factory=Counter)
    talkers_pkts: Counter = field(default_factory=Counter)
    conversations: list[Conversation] = field(default_factory=list)
    netflow: list[NetFlow] = field(default_factory=list)
    kerberos: list[KerbFinding] = field(default_factory=list)
    ntlm: list[NtlmFinding] = field(default_factory=list)
    tds: list[TdsFinding] = field(default_factory=list)
    ldap: list[LdapFinding] = field(default_factory=list)
    http_auth: list[HttpAuthFinding] = field(default_factory=list)
    tls: list[TlsFinding] = field(default_factory=list)
    radius: list[RadiusFinding] = field(default_factory=list)
    eap: list[EapFinding] = field(default_factory=list)
    cleartext: list[CleartextFinding] = field(default_factory=list)
    app_auth: list[AppAuthFinding] = field(default_factory=list)
    wpa: list[WpaFinding] = field(default_factory=list)
    dns: list[DnsTxn] = field(default_factory=list)
    hostnames: list[HostName] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)

    def add_name(self, name, kind, ip="", mac="", source=""):
        name = (name or "").strip().rstrip(".")
        if not name or name == "<Root>":
            return
        key = (name.lower(), kind, ip)
        if key in self._name_keys:
            return
        self._name_keys.add(key)
        self.hostnames.append(HostName(name=name, kind=kind, ip=ip, mac=mac, source=source))

    _name_keys: set = field(default_factory=set, repr=False)

    # rolled-up TCP health
    tcp_syn: int = 0
    tcp_synack: int = 0
    tcp_rst: int = 0
    tcp_fin: int = 0
    tcp_retrans: int = 0
    failed_handshakes: int = 0
    reset_conns: int = 0

    # duplicate-frame accounting (e.g. pktmon multi-component captures)
    duplicate_frames: int = 0
    deduped: bool = False


class _Conn:
    """Mutable per-connection state during the pass."""

    __slots__ = ("conv", "stream", "client_dir", "saw_syn", "saw_synack",
                 "next_seq", "ports")

    def __init__(self, conv: Conversation):
        self.conv = conv
        self.stream = TCPStream()
        self.client_dir = None          # (src_ip,sport,dst_ip,dport) of SYN sender
        self.saw_syn = False
        self.saw_synack = False
        self.next_seq = {}              # direction tuple -> next expected seq
        self.ports = set()


def _service(sport: int, dport: int) -> str:
    for p in (dport, sport):
        if p in SERVICE_PORTS:
            return SERVICE_PORTS[p]
    return ""


def analyze(path: str, reassemble_cap: int = 262144,
            dedup: bool = False, dedup_window: float = 0.05) -> AnalysisResult:
    reader = CaptureReader(path)
    result = AnalysisResult(info=reader.info)
    result.deduped = dedup
    conns: dict[tuple, _Conn] = {}
    seen: dict[int, float] = {}      # frame-body hash -> last timestamp seen
    radius_pkts: list = []           # (RadiusPacket, sip, dip, sport, dport, ts)
    eapol_items: list = []           # (eth_src, eth_dst, eapol_payload) for 802.1X
    wifi_ssids: dict = {}            # bssid -> essid (from beacons)
    wifi_keys: list = []             # (bssid, sta, EapolKey)
    flows: dict = {}                 # directed 5-tuple -> NetFlow
    dns_raw: list = []               # raw DNS datagrams for Q/R correlation

    for pkt in reader:
        if pkt.linktype in dot11.WIFI_LINKTYPES:
            _dot11_frame(result, pkt, wifi_ssids, wifi_keys)
            continue
        # Detect (and optionally drop) exact-duplicate frames captured at
        # multiple observation points - common with Windows pktmon, which can
        # record each packet 2-4x. Window-bounded so genuine retransmits
        # (seconds apart) are preserved.
        h = hash(pkt.data)
        prev = seen.get(h)
        seen[h] = pkt.ts
        if prev is not None and (pkt.ts == 0.0 or 0.0 <= pkt.ts - prev <= dedup_window):
            result.duplicate_frames += 1
            if dedup:
                continue
        if len(seen) > 200000:
            cutoff = pkt.ts - dedup_window
            seen = {k: v for k, v in seen.items() if v >= cutoff}

        d = decode(pkt.data, pkt.linktype)
        if d is None:
            result.proto_stats["non-IP/undecoded"] += 1
            continue
        _account_stats(result, d, pkt.orig_len)
        if d.src_ip:                                  # unidirectional NetFlow record
            key = (d.src_ip, d.dst_ip, d.src_port, d.dst_port, d.proto)
            fl = flows.get(key)
            if fl is None:
                fl = NetFlow(src=d.src_ip, dst=d.dst_ip, sport=d.src_port, dport=d.dst_port,
                             proto=d.proto, first=pkt.ts or 0.0, tos=d.tos)
                flows[key] = fl
            fl.packets += 1
            fl.bytes += pkt.orig_len
            if pkt.ts:
                if not fl.first:
                    fl.first = pkt.ts
                fl.last = pkt.ts
            fl.flags |= d.tcp_flags
        if d.l3 == "EAPOL" and d.payload:
            eapol_items.append((d.eth_src, d.eth_dst, d.payload))
        if d.l4 in ("TCP", "UDP"):
            key = conn_key(d)
            conn = conns.get(key)
            if conn is None:
                conv = Conversation(
                    proto=d.l4, a=f"{d.src_ip}:{d.src_port}", b=f"{d.dst_ip}:{d.dst_port}",
                    service=_service(d.src_port, d.dst_port), first_ts=pkt.ts or 0.0,
                )
                conn = _Conn(conv)
                conns[key] = conn
            _update_conn(conn, d, pkt)
            if d.l4 == "TCP":
                _reassemble(conn, d)
            elif d.l4 == "UDP":
                _udp_payload(result, conn, d, pkt, dns_raw)
                if (d.src_port in RADIUS_PORTS or d.dst_port in RADIUS_PORTS) and d.payload:
                    rp = radius.parse(d.payload)
                    if rp is not None:
                        radius_pkts.append((rp, d.src_ip, d.dst_ip, d.src_port, d.dst_port, pkt.ts or 0.0))

    # second phase: per-connection auth analysis on reassembled streams
    for conn in conns.values():
        result.conversations.append(conn.conv)
        if conn.conv.proto == "TCP":
            _finalize_tcp_conn(result, conn)

    _finalize_radius(result, radius_pkts)
    _finalize_eap(result, radius_pkts)
    _finalize_eapol(result, eapol_items)
    _finalize_wpa(result, wifi_ssids, wifi_keys)
    _finalize_dns(result, dns_raw)
    _finalize_names(result)
    result.netflow = sorted(flows.values(), key=lambda f: (f.first or 0.0, -f.bytes))
    _roll_up(result, conns)
    _derive_anomalies(result)
    return result


def _dot11_frame(result: AnalysisResult, pkt, ssids: dict, keys: list) -> None:
    result.proto_stats["802.11"] += 1
    frame = dot11.strip_radiotap(pkt.data, pkt.linktype)
    d = dot11.parse(frame)
    if d is None:
        return
    if d.ftype == 0:                                  # management
        ssid = dot11.beacon_ssid(d)
        if ssid:
            ssids[dot11._mac(d.bssid)] = ssid
        return
    if d.ftype == 2:                                  # data - look for EAPOL-Key
        k = dot11.extract_eapol_key(d)
        if k is not None and k.msg:
            keys.append((dot11._mac(d.bssid), dot11._mac(d.sta), k))


def _finalize_wpa(result: AnalysisResult, ssids: dict, keys: list) -> None:
    seen = set()
    # PMKID (from M1) - no full handshake needed
    for bssid, sta, k in keys:
        if k.msg == 1 and k.pmkid:
            essid = ssids.get(bssid, "")
            tag = ("PMKID", bssid, sta)
            if tag in seen:
                continue
            seen.add(tag)
            ap = bytes.fromhex(bssid.replace(":", ""))
            st = bytes.fromhex(sta.replace(":", ""))
            result.wpa.append(WpaFinding(
                bssid=bssid, sta=sta, essid=essid, kind="PMKID", mode="22000",
                hashcat=dot11.pmkid_hash(k.pmkid, ap, st, essid),
                note="" if essid else "SSID unknown (no beacon captured)"))
    # EAPOL M1+M2 pairs
    m1 = {}
    for bssid, sta, k in keys:
        if k.msg == 1:
            m1[(bssid, sta)] = k
    for bssid, sta, k in keys:
        if k.msg != 2:
            continue
        a = m1.get((bssid, sta))
        if a is None:
            continue
        essid = ssids.get(bssid, "")
        tag = ("EAPOL", bssid, sta)
        if tag in seen:
            continue
        seen.add(tag)
        ap = bytes.fromhex(bssid.replace(":", ""))
        st = bytes.fromhex(sta.replace(":", ""))
        result.wpa.append(WpaFinding(
            bssid=bssid, sta=sta, essid=essid, kind="EAPOL", mode="22000",
            hashcat=dot11.eapol_hash(k.mic, ap, st, essid, a.nonce, dot11.zero_mic(k)),
            note="" if essid else "SSID unknown (no beacon captured)"))


def _collect_dns(result: AnalysisResult, payload: bytes, label: str) -> None:
    msg = names.parse_dns(payload)
    if not msg:
        return
    qkind = "dns-query" if label == "DNS" else label
    for qn, _qt in msg["queries"]:
        result.add_name(qn, qkind, source=f"{label} query")
    for nm, rt, val in msg["answers"]:
        if rt in ("A", "AAAA") and val:
            result.add_name(nm, rt, ip=val, source=f"{label} answer")
        elif rt == "PTR" and val:
            ip = ""
            if nm.lower().endswith(".in-addr.arpa"):
                ip = ".".join(reversed(nm.split(".")[:4]))
            result.add_name(val, "PTR", ip=ip, source=f"{label} PTR")
        elif rt in ("CNAME", "SRV", "NS") and val:
            result.add_name(val, rt, source=f"{label} {rt}")


def _finalize_dns(result: AnalysisResult, dns_raw: list) -> None:
    """Correlate DNS query/response pairs from raw collected datagrams."""
    pending: dict[tuple, tuple] = {}    # (qid, client, server) -> (ts, qname, qtype, source)
    txns: list[DnsTxn] = []

    for ts, src_ip, dst_ip, src_port, dst_port, payload, source in dns_raw:
        r = names.parse_dns_full(payload)
        if r is None:
            continue
        qid = r["qid"]
        if r["qr"] == 0:                # query: client -> server
            key = (qid, src_ip, dst_ip)
            if key not in pending and r["queries"]:
                q = r["queries"][0]
                pending[key] = (ts, q[0], q[1], source)
        else:                           # response: server -> client
            key = (qid, dst_ip, src_ip)
            if key in pending:
                q_ts, qname, qtype, src = pending.pop(key)
                txns.append(DnsTxn(
                    qid=qid, qname=qname, qtype=qtype,
                    client=dst_ip, server=src_ip,
                    ts_q=q_ts, ts_r=ts,
                    rcode=r["rcode"], answers=r["answers"],
                    authority=r["authority"],
                    source=src, aa=r["aa"], tc=r["tc"]))

    # Unanswered queries -> TIMEOUT
    for (qid, client, server), (ts, qname, qtype, source) in pending.items():
        txns.append(DnsTxn(qid=qid, qname=qname, qtype=qtype,
                           client=client, server=server,
                           ts_q=ts, ts_r=0.0, rcode=-1, source=source))

    result.dns = sorted(txns, key=lambda t: t.ts_q)


def _finalize_names(result: AnalysisResult) -> None:
    """Harvest host names from the auth findings (Kerberos SPNs, TDS, NTLM)."""
    for kf in result.kerberos:
        spn = kf.msg.sname
        if spn and "/" in spn:
            host = spn.split("/", 1)[1].split(":")[0]
            if "." in host or not host.endswith("$"):
                result.add_name(host, "SPN", source="Kerberos")
    for f in result.tds:
        if f.info and f.info.login and f.info.login.servername:
            result.add_name(f.info.login.servername, "MSSQL-server",
                            ip=f.server.rsplit(":", 1)[0], source="MSSQL")


def _finalize_radius(result: AnalysisResult, pkts: list) -> None:
    # index responses (server -> NAS) so we can mark Accept/Reject and grab raw
    responses = {}
    for rp, sip, dip, sport, dport, ts in pkts:
        if rp.code in (2, 3, 11):
            responses[(rp.ident, dip, sip)] = rp           # key by (ident, nas, radius)
    for rp, sip, dip, sport, dport, ts in pkts:
        if rp.code != 1:                          # Access-Request only
            continue
        resp = responses.get((rp.ident, sip, dip))
        f = RadiusFinding(
            client=f"{sip}:{sport}", server=f"{dip}:{dport}",
            username=radius._username(rp), method=radius.auth_method(rp),
            nas=radius.nas_info(rp), calling_station=radius.calling_station(rp),
            result=resp.code_name if resp is not None else "(no response captured)",
            req_authenticator=rp.authenticator,
            userpw_enc=rp.get(radius.A_USER_PASSWORD) or b"",
            msgauth=rp.msgauth,
            msgauth_packet=radius.msgauth_zeroed(rp) if rp.msgauth else b"",
        )
        if resp is not None:
            f.resp_raw = resp.raw
        mh = radius.mschap_hash(rp)
        if mh:
            f.hashcat, f.version = mh
            f.mode = "5500"
        result.radius.append(f)


def _finalize_eap(result: AnalysisResult, pkts: list) -> None:
    # group EAP packets by NAS<->server IP pair, in capture order
    pairs: dict[tuple, list] = {}
    for rp, sip, dip, sport, dport, ts in pkts:
        eapdata = b"".join(rp.getall(radius.A_EAP_MESSAGE))
        if not eapdata:
            continue
        ep = eap.parse(eapdata)
        if ep is None:
            continue
        client, server = (sip, dip) if rp.code == 1 else (dip, sip)
        un = radius._username(rp)
        pairs.setdefault(tuple(sorted((sip, dip))), []).append((ep, client, server, un))

    for seq in pairs.values():
        # split into conversations at each EAP Success/Failure terminal
        conv = []
        for item in seq:
            conv.append(item)
            if item[0].code in (3, 4):
                _emit_eap(result, conv)
                conv = []
        if conv:
            _emit_eap(result, conv)


def _emit_eap(result: AnalysisResult, conv: list, carrier: str = "RADIUS") -> None:
    if not conv:
        return
    eaps = [c[0] for c in conv]
    client = next((c[1] for c in conv if c[1]), "")
    server = next((c[2] for c in conv if c[2]), "")
    hint = next((c[3] for c in conv if c[3]), "")
    info = eap.analyze_conversation(eaps, identity_hint=hint)
    result.eap.append(EapFinding(
        client=client, server=server, carrier=carrier, identity=info["identity"],
        method=info["method"], methods=info["methods"], result=info["result"],
        tunnelled=info["tunnelled"], nak_to=info["nak_to"],
        hashcat=info["hashcat"], mode=info["mode"], version=info["version"],
        sni=info["sni"], tls_version=info["tls_version"], cert_subject=info["cert_subject"],
        cert_issuer=info["cert_issuer"], cert_sans=info["cert_sans"], not_after=info["not_after"],
    ))


def _finalize_eapol(result: AnalysisResult, items: list) -> None:
    """items: (eth_src, eth_dst, eapol_payload) in capture order (802.1X)."""
    pairs: dict[tuple, list] = {}
    for src, dst, payload in items:
        parsed = eap.parse_eapol(payload)
        if parsed is None:
            continue
        etype, body = parsed
        if etype != 0:                       # only EAP-Packet carries EAP
            continue
        ep = eap.parse(body)
        if ep is None:
            continue
        client, server = (src, dst) if ep.code == 2 else (dst, src)
        pairs.setdefault(tuple(sorted((src, dst))), []).append((ep, client, server, ""))
    for seq in pairs.values():
        conv = []
        for item in seq:
            conv.append(item)
            if item[0].code in (3, 4):
                _emit_eap(result, conv, carrier="802.1X")
                conv = []
        if conv:
            _emit_eap(result, conv, carrier="802.1X")


def apply_radius_secret(result: AnalysisResult, secret: str) -> bool:
    """Validate *secret* against captured authenticators and decrypt PAP passwords.

    Returns True if the secret was confirmed correct by at least one packet.
    """
    sec = secret.encode()
    confirmed = False
    for f in result.radius:
        ok = False
        if f.resp_raw and f.req_authenticator:
            ok = radius.verify_response_auth(sec, f.req_authenticator, f.resp_raw)
        if not ok and f.msgauth and f.msgauth_packet:
            ok = radius.verify_msgauth(sec, f.msgauth_packet, f.msgauth)
        f.secret = secret
        f.secret_valid = ok
        confirmed = confirmed or ok
        if f.userpw_enc:
            f.password = radius.decrypt_pap(sec, f.req_authenticator, f.userpw_enc)
    return confirmed


def _radius_secret_targets(result: AnalysisResult) -> list:
    targets = []
    for f in result.radius:
        if f.resp_raw and f.req_authenticator:
            targets.append(("resp", f.req_authenticator, f.resp_raw))
        if f.msgauth and f.msgauth_packet:
            targets.append(("msgauth", f.msgauth_packet, f.msgauth))
    return targets


def recover_radius_secret(result: AnalysisResult, candidates) -> str | None:
    """Dictionary-attack the RADIUS shared secret. *candidates* yields bytes."""
    targets = _radius_secret_targets(result)
    found = radius.crack_secret(targets, candidates)
    if found is not None:
        try:
            return found.decode("utf-8", "replace")
        except Exception:
            return found.hex()
    return None


def _account_stats(result: AnalysisResult, d: Decoded, wire_len: int) -> None:
    if d.l3:
        result.proto_stats[d.l3] += 1
    if d.l4:
        result.proto_stats[d.l4] += 1
    if not d.l3 and not d.l4:
        result.proto_stats["non-IP"] += 1
    svc = _service(d.src_port, d.dst_port) if d.l4 in ("TCP", "UDP") else ""
    if svc:
        result.service_stats[svc] += 1
    if d.src_ip:
        result.talkers_bytes[d.src_ip] += wire_len
        result.talkers_pkts[d.src_ip] += 1
    if d.dst_ip:
        result.talkers_pkts[d.dst_ip] += 0  # ensure key exists


def _update_conn(conn: _Conn, d: Decoded, pkt) -> None:
    conv = conn.conv
    conv.packets += 1
    conv.bytes += pkt.orig_len
    if pkt.ts:
        conv.last_ts = pkt.ts
        if not conv.first_ts:
            conv.first_ts = pkt.ts
    conn.ports.add(d.src_port)
    conn.ports.add(d.dst_port)
    if d.l4 != "TCP":
        return
    f = d.tcp_flags
    if f & SYN and not (f & ACK):
        conv.syn += 1
        conn.saw_syn = True
        if conn.client_dir is None:
            conn.client_dir = (d.src_ip, d.src_port, d.dst_ip, d.dst_port)
    if (f & SYN) and (f & ACK):
        conv.synack += 1
        conn.saw_synack = True
    if f & RST:
        conv.rst += 1
    if f & FIN:
        conv.fin += 1


def _reassemble(conn: _Conn, d: Decoded) -> None:
    direction = (d.src_ip, d.src_port, d.dst_ip, d.dst_port)
    is_syn = bool(d.tcp_flags & SYN)
    # heuristic retransmission / out-of-order accounting
    if d.payload:
        nxt = conn.next_seq.get(direction)
        if nxt is not None and d.tcp_seq < nxt:
            conn.conv.retrans += 1
        end = (d.tcp_seq + len(d.payload)) & 0xFFFFFFFF
        if nxt is None or end > nxt:
            conn.next_seq[direction] = end
    conn.stream.add(direction, d.tcp_seq, d.payload, is_syn)


def _udp_payload(result: AnalysisResult, conn: _Conn, d: Decoded, pkt, dns_raw: list) -> None:
    # Kerberos over UDP (port 88/464) arrives one message per datagram.
    if (d.src_port in KERBEROS_PORTS or d.dst_port in KERBEROS_PORTS) and d.payload:
        for blob in kerberos.iter_messages(d.payload, "udp"):
            msg = kerberos.parse(blob, "udp")
            if msg:
                msg.src, msg.dst = f"{d.src_ip}:{d.src_port}", f"{d.dst_ip}:{d.dst_port}"
                msg.ts = pkt.ts or 0.0
                result.kerberos.append(KerbFinding(msg=msg, client=msg.src, server=msg.dst))
    # SIP digest over UDP (5060)
    if (d.src_port in SIP_PORTS or d.dst_port in SIP_PORTS) and d.payload:
        for fnd in appauth.digest_scan(d.payload, "SIP"):
            if not any(f.protocol == "SIP" and f.hashcat == fnd["hashcat"] for f in result.app_auth):
                result.app_auth.append(AppAuthFinding(
                    client=f"{d.src_ip}:{d.src_port}", server=f"{d.dst_ip}:{d.dst_port}",
                    protocol=fnd["protocol"], account=fnd.get("account", ""), hashcat=fnd.get("hashcat", ""),
                    mode=fnd.get("mode", ""), tool=fnd.get("tool", ""), note=fnd.get("note", "")))
    # DNS / mDNS / LLMNR hostnames + raw collection for Q/R correlation
    if (d.src_port in DNS_PORTS or d.dst_port in DNS_PORTS) and d.payload:
        _collect_dns(result, d.payload, "DNS")
        dns_raw.append((pkt.ts, d.src_ip, d.dst_ip, d.src_port, d.dst_port, d.payload, "DNS"))
    elif (d.src_port in MDNS_PORTS or d.dst_port in MDNS_PORTS) and d.payload:
        _collect_dns(result, d.payload, "mDNS")
        dns_raw.append((pkt.ts, d.src_ip, d.dst_ip, d.src_port, d.dst_port, d.payload, "mDNS"))
    elif (d.src_port in LLMNR_PORTS or d.dst_port in LLMNR_PORTS) and d.payload:
        _collect_dns(result, d.payload, "LLMNR")
        dns_raw.append((pkt.ts, d.src_ip, d.dst_ip, d.src_port, d.dst_port, d.payload, "LLMNR"))
    # DHCP client hostnames
    if (d.src_port in DHCP_PORTS or d.dst_port in DHCP_PORTS) and d.payload:
        info = names.parse_dhcp(d.payload)
        if info and (info["hostname"] or info["fqdn"]):
            result.add_name(info["fqdn"] or info["hostname"], "DHCP",
                            ip=info["requested_ip"], mac=info["mac"], source="DHCP")
    # SNMP v1/v2c community strings + v3 USM auth (UDP 161/162)
    if (d.src_port in SNMP_PORTS or d.dst_port in SNMP_PORTS) and d.payload:
        info = cleartext.analyze_snmp(d.payload)
        if info is not None and info["version"] in ("v1", "v2c"):
            if not any(f.protocol == "SNMP" and f.password == info["community"] for f in result.cleartext):
                result.cleartext.append(CleartextFinding(
                    protocol="SNMP", client=f"{d.src_ip}:{d.src_port}", server=f"{d.dst_ip}:{d.dst_port}",
                    mechanism=f"community ({info['version']})", username="", password=info["community"],
                    note="DEFAULT community" if info["default"] else ""))
        s3 = appauth.snmpv3(d.payload)
        if s3 is not None and not any(f.protocol == "SNMPv3" and f.hashcat == s3["hashcat"] for f in result.app_auth):
            result.app_auth.append(AppAuthFinding(
                client=f"{d.src_ip}:{d.src_port}", server=f"{d.dst_ip}:{d.dst_port}",
                protocol="SNMPv3", account=s3["account"], hashcat=s3["hashcat"],
                mode=s3["mode"], tool=s3["tool"], note=s3["note"]))


def _client_server(conn: _Conn) -> tuple[str, str, tuple | None, tuple | None]:
    """Return (client_ep, server_ep, client_dir, server_dir)."""
    cd = conn.client_dir
    if cd is None:
        # fall back to service port heuristic
        a_ip, a_port = conn.conv.a.rsplit(":", 1)
        b_ip, b_port = conn.conv.b.rsplit(":", 1)
        if int(b_port) in SERVICE_PORTS or int(b_port) < int(a_port):
            cd = (a_ip, int(a_port), b_ip, int(b_port))
        else:
            cd = (b_ip, int(b_port), a_ip, int(a_port))
    client_ep = f"{cd[0]}:{cd[1]}"
    server_ep = f"{cd[2]}:{cd[3]}"
    server_dir = (cd[2], cd[3], cd[0], cd[1])
    return client_ep, server_ep, cd, server_dir


def _finalize_tcp_conn(result: AnalysisResult, conn: _Conn) -> None:
    client_ep, server_ep, client_dir, server_dir = _client_server(conn)
    client_bytes = conn.stream.assemble(client_dir) if client_dir else b""
    server_bytes = conn.stream.assemble(server_dir) if server_dir else b""
    if not client_bytes and not server_bytes:
        return
    ports = conn.ports

    # --- Kerberos over TCP ---
    if ports & KERBEROS_PORTS:
        for stream, src, dst in ((client_bytes, client_ep, server_ep), (server_bytes, server_ep, client_ep)):
            for blob in kerberos.iter_messages(stream, "tcp"):
                msg = kerberos.parse(blob, "tcp")
                if msg:
                    msg.src, msg.dst = src, dst
                    result.kerberos.append(KerbFinding(msg=msg, client=client_ep, server=server_ep))

    # --- NTLM (any carrier) ---
    _scan_ntlm(result, conn, client_ep, server_ep, client_bytes, server_bytes, ports)

    # --- MSSQL / TDS ---
    if ports & TDS_PORTS:
        info = tds.analyze_stream(client_bytes, server_bytes)
        if info is not None:
            result.tds.append(TdsFinding(client=client_ep, server=server_ep, info=info))

    # --- LDAP (non-TLS) ---
    if ports & LDAP_PORTS:
        for stream in (client_bytes, server_bytes):
            for b in ldap.analyze_stream(stream):
                result.ldap.append(LdapFinding(client=client_ep, server=server_ep, bind=b))

    # --- TLS (LDAPS / HTTPS / etc.) ---
    server_ip = server_ep.rsplit(":", 1)[0]
    if (ports & TLS_PORTS) or tls.looks_like_tls(client_bytes):
        info = tls.analyze_stream(client_bytes, server_bytes)
        if info is not None:
            svc = _service(client_dir[1], client_dir[3]) if client_dir else ""
            result.tls.append(TlsFinding(client=client_ep, server=server_ep, service=svc, info=info))
            if info.sni:
                result.add_name(info.sni, "SNI", ip=server_ip, source="TLS")
            if info.cert_subject:
                result.add_name(info.cert_subject, "cert-CN", ip=server_ip, source="cert")
            for san in info.cert_sans:
                result.add_name(san, "cert-SAN", ip=server_ip, source="cert")

    # DNS over TCP (length-prefixed)
    if ports & DNS_PORTS:
        for stream in (client_bytes, server_bytes):
            off = 0
            while off + 2 <= len(stream):
                mlen = struct.unpack("!H", stream[off:off + 2])[0]
                if mlen == 0 or off + 2 + mlen > len(stream):
                    break
                _collect_dns(result, stream[off + 2:off + 2 + mlen], "DNS")
                off += 2 + mlen

    # --- Cleartext app protocols (FTP/TELNET/SMTP/POP3/IMAP) ---
    proto = next((CLEARTEXT_TCP[p] for p in ports if p in CLEARTEXT_TCP), None)
    if proto:
        fn = getattr(cleartext, f"analyze_{proto}")
        for cred in fn(client_bytes, server_bytes):
            result.cleartext.append(CleartextFinding(
                protocol=proto.upper(), client=client_ep, server=server_ep,
                mechanism=cred.get("mechanism", ""), username=cred.get("username", ""),
                password=cred.get("password", ""), result=cred.get("result", ""),
                note=cred.get("note", "")))

    # --- Challenge-response app auth (DB / VoIP / remote / mail CRAM-MD5) ---
    def _app(finding):
        if finding:
            result.app_auth.append(AppAuthFinding(
                client=client_ep, server=server_ep, protocol=finding["protocol"],
                account=finding.get("account", ""), hashcat=finding.get("hashcat", ""),
                mode=finding.get("mode", ""), tool=finding.get("tool", ""), note=finding.get("note", "")))

    if ports & MAIL_PORTS:
        _app(appauth.cram_md5(client_bytes, server_bytes))
    if ports & POSTGRES_PORTS:
        _app(appauth.postgres(client_bytes, server_bytes))
    if ports & MYSQL_PORTS:
        _app(appauth.mysql(client_bytes, server_bytes))
    if ports & VNC_PORTS:
        _app(appauth.vnc(client_bytes, server_bytes))
    if ports & RDP_PORTS:
        _app(appauth.rdp(client_bytes, server_bytes))
    if ports & SIP_PORTS:
        for fnd in appauth.digest_scan(client_bytes + b"\n" + server_bytes, "SIP"):
            _app(fnd)

    # --- HTTP auth ---
    if (ports & HTTP_PORTS) or client_bytes[:8].split(b" ", 1)[0] in (
        b"GET", b"POST", b"PUT", b"HEAD", b"OPTIONS", b"DELETE", b"PATCH", b"CONNECT", b"PROPFIND",
    ):
        for a in httpauth.analyze(client_bytes, server_bytes):
            result.http_auth.append(HttpAuthFinding(client=client_ep, server=server_ep, auth=a))
        for fnd in appauth.digest_scan(client_bytes, "HTTP"):
            _app(fnd)
        for m in re.finditer(rb"(?im)^Host:[ \t]*([^\r\n:]+)", client_bytes):
            result.add_name(m.group(1).decode("latin-1", "replace"), "http-host",
                            ip=server_ip, source="HTTP")


def _carrier(ports: set) -> str:
    if ports & SMB_PORTS:
        return "SMB"
    if ports & HTTP_PORTS:
        return "HTTP"
    if ports & LDAP_PORTS:
        return "LDAP"
    if ports & TDS_PORTS:
        return "MSSQL"
    if ports & {135}:
        return "MS-RPC"
    return "unknown"


def _scan_ntlm(result, conn, client_ep, server_ep, client_bytes, server_bytes, ports) -> None:
    # Challenge comes from server->client; authenticate from client->server.
    challenge = b""
    target = ""
    for off, mtype in ntlm.find_messages(server_bytes):
        if mtype == 2:
            ch = ntlm.parse_challenge(server_bytes, off)
            if ch and ch.server_challenge:
                challenge = ch.server_challenge
                target = ch.target_name
                break
    carrier = _carrier(ports)
    found_auth = False
    for off, mtype in ntlm.find_messages(client_bytes):
        if mtype == 3:
            auth = ntlm.parse_authenticate(client_bytes, off)
            if auth is None:
                continue
            found_auth = True
            f = NtlmFinding(client=client_ep, server=server_ep, carrier=carrier,
                            auth=auth, challenge=challenge, target=target)
            hc = auth.to_hashcat(challenge) if challenge else None
            if hc:
                f.hashcat, f.mode = hc
            result.ntlm.append(f)
    # Record a bare challenge-only observation if we saw type2 but no type3
    if challenge and not found_auth:
        result.ntlm.append(NtlmFinding(client=client_ep, server=server_ep, carrier=carrier,
                                       auth=None, challenge=challenge, target=target))


def _roll_up(result: AnalysisResult, conns: dict) -> None:
    for conn in conns.values():
        c = conn.conv
        if c.proto != "TCP":
            continue
        result.tcp_syn += c.syn
        result.tcp_synack += c.synack
        result.tcp_rst += c.rst
        result.tcp_fin += c.fin
        result.tcp_retrans += c.retrans
        if c.rst:
            result.reset_conns += 1
        if conn.saw_syn and not conn.saw_synack and c.bytes and c.packets <= 4:
            result.failed_handshakes += 1
        elif conn.saw_syn and not conn.saw_synack and c.rst:
            result.failed_handshakes += 1
    result.conversations.sort(key=lambda c: c.bytes, reverse=True)


def _derive_anomalies(result: AnalysisResult) -> None:
    a = result.anomalies
    info = result.info
    total = info.packet_count or 1
    if result.duplicate_frames and not result.deduped:
        pct = 100 * result.duplicate_frames / total
        if pct >= 15:
            a.append(
                f"{result.duplicate_frames} duplicate frames ({pct:.0f}% of capture) - "
                f"looks like a multi-component pktmon capture recording each packet several "
                f"times. Re-run with --dedup for accurate packet/byte/retransmission counts."
            )
    elif result.duplicate_frames and result.deduped:
        a.append(f"Dropped {result.duplicate_frames} duplicate frames (multi-component capture); counts below are de-duplicated.")
    if info.errors:
        a.append(f"Capture has {len(info.errors)} structural error(s) - file may be corrupt or truncated.")
    if info.truncated_count:
        a.append(
            f"{info.truncated_count} frame(s) captured shorter than on-wire length "
            f"(snaplen {info.snaplen or '?'}); payloads may be incomplete for deep analysis."
        )
    if result.failed_handshakes:
        a.append(f"{result.failed_handshakes} TCP connection(s) failed to complete the handshake (refused/filtered/timeout).")
    if result.reset_conns:
        a.append(f"{result.reset_conns} TCP connection(s) saw a RST (reset/refused).")
    if result.tcp_retrans:
        a.append(f"{result.tcp_retrans} TCP retransmission/out-of-order segment(s) (heuristic) - possible loss/latency.")

    # Kerberos weakness + failures
    weak = Counter()
    kerb_errors = Counter()
    for kf in result.kerberos:
        m = kf.msg
        for e in m.weak_etypes:
            weak[e] += 1
        if m.error_code is not None and m.error_code in kerberos.FAILURE_ERRORS:
            kerb_errors[m.error_name] += 1
    if weak:
        names = ", ".join(f"{kerberos.ETYPE_NAMES.get(e, e)}({n})" for e, n in weak.most_common())
        a.append(f"Weak Kerberos encryption types observed: {names} - RC4/DES enable Kerberoasting/AS-REP roasting and downgrade.")
    for name, n in kerb_errors.most_common():
        a.append(f"Kerberos failures: {name} x{n}.")

    # NTLM presence / version
    v1 = sum(1 for f in result.ntlm if f.auth and f.auth.ntlm_version == "NTLMv1")
    if v1:
        a.append(f"{v1} NTLMv1 authentication(s) observed - weak, crackable; should be disabled.")
    if any(f.auth for f in result.ntlm):
        a.append("NTLM authentication in use - prefer Kerberos; review whether NTLM can be restricted.")

    # MSSQL cleartext
    for f in result.tds:
        if f.info and f.info.encryption_raw in (0, 2):
            a.append(f"MSSQL {f.client}->{f.server} negotiated {f.info.encryption} - login/data exposed in clear.")
        if f.info and f.info.login and f.info.login.password:
            a.append(f"MSSQL SQL-auth credentials recovered for user '{f.info.login.username}'.")

    # LDAP cleartext binds
    for f in result.ldap:
        b = f.bind
        if b.kind == "request" and b.method == "simple" and b.password:
            a.append(f"LDAP simple bind with cleartext password for DN '{b.dn}' ({f.client}->{f.server}).")
        if b.kind == "response" and b.result_code == 49:
            a.append(f"LDAP invalidCredentials (49) on {f.server} - failed bind.")

    # HTTP Basic
    for f in result.http_auth:
        if f.auth.scheme.lower() == "basic" and f.auth.username:
            a.append(f"HTTP Basic credentials recovered ({f.auth.username}) to {f.auth.host or f.server}.")

    # TLS / LDAPS
    for f in result.tls:
        v = f.info.server_version or f.info.client_version
        label = f.service or "TLS"
        if v in ("SSL 3.0", "TLS 1.0", "TLS 1.1"):
            a.append(f"{label} {f.server} negotiated legacy {v} - deprecated, should be disabled.")
        if f.service in ("LDAPS", "LDAPS-GC") and f.info.is_tls:
            cert = f.info.cert_subject or (f.info.cert_sans[0] if f.info.cert_sans else "")
            a.append(f"LDAPS in use to {f.server} ({v or 'TLS'}{', cert ' + cert if cert else ''}) - bind is encrypted (good).")

    # RADIUS
    rad_hashes = [f for f in result.radius if f.hashcat]
    if rad_hashes:
        users = ", ".join(sorted({f.username for f in rad_hashes}))
        a.append(f"{len(rad_hashes)} RADIUS MS-CHAP(v2) hash(es) recovered ({users}) - crackable with hashcat -m 5500.")
    if any(f.method == "PAP" for f in result.radius):
        a.append("RADIUS PAP authentication observed - password is only obfuscated by the shared secret; prefer EAP-TLS.")
    rejects = [f for f in result.radius if f.result == "Access-Reject"]
    if rejects:
        a.append(f"{len(rejects)} RADIUS Access-Reject(s) - failed authentication "
                 f"({', '.join(sorted({f.username for f in rejects if f.username}))}).")

    # EAP / PEAP
    eap_hashes = [f for f in result.eap if f.hashcat]
    for f in eap_hashes:
        mode = "4800" if f.mode == "4800" else "5500"
        a.append(f"{f.version} hash recovered for '{f.identity or 'unknown'}' - crackable with hashcat -m {mode}.")
    if any(f.method == "MD5-Challenge" for f in result.eap):
        a.append("EAP-MD5 in use - weak, offline-crackable; disable in favour of PEAP/EAP-TLS.")
    leaky = [f for f in result.eap if f.tunnelled and f.identity
             and f.identity.lower() not in ("anonymous", "") and "anonymous" not in f.identity.lower()]
    if leaky:
        a.append("PEAP/TTLS exposing a real outer identity ("
                 + ", ".join(sorted({f.identity for f in leaky}))
                 + ") - enable identity privacy (anonymous outer identity).")

    # Cleartext / legacy auth
    ct_creds = [f for f in result.cleartext if f.protocol != "SNMP" and (f.username or f.password)]
    for f in ct_creds:
        cred = f.username + (":" + f.password if f.password else "")
        a.append(f"{f.protocol} credentials in cleartext: {cred} ({f.client} -> {f.server}) - protocol unencrypted.")
    snmp = [f for f in result.cleartext if f.protocol == "SNMP"]
    if snmp:
        comms = ", ".join(sorted({f.password for f in snmp if f.password}))
        a.append(f"SNMP community string(s) in cleartext: {comms}.")
    if any(f.note == "DEFAULT community" for f in snmp):
        a.append("SNMP using a DEFAULT community string (public/private) - trivial read/write access.")

    # Challenge-response app auth
    for f in result.app_auth:
        if f.hashcat and f.mode:
            who = f" for '{f.account}'" if f.account else ""
            a.append(f"{f.protocol} hash recovered{who} - crackable with hashcat -m {f.mode}.")
        elif f.protocol == "RDP" and f.note:
            a.append(f"RDP: {f.note} ({f.client} -> {f.server}).")
        elif f.protocol == "VNC" and f.hashcat:
            a.append(f"VNC challenge/response captured ({f.client} -> {f.server}) - crackable with john --format=vnc.")
        elif f.protocol == "HTTP-Digest":
            a.append(f"HTTP Digest auth for '{f.account}' - crackable offline.")
    if any(f.protocol == "RDP" and "no TLS" in f.note for f in result.app_auth):
        a.append("RDP using Standard Security (no TLS) - session is weakly protected; require NLA/TLS.")

    # WPA / Wi-Fi
    for f in result.wpa:
        net = f"SSID '{f.essid}'" if f.essid else f"BSSID {f.bssid}"
        a.append(f"WPA {f.kind} captured for {net} - crackable with hashcat -m 22000.")

    # DNS
    if result.dns:
        nxd = [t for t in result.dns if t.rcode == 3]
        timeouts = [t for t in result.dns if t.rcode == -1]
        servfails = [t for t in result.dns if t.rcode == 2]
        answered = [t for t in result.dns if t.answered]
        if nxd:
            rate = int(len(nxd) * 100 / len(result.dns))
            a.append(f"DNS: {len(nxd)} NXDOMAIN response(s) ({rate}% of queries).")
            if rate >= 40:
                a.append("DNS: high NXDOMAIN rate (>=40%) - possible enumeration, tunneling, or misconfigured client.")
        if servfails:
            a.append(f"DNS: {len(servfails)} SERVFAIL response(s) - check resolver/zone delegation.")
        if timeouts:
            a.append(f"DNS: {len(timeouts)} unanswered query/queries (timeout) - possible connectivity/firewall issue.")
        if answered:
            lats = [t.latency_ms for t in answered if t.latency_ms is not None]
            if lats:
                slow = [l for l in lats if l > 500]
                if slow:
                    a.append(f"DNS: {len(slow)} slow response(s) (>500 ms, max {max(slow):.0f} ms) - check resolver performance.")
