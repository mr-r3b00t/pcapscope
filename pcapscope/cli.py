"""Command-line interface for pcapscope."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import report
from .analyze import analyze
from .reader import CaptureError

# subcommand -> renderer function over an AnalysisResult
RENDERERS = {
    "validate": report.render_validation,
    "info": report.render_validation,
    "protocols": report.render_protocols,
    "talkers": report.render_talkers,
    "flows": report.render_conversations,
    "conversations": report.render_conversations,
    "tcp": report.render_tcp_health,
    "kerberos": report.render_kerberos,
    "ntlm": report.render_ntlm,
    "mssql": report.render_tds,
    "tds": report.render_tds,
    "ldap": report.render_ldap,
    "tls": report.render_tls,
    "ldaps": report.render_tls,
    "radius": report.render_radius,
    "cleartext": report.render_cleartext,
    "appauth": report.render_appauth,
    "wpa": report.render_wpa,
    "wifi": report.render_wpa,
    "dns": report.render_dns,
    "hostnames": report.render_hostnames,
    "hosts": report.render_hostnames,
    "names": report.render_hostnames,
    "http": report.render_http_auth,
    "findings": report.render_anomalies,
    "report": report.render_full,
}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pcapscope",
        description="Zero-dependency PCAP/PCAPNG analyzer for authentication troubleshooting "
                    "(Kerberos, NTLM/NetNTLM, MSSQL/TDS, LDAP, HTTP auth).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  pcapscope capture.pcapng              full report\n"
               "  pcapscope validate capture.pcap       integrity check only\n"
               "  pcapscope kerberos capture.pcapng     Kerberos messages + etypes\n"
               "  pcapscope ntlm capture.pcap           NetNTLM hashes (hashcat format)\n"
               "  pcapscope extract --kind creds cap    just the recovered credentials\n"
               "  pcapscope report cap --json out.json  machine-readable output\n"
               "  pcapscope serve capture.pcapng        local web dashboard\n",
    )
    sub = p.add_subparsers(dest="command")

    for name in ("validate", "info", "report", "protocols", "talkers", "flows",
                 "conversations", "tcp", "kerberos", "ntlm", "mssql", "tds",
                 "ldap", "tls", "ldaps", "cleartext", "appauth", "wpa", "wifi",
                 "dns", "hostnames", "hosts", "names", "http", "findings"):
        sp = sub.add_parser(name, help=f"{name} view")
        sp.add_argument("file", help="capture file (.pcap / .pcapng)")
        sp.add_argument("--json", metavar="PATH", help="also write full JSON to PATH")
        sp.add_argument("--top", type=int, default=15, help="rows for talkers/flows")
        sp.add_argument("--dedup", action="store_true",
                        help="drop exact-duplicate frames (multi-component pktmon captures)")

    ex = sub.add_parser("extract", help="extract specific material")
    ex.add_argument("file")
    ex.add_argument("--dedup", action="store_true",
                    help="drop exact-duplicate frames (multi-component pktmon captures)")
    ex.add_argument("--kind", required=True,
                    choices=["creds", "ntlm", "kerberos", "mssql", "ldap", "http", "cleartext", "json"],
                    help="what to extract")

    xp = sub.add_parser("export", help="write hashcat files named <pcap>_<hashtype>.txt")
    xp.add_argument("file")
    xp.add_argument("--out-dir", help="output directory (default: the pcap's folder)")
    xp.add_argument("--dedup", action="store_true",
                    help="drop exact-duplicate frames (multi-component pktmon captures)")

    rad = sub.add_parser("radius", help="RADIUS auth, MS-CHAP hashes, shared-secret recovery")
    rad.add_argument("file")
    rad.add_argument("--json", metavar="PATH", help="also write full JSON to PATH")
    rad.add_argument("--dedup", action="store_true")
    rad.add_argument("--secret", help="known shared secret: validate it + decrypt PAP passwords")
    rad.add_argument("--recover-secret", action="store_true",
                     help="dictionary-attack the shared secret (Response/Message-Authenticator)")
    rad.add_argument("--wordlist", help="wordlist for --recover-secret (default: ./dictionary/rockyou.txt)")

    nf = sub.add_parser("netflow", help="NetFlow-style unidirectional 5-tuple flow records")
    nf.add_argument("file")
    nf.add_argument("--top", type=int, default=40, help="rows to print (default 40)")
    nf.add_argument("--csv", metavar="PATH", help="write ALL flows as nfdump-style CSV")
    nf.add_argument("--json", metavar="PATH", help="also write full JSON to PATH")
    nf.add_argument("--dedup", action="store_true")

    sv = sub.add_parser("serve", help="launch local web dashboard")
    sv.add_argument("file", nargs="?", help="optional capture to open on start")
    sv.add_argument("--port", type=int, default=8088)
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--dir", help="directory of captures to browse (default: file's dir or cwd)")
    sv.add_argument("--hashcat", help="path to hashcat.exe (default: ./hashcat/hashcat.exe)")
    sv.add_argument("--wordlist-dir", help="folder of wordlists (default: ./dictionary)")
    sv.add_argument("--token", help="fixed access token (default: random per run)")
    sv.add_argument("--no-browser", action="store_true", help="don't auto-open a browser")
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # Convenience: `pcapscope <file>` with no subcommand -> full report.
    if argv and argv[0] not in RENDERERS and argv[0] not in ("extract", "serve", "-h", "--help") \
            and os.path.isfile(argv[0]):
        argv = ["report"] + argv

    parser = _build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 1

    if args.command == "serve":
        from .serve import serve
        return serve(args.host, args.port, args.file, args.dir,
                     args.hashcat, args.wordlist_dir, args.token,
                     open_browser=not args.no_browser)

    try:
        result = analyze(args.file, dedup=getattr(args, "dedup", False))
    except CaptureError as e:
        print(f"error: {args.file}: {e}", file=sys.stderr)
        return 2
    except FileNotFoundError:
        print(f"error: file not found: {args.file}", file=sys.stderr)
        return 2

    if args.command == "netflow":
        print(report.render_netflow(result, args.top))
        if args.csv:
            with open(args.csv, "w", encoding="utf-8", newline="") as fh:
                fh.write(report.netflow_csv(result))
            print(f"\n[+] {len(result.netflow)} flows written to {args.csv}")
        if args.json:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(report.to_json(result), fh, indent=2, default=str)
            print(f"[+] JSON written to {args.json}")
        return 0

    if args.command == "radius":
        return _radius(result, args)

    if args.command == "extract":
        return _extract(result, args.kind)

    if args.command == "export":
        written = report.export_hashcat(result, args.file, args.out_dir)
        if not written:
            print("No crackable hashes found to export "
                  "(no NTLM/Kerberos material in this capture).")
            return 0
        out_loc = os.path.dirname(written[0]["path"]) or "."
        allf = [w for w in written if w["kind"] == "all"]
        prio = [w for w in written if w["kind"] == "priority"]
        print(f"Exported to {out_loc}:\n")
        print("  Full files (every hash of that type):")
        for w in allf:
            print(f"    {w['file']:<46} {w['count']:>3}  ->  hashcat -m {w['mode']} {w['file']} <wordlist>")
        if prio:
            print("\n  Priority files (user/service accounts only - crack these first):")
            for w in prio:
                print(f"    {w['file']:<46} {w['count']:>3}  ->  hashcat -m {w['mode']} {w['file']} <wordlist>")

        # account classification
        cls = report.classify_report(result)
        print("\n  Account classification:")
        for klass in ("user", "service", "machine", "krbtgt", "system", "unknown"):
            accts = cls.get(klass)
            if not accts:
                continue
            mark = "  <== worth cracking" if klass in report.CRACKABLE_CLASSES else "  (skip - random pw)" if klass in ("machine", "krbtgt", "system") else ""
            shown = ", ".join(accts[:8]) + (f" (+{len(accts) - 8} more)" if len(accts) > 8 else "")
            print(f"    {klass:<8} ({len(accts)}): {shown}{mark}")
        return 0

    renderer = RENDERERS[args.command]
    # talkers/flows honour --top
    if args.command in ("talkers",):
        print(report.render_talkers(result, args.top))
    elif args.command in ("flows", "conversations"):
        print(report.render_conversations(result, args.top))
    else:
        print(renderer(result))

    if getattr(args, "json", None):
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report.to_json(result), fh, indent=2, default=str)
        print(f"\n[+] JSON written to {args.json}")
    return 0


_COMMON_SECRETS = [b"testing123", b"secret", b"radius", b"cisco", b"password",
                   b"admin", b"changeme", b"test", b"shared", b"mysecret", b"123456"]


def _secret_candidates(wordlist_path):
    seen = set()
    for c in _COMMON_SECRETS:
        seen.add(c)
        yield c
    if wordlist_path and os.path.isfile(wordlist_path):
        with open(wordlist_path, "rb") as fh:
            for line in fh:
                c = line.rstrip(b"\r\n")
                if c and c not in seen:
                    yield c


def _find_rockyou(file_path):
    base = os.path.dirname(os.path.abspath(file_path))
    for c in (os.path.join(base, "dictionary", "rockyou.txt"),
              os.path.join(os.getcwd(), "dictionary", "rockyou.txt")):
        if os.path.isfile(c):
            return c
    return None


def _radius(result, args) -> int:
    from .analyze import apply_radius_secret, recover_radius_secret

    if not result.radius:
        print(report.render_radius(result))
        return 0

    if getattr(args, "recover_secret", False):
        wl = args.wordlist or _find_rockyou(args.file)
        targets = [f for f in result.radius if f.can_recover_secret]
        if not targets:
            print("[!] No verifiable authenticator (need an Access-Request/response pair or "
                  "a Message-Authenticator) to recover the secret.")
        else:
            print(f"[*] Recovering shared secret (common list + {os.path.basename(wl) if wl else 'no wordlist'}) ...")
            found = recover_radius_secret(result, _secret_candidates(wl))
            if found is not None:
                print(f"[+] Shared secret recovered: '{found}'")
                apply_radius_secret(result, found)
            else:
                print("[!] Shared secret not found in the wordlist.")

    if getattr(args, "secret", None):
        ok = apply_radius_secret(result, args.secret)
        print(f"[{'+' if ok else '!'}] secret '{args.secret}' "
              + ("confirmed against a captured authenticator." if ok
                 else "could NOT be confirmed (PAP decrypted but unverified - may be wrong)."))

    print(report.render_radius(result))
    print(report.render_eap(result))
    if getattr(args, "json", None):
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report.to_json(result), fh, indent=2, default=str)
        print(f"\n[+] JSON written to {args.json}")
    return 0


def _extract(result, kind: str) -> int:
    if kind == "json":
        print(json.dumps(report.to_json(result), indent=2, default=str))
        return 0
    if kind in ("ntlm", "creds"):
        for f in result.ntlm:
            if f.hashcat:
                print(f.hashcat)
    if kind in ("mssql", "creds"):
        for f in result.tds:
            if f.info and f.info.login and f.info.login.password:
                lg = f.info.login
                print(f"mssql {f.server} {lg.username}:{lg.password}")
    if kind in ("ldap", "creds"):
        for f in result.ldap:
            b = f.bind
            if b.kind == "request" and b.password:
                print(f"ldap {f.server} {b.dn}:{b.password}")
    if kind in ("http", "creds"):
        for f in result.http_auth:
            a = f.auth
            if a.username:
                print(f"http {a.host or f.server} {a.username}:{a.password}")
    if kind in ("cleartext", "creds"):
        for f in result.cleartext:
            if f.username or f.password:
                print(f"{f.protocol.lower()} {f.server} {f.username}:{f.password}")
    if kind in ("kerberos", "creds"):
        for f in result.kerberos:
            for hd in f.msg.extractable_hashes():
                print(hd["hash"])
    if kind == "kerberos":
        for f in result.kerberos:
            m = f.msg
            print(f"# {m.kind}\tuser={m.cname}\tspn={m.sname}\trealm={m.realm}\t"
                  f"etypes={','.join(str(e) for e in m.etypes)}\terror={m.error_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
