"""A zero-dependency local web dashboard for browsing capture analysis.

Uses only ``http.server`` from the standard library. Binds to localhost by
default. Lists capture files in a directory and renders the same analysis the
CLI produces as an interactive page (overview, findings, Kerberos, NTLM, MSSQL,
LDAP, HTTP, flows, talkers).
"""

from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import report
from .analyze import analyze
from .reader import CaptureError

CAP_EXT = (".pcap", ".pcapng", ".cap", ".pcapng.gz", ".pcapng1")
_cache: dict[tuple, dict] = {}

# Hashcat modes pcapscope produces - the only ones the crack endpoint accepts.
CRACK_MODES = {"0", "1000", "4800", "5500", "5600", "7500", "10200", "11100",
               "11200", "11400", "13100", "18200", "19600", "19700", "19800",
               "19900", "22000", "25100", "25200", "26700", "26800", "26900", "27300"}
STATUS_LABELS = {1: "init", 2: "autotune", 3: "running", 4: "paused",
                 5: "exhausted", 6: "cracked", 7: "aborted", 8: "quit"}
MODE_NAMES = {
    "0": "MD5", "1000": "NTLM", "4800": "EAP-MD5 / Chap-MD5",
    "5500": "NetNTLMv1 / MS-CHAPv2", "5600": "NetNTLMv2",
    "10200": "CRAM-MD5", "11100": "PostgreSQL", "11200": "MySQL", "11400": "SIP digest",
    "22000": "WPA-PBKDF2-PMKID+EAPOL", "25100": "SNMPv3 HMAC-MD5", "25200": "SNMPv3 HMAC-SHA1",
    "26700": "SNMPv3 SHA224", "26800": "SNMPv3 SHA256", "26900": "SNMPv3 SHA384", "27300": "SNMPv3 SHA512",
    "7500": "Kerberos AS-REQ preauth (RC4)", "13100": "Kerberoast TGS-REP (RC4)",
    "18200": "AS-REP roast", "19600": "Kerberoast TGS-REP (AES128)",
    "19700": "Kerberoast TGS-REP (AES256)", "19800": "Kerberos preauth (AES128)",
    "19900": "Kerberos preauth (AES256)",
}

_linecount_cache: dict[tuple, int] = {}


def _count_lines(path):
    try:
        st = os.stat(path)
    except OSError:
        return 0
    key = (path, st.st_mtime, st.st_size)
    if key in _linecount_cache:
        return _linecount_cache[key]
    n = 0
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                n += chunk.count(b"\n")
    except OSError:
        return 0
    _linecount_cache[key] = n
    return n

# ---------------------------------------------------------------------------
# Background hashcat jobs
# ---------------------------------------------------------------------------
_jobs: dict[str, "CrackJob"] = {}
_job_lock = threading.Lock()
_job_seq = [0]


def _account_from_hash(h: str) -> str:
    """Best-effort account label from a raw hash line (for result display)."""
    if h.startswith("$krb5tgs$"):
        m = re.search(r"\*([^*]+)\*", h)
        if m:
            return m.group(1)
        p = h.split("$")
        return p[3] if len(p) > 3 else h[:24]
    if h.startswith("$krb5asrep$"):
        m = re.search(r"\$krb5asrep\$\d+\$([^:]+):", h)
        return m.group(1) if m else h[:24]
    if h.startswith("$krb5pa$"):
        p = h.split("$")
        return p[3] if len(p) > 3 else h[:24]
    if "::" in h:                                   # NetNTLM: user::DOMAIN:...
        user, rest = h.split("::", 1)
        dom = rest.split(":", 1)[0]
        return f"{dom}\\{user}" if dom else user
    return h[:24]


class CrackJob:
    def __init__(self, jid, hashfile, mode, opts):
        self.id = jid
        self.hashfile = hashfile
        self.file = os.path.basename(hashfile)
        self.mode = str(mode)
        self.attack = opts.get("attack", "0")
        self.wordlist = opts.get("wordlist", "")
        self.wordlist_name = os.path.basename(self.wordlist) if self.wordlist else ""
        self.rules_path = opts.get("rules_path", "")
        self.rules = os.path.basename(self.rules_path) if self.rules_path else ""
        self.mask = opts.get("mask", "")
        self.optimized = bool(opts.get("optimized"))
        self.hash_count = _count_lines(hashfile)
        self.status = "queued"
        self.progress = 0.0
        self.speed = 0
        self.attempts = 0
        self.keyspace = 0
        self.eta = None
        self.recovered = [0, 0]
        self.cracked: list[dict] = []
        self.error = None
        self.started = time.time()
        self.finished = None
        self._proc = None
        self._stop = False

    def attack_desc(self):
        if self.attack == "3":
            return f"mask {self.mask}"
        d = f"dict {self.wordlist_name}"
        if self.rules:
            d += f" +{self.rules}"
        if self.optimized:
            d += " -O"
        return d

    def to_dict(self):
        elapsed = (self.finished or time.time()) - self.started
        eta = 0
        if self.eta and self.finished is None:
            eta = max(0, int(self.eta - time.time()))
        return {
            "id": self.id, "file": self.file, "mode": self.mode,
            "mode_name": MODE_NAMES.get(self.mode, "mode " + self.mode),
            "hash_count": self.hash_count,
            "wordlist": self.wordlist_name, "attack": self.attack,
            "attack_desc": self.attack_desc(), "status": self.status,
            "progress": self.progress, "speed": self.speed,
            "attempts": self.attempts, "keyspace": self.keyspace,
            "eta_seconds": eta,
            "recovered": self.recovered, "cracked": self.cracked,
            "error": self.error, "elapsed": round(elapsed, 1),
            "running": self.finished is None,
        }


def _apply_status(job, st):
    job.status = STATUS_LABELS.get(st.get("status", 0), job.status)
    prog = st.get("progress") or [0, 0]
    job.attempts, job.keyspace = prog[0], prog[1]
    if prog[1]:
        job.progress = round(100.0 * prog[0] / prog[1], 1)
    rec = st.get("recovered_hashes")
    if rec:
        job.recovered = rec
    job.speed = sum(d.get("speed", 0) for d in (st.get("devices") or []))
    if st.get("estimated_stop"):
        job.eta = st["estimated_stop"]


def _collect_results(job, outfile):
    if not os.path.isfile(outfile):
        return
    try:
        cracked = [l.rstrip("\n") for l in open(outfile, encoding="utf-8", errors="replace") if l.strip()]
        hashlines = [l.rstrip("\n") for l in open(job.hashfile, encoding="utf-8", errors="replace") if l.strip()]
    except OSError:
        return
    results = []
    for entry in cracked:
        matched, pw = None, ""
        for hl in hashlines:
            if entry.startswith(hl + ":"):
                matched, pw = hl, entry[len(hl) + 1:]
                break
        if matched is None and ":" in entry:        # fallback
            matched, pw = entry.rsplit(":", 1)
        if matched is not None:
            results.append({"account": _account_from_hash(matched), "password": pw})
    job.cracked = results


def _run_crack(job, hashcat_exe, out_dir):
    job.status = "running"
    work_dir = os.path.dirname(hashcat_exe)
    pot = os.path.join(out_dir, job.id + ".potfile")
    outf = os.path.join(out_dir, job.id + ".out")
    for p in (pot, outf):
        try:
            if os.path.isfile(p):
                os.remove(p)
        except OSError:
            pass
    cmd = [hashcat_exe, "-m", job.mode]
    if job.optimized:
        cmd.append("-O")
    cmd += ["-a", job.attack, job.hashfile]
    if job.attack == "3":
        cmd.append(job.mask)
    else:
        cmd.append(job.wordlist)
        if job.rules_path:
            cmd += ["-r", job.rules_path]
    cmd += ["--potfile-path", pot, "-o", outf,
            "--status", "--status-json", "--status-timer", "1", "-w", "3"]
    try:
        job._proc = subprocess.Popen(
            cmd, cwd=work_dir, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
        )
    except Exception as e:
        job.status, job.error, job.finished = "error", str(e), time.time()
        return
    for line in job._proc.stdout:
        if job._stop:
            break
        i = line.find("{")
        if i >= 0 and '"status"' in line:
            try:
                _apply_status(job, json.loads(line[i:]))
            except Exception:
                pass
    try:
        job._proc.wait(timeout=10)
    except Exception:
        pass
    _collect_results(job, outf)
    if job._stop:
        job.status = "stopped"
    elif job.cracked and job.recovered[1] and job.recovered[0] >= job.recovered[1]:
        job.status = "cracked"
    elif job.cracked:
        job.status = "partial"
    elif job.status not in ("error",):
        job.status = "exhausted"
    job.progress = job.progress if job.status == "stopped" else 100.0
    job.finished = time.time()


def _start_crack(hashcat_exe, hashfile, mode, opts, out_dir):
    with _job_lock:
        _job_seq[0] += 1
        jid = f"job{_job_seq[0]}"
    job = CrackJob(jid, hashfile, mode, opts)
    _jobs[jid] = job
    threading.Thread(target=_run_crack, args=(job, hashcat_exe, out_dir), daemon=True).start()
    return job


def _stop_job(jid):
    job = _jobs.get(jid)
    if not job:
        return False
    job._stop = True
    if job._proc and job._proc.poll() is None:
        try:
            job._proc.terminate()
        except Exception:
            pass
    return True


def _detect_hashcat(base):
    for cand in (os.path.join(base, "hashcat", "hashcat.exe"),
                 os.path.join(base, "hashcat.exe"),
                 os.path.join(base, "hashcat", "hashcat.bin"),
                 os.path.join(base, "hashcat", "hashcat")):
        if os.path.isfile(cand):
            return cand
    return None


def _list_wordlists(wdir):
    out = []
    if wdir and os.path.isdir(wdir):
        for n in sorted(os.listdir(wdir)):
            p = os.path.join(wdir, n)
            if os.path.isfile(p) and n.lower().endswith((".txt", ".dict", ".lst", ".wordlist")):
                out.append({"name": n, "size": os.path.getsize(p)})
    return out


_COMMON_SECRETS = [b"testing123", b"secret", b"radius", b"cisco", b"password",
                   b"admin", b"changeme", b"test", b"shared", b"mysecret", b"123456"]
_radius_recover: dict[str, dict] = {}


def _radius_recover_run(full, wordlist):
    from .analyze import analyze as _an, _radius_secret_targets
    name = os.path.basename(full)
    st = _radius_recover[name]
    try:
        result = _an(full)
    except Exception as e:
        st.update(status="error", error=str(e), done=True)
        return
    targets = _radius_secret_targets(result)
    if not targets:
        st.update(status="no-target", done=True)
        return

    def candidates():
        for c in _COMMON_SECRETS:
            yield c
        if wordlist and os.path.isfile(wordlist):
            with open(wordlist, "rb") as fh:
                for line in fh:
                    yield line.rstrip(b"\r\n")

    from . import radius as _r
    tested = 0
    for cand in candidates():
        if st.get("stop"):
            st.update(status="stopped", done=True, tested=tested)
            return
        tested += 1
        if tested % 20000 == 0:
            st["tested"] = tested
        for t in targets:
            if _r.check_secret(cand, t):
                st.update(status="found", secret=cand.decode("utf-8", "replace"),
                          tested=tested, done=True)
                return
    st.update(status="not-found", tested=tested, done=True)


def _rules_dir(hashcat_exe):
    return os.path.join(os.path.dirname(hashcat_exe), "rules") if hashcat_exe else None


def _list_rules(hashcat_exe):
    rdir = _rules_dir(hashcat_exe)
    out = []
    if rdir and os.path.isdir(rdir):
        for n in sorted(os.listdir(rdir)):
            if n.lower().endswith(".rule") and os.path.isfile(os.path.join(rdir, n)):
                out.append(n)
    # surface the popular ones first
    popular = ["best64.rule", "rockyou-30000.rule", "OneRuleToRuleThemAll.rule", "dive.rule"]
    out.sort(key=lambda n: (n not in popular, n.lower()))
    return out


def _list_dir(directory: str) -> list[dict]:
    out = []
    try:
        for name in sorted(os.listdir(directory)):
            low = name.lower()
            if low.endswith((".pcap", ".pcapng", ".cap")):
                full = os.path.join(directory, name)
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                out.append({"name": name, "size": st.st_size, "mtime": st.st_mtime})
    except OSError:
        pass
    return out


def _analyze_cached(directory: str, name: str) -> dict:
    safe = os.path.basename(name)
    full = os.path.join(directory, safe)
    if not os.path.isfile(full):
        return {"error": f"file not found: {safe}"}
    mtime = os.path.getmtime(full)
    key = (full, mtime)
    if key in _cache:
        return _cache[key]
    try:
        result = analyze(full)
    except CaptureError as e:
        return {"error": str(e)}
    except Exception as e:  # pragma: no cover - defensive
        return {"error": f"{type(e).__name__}: {e}"}
    data = report.to_json(result)
    _cache[key] = data
    return data


def _default_wordlist(wdir):
    if not wdir or not os.path.isdir(wdir):
        return None
    lists = _list_wordlists(wdir)
    for w in lists:                                  # prefer rockyou if present
        if "rockyou" in w["name"].lower():
            return os.path.join(wdir, w["name"])
    return os.path.join(wdir, lists[0]["name"]) if lists else None


def _is_ip_literal(host: str) -> bool:
    return bool(host) and all(c in "0123456789.:abcdefABCDEF" for c in host)


def _make_handler(directory, init_file, hashcat_exe, wordlist_dir, token, allowed_hosts, port):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):  # quiet
            pass

        def _send(self, code, body, ctype="application/json", cookie=None):
            if isinstance(body, (dict, list)):
                body = json.dumps(body, default=str).encode("utf-8")
            elif isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.send_header("X-Content-Type-Options", "nosniff")
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(body)

        # -- security gates --------------------------------------------------
        def _host_ok(self):
            """Reject DNS-rebinding: Host must be loopback/localhost, the bound
            host, or a bare IP literal on our port (LAN access)."""
            h = self.headers.get("Host", "")
            if h in allowed_hosts:
                return True
            name = h.rsplit(":", 1)[0] if ":" in h else h
            pport = h.rsplit(":", 1)[1] if ":" in h else ""
            return _is_ip_literal(name) and (pport == str(port) or not pport)

        def _cookie_token(self):
            for part in self.headers.get("Cookie", "").split(";"):
                part = part.strip()
                if part.startswith("pcap_tok="):
                    return part[len("pcap_tok="):]
            return ""

        def _api_ok(self, post=False):
            hdr = self.headers.get("X-Auth-Token", "")
            if hdr and secrets.compare_digest(hdr, token):
                return True
            if not post:                                  # GET may use the cookie
                ck = self._cookie_token()
                if ck and secrets.compare_digest(ck, token):
                    return True
            return False

        def do_GET(self):
            if not self._host_ok():
                return self._send(403, {"error": "forbidden host"})
            u = urlparse(self.path)
            if u.path in ("/", "/index.html"):
                qtok = (parse_qs(u.query).get("token") or [""])[0]
                ck = self._cookie_token()
                ok = (qtok and secrets.compare_digest(qtok, token)) or \
                     (ck and secrets.compare_digest(ck, token))
                if not ok:
                    return self._send(403, "Unauthorized. Open the http://...?token=... URL "
                                      "printed in the pcapscope terminal.", "text/plain; charset=utf-8")
                html = (PAGE.replace("__INIT_FILE__", json.dumps(init_file or ""))
                            .replace("__TOKEN__", json.dumps(token)))
                return self._send(200, html, "text/html; charset=utf-8",
                                  cookie=f"pcap_tok={token}; Path=/; SameSite=Strict")
            if not self._api_ok():
                return self._send(401, {"error": "unauthorized"})
            if u.path == "/api/list":
                return self._send(200, {"dir": directory, "files": _list_dir(directory)})
            if u.path == "/api/analyze":
                q = parse_qs(u.query)
                name = (q.get("file") or [""])[0]
                if not name:
                    return self._send(400, {"error": "missing file"})
                return self._send(200, _analyze_cached(directory, name))
            if u.path == "/api/export":
                q = parse_qs(u.query)
                name = os.path.basename((q.get("file") or [""])[0])
                full = os.path.join(directory, name)
                if not name or not os.path.isfile(full):
                    return self._send(404, {"error": "file not found"})
                try:
                    result = analyze(full)
                except Exception as e:  # pragma: no cover - defensive
                    return self._send(500, {"error": f"{type(e).__name__}: {e}"})
                written = report.export_hashcat(result, full, directory)
                return self._send(200, {"written": written, "dir": directory,
                                        "classification": report.classify_report(result)})
            if u.path == "/api/crack/config":
                wls = _list_wordlists(wordlist_dir)
                for w in wls:
                    w["lines"] = _count_lines(os.path.join(wordlist_dir, w["name"]))
                rdir = _rules_dir(hashcat_exe)
                rules = [{"name": r, "lines": _count_lines(os.path.join(rdir, r))}
                         for r in _list_rules(hashcat_exe)]
                return self._send(200, {
                    "hashcat": bool(hashcat_exe), "hashcat_path": hashcat_exe or "",
                    "wordlists": wls,
                    "default_wordlist": os.path.basename(_default_wordlist(wordlist_dir) or ""),
                    "rules": rules,
                })
            if u.path == "/api/radius/recover_status":
                name = os.path.basename((parse_qs(u.query).get("file") or [""])[0])
                return self._send(200, _radius_recover.get(name, {"status": "none", "done": True}))
            if u.path == "/api/jobs":
                jobs = [j.to_dict() for j in sorted(_jobs.values(), key=lambda j: j.started, reverse=True)]
                return self._send(200, {"jobs": jobs})
            if u.path == "/api/job":
                jid = (parse_qs(u.query).get("id") or [""])[0]
                job = _jobs.get(jid)
                if not job:
                    return self._send(404, {"error": "no such job"})
                return self._send(200, job.to_dict())
            return self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self._host_ok():
                return self._send(403, {"error": "forbidden host"})
            if not self._api_ok(post=True):              # POST requires the header (CSRF-safe)
                return self._send(401, {"error": "unauthorized (missing X-Auth-Token)"})
            u = urlparse(self.path)
            if u.path == "/api/crack":
                if not hashcat_exe:
                    return self._send(400, {"error": "hashcat not found - put it in ./hashcat/hashcat.exe or pass --hashcat"})
                q = parse_qs(u.query)
                name = os.path.basename((q.get("file") or [""])[0])
                mode = (q.get("mode") or [""])[0]
                hashfile = os.path.join(directory, name)
                if not name.endswith(".txt") or not os.path.isfile(hashfile):
                    return self._send(404, {"error": "hash file not found"})
                if mode not in CRACK_MODES:
                    return self._send(400, {"error": f"mode {mode!r} not allowed"})
                attack = (q.get("attack") or ["0"])[0]
                if attack not in ("0", "3"):
                    return self._send(400, {"error": "attack must be 0 (dict) or 3 (mask)"})
                opts = {"attack": attack,
                        "optimized": (q.get("optimized") or [""])[0] in ("1", "true", "on")}
                if attack == "3":
                    mask = (q.get("mask") or [""])[0]
                    if not mask or len(mask) > 128:
                        return self._send(400, {"error": "provide a mask (e.g. ?a?a?a?a?a?a)"})
                    opts["mask"] = mask
                else:
                    wl = os.path.basename((q.get("wordlist") or [""])[0]) if q.get("wordlist") else ""
                    wordlist = os.path.join(wordlist_dir, wl) if (wl and wordlist_dir) else _default_wordlist(wordlist_dir)
                    if not wordlist or not os.path.isfile(wordlist):
                        return self._send(400, {"error": "wordlist not found (place one in ./dictionary)"})
                    opts["wordlist"] = wordlist
                    rule = os.path.basename((q.get("rules") or [""])[0]) if q.get("rules") else ""
                    if rule:
                        if rule not in _list_rules(hashcat_exe):
                            return self._send(400, {"error": f"rule {rule!r} not found in hashcat/rules"})
                        opts["rules_path"] = os.path.join(_rules_dir(hashcat_exe), rule)
                job = _start_crack(hashcat_exe, hashfile, mode, opts, directory)
                return self._send(200, job.to_dict())
            if u.path == "/api/stop_job":
                jid = (parse_qs(u.query).get("id") or [""])[0]
                return self._send(200, {"stopped": _stop_job(jid)})
            if u.path == "/api/radius/secret":
                q = parse_qs(u.query)
                name = os.path.basename((q.get("file") or [""])[0])
                secret = (q.get("secret") or [""])[0]
                full = os.path.join(directory, name)
                if not os.path.isfile(full):
                    return self._send(404, {"error": "file not found"})
                from .analyze import apply_radius_secret
                try:
                    result = analyze(full)
                except Exception as e:
                    return self._send(500, {"error": str(e)})
                valid = apply_radius_secret(result, secret)
                return self._send(200, {"valid": valid,
                                        "radius": [report._radius_json(f) for f in result.radius]})
            if u.path == "/api/radius/recover":
                q = parse_qs(u.query)
                name = os.path.basename((q.get("file") or [""])[0])
                full = os.path.join(directory, name)
                if not os.path.isfile(full):
                    return self._send(404, {"error": "file not found"})
                wl = _default_wordlist(wordlist_dir)
                _radius_recover[name] = {"status": "running", "done": False, "tested": 0, "secret": None}
                threading.Thread(target=_radius_recover_run, args=(full, wl), daemon=True).start()
                return self._send(200, {"started": True})
            if u.path == "/api/delete":
                raw = self.headers.get("X-Filename", "") or (parse_qs(u.query).get("file") or [""])[0]
                name = os.path.basename(raw)
                if not name or not name.lower().endswith((".pcap", ".pcapng", ".cap")):
                    return self._send(400, {"error": "invalid file"})
                path = os.path.join(directory, name)
                if not os.path.isfile(path):
                    return self._send(404, {"error": "not found"})
                try:
                    os.remove(path)
                except OSError as e:
                    return self._send(500, {"error": str(e)})
                for k in [k for k in _cache if k[0] == path]:
                    _cache.pop(k, None)
                return self._send(200, {"ok": True, "name": name})
            if u.path != "/api/upload":
                return self._send(404, {"error": "not found"})
            try:
                length = int(self.headers.get("Content-Length", "0") or 0)
            except ValueError:
                length = 0
            if length <= 0 or length > 1024 * 1024 * 1024:
                return self._send(400, {"error": "missing or oversized upload"})
            raw_name = self.headers.get("X-Filename", "upload.pcap")
            name = os.path.basename(raw_name) or "upload.pcap"
            if not name.lower().endswith((".pcap", ".pcapng", ".cap")):
                name += ".pcap"
            dest = os.path.join(directory, name)
            try:
                remaining = length
                with open(dest, "wb") as fh:
                    while remaining > 0:
                        chunk = self.rfile.read(min(65536, remaining))
                        if not chunk:
                            break
                        fh.write(chunk)
                        remaining -= len(chunk)
            except OSError as e:
                return self._send(500, {"error": str(e)})
            return self._send(200, {"name": name})

    return Handler


def serve(host: str, port: int, file: str | None, directory: str | None,
          hashcat: str | None = None, wordlist_dir: str | None = None,
          token: str | None = None, open_browser: bool = True) -> int:
    init_file = None
    if file:
        file = os.path.abspath(file)
        if directory is None:
            directory = os.path.dirname(file) or "."
        init_file = os.path.basename(file)
    if directory is None:
        directory = os.getcwd()
    directory = os.path.abspath(directory)

    # Locate hashcat + wordlists (look in the capture dir and cwd by default).
    hashcat_exe = hashcat if (hashcat and os.path.isfile(hashcat)) else (
        _detect_hashcat(directory) or _detect_hashcat(os.getcwd()))
    if wordlist_dir is None:
        for cand in (os.path.join(directory, "dictionary"), os.path.join(os.getcwd(), "dictionary")):
            if os.path.isdir(cand):
                wordlist_dir = cand
                break
    wordlist_dir = os.path.abspath(wordlist_dir) if wordlist_dir else None

    token = token or secrets.token_urlsafe(24)
    loopback = host in ("127.0.0.1", "localhost", "::1", "0.0.0.0")
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", "127.0.0.1", "localhost",
                     f"{host}:{port}", host}
    handler = _make_handler(directory, init_file, hashcat_exe, wordlist_dir,
                            token, allowed_hosts, port)
    httpd = ThreadingHTTPServer((host, port), handler)
    disp = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    url = f"http://{disp}:{port}/?token={token}"
    print(f"[+] pcapscope dashboard serving captures from: {directory}")
    print(f"[+] hashcat: {hashcat_exe or 'NOT FOUND'} | wordlists: {wordlist_dir or 'none'}")
    if not loopback:
        print(f"[!] WARNING: bound to non-loopback {host} - the dashboard (and recovered "
              f"credentials) is reachable from the network. The access token is required, "
              f"but consider an SSH tunnel instead.")
    print(f"[+] open (token required):  {url}")
    print("[+] Ctrl-C to stop")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] stopped")
    finally:
        httpd.server_close()
    return 0


# ---------------------------------------------------------------------------
# Single-page dashboard (vanilla JS, no external resources).
# ---------------------------------------------------------------------------
PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>pcapscope - auth analysis</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1c2330;--border:#30363d;--fg:#c9d1d9;
--muted:#8b949e;--accent:#58a6ff;--ok:#3fb950;--warn:#d29922;--bad:#f85149;--mono:ui-monospace,SFMono-Regular,Consolas,monospace;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
header{padding:10px 16px;background:var(--panel);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px}
header h1{font-size:16px;margin:0;color:var(--accent)}
header .sub{color:var(--muted);font-size:12px}
.layout{display:flex;height:calc(100vh - 45px)}
.sidebar{width:260px;border-right:1px solid var(--border);overflow:auto;background:var(--panel)}
.sidebar h2{font-size:11px;text-transform:uppercase;color:var(--muted);padding:10px 14px 4px;margin:0;letter-spacing:.05em}
.file{padding:8px 14px;cursor:pointer;border-bottom:1px solid var(--border);font-size:13px;display:flex;align-items:center;gap:6px}
.file:hover{background:var(--panel2)}
.file.active{background:var(--panel2);border-left:3px solid var(--accent)}
.file .meta{color:var(--muted);font-size:11px}
.file .info{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.file .act{opacity:0;border:none;background:none;color:var(--muted);cursor:pointer;display:flex;align-items:center;padding:3px;border-radius:4px}
.file:hover .act{opacity:.6}
.file .close{font-size:15px;line-height:1;padding:1px 5px}
.file .close:hover{opacity:1;color:var(--fg);background:var(--border)}
.file .trash:hover{opacity:1;color:var(--bad);background:rgba(248,81,73,.14)}
.file .trash svg{display:block}
.main{flex:1;overflow:auto;padding:0 18px 40px}
.tabs{display:flex;gap:2px;position:sticky;top:0;background:var(--bg);padding:10px 0;flex-wrap:wrap;border-bottom:1px solid var(--border);z-index:5}
.tab{padding:6px 12px;cursor:pointer;border:1px solid transparent;border-radius:6px;font-size:13px;color:var(--muted)}
.tab:hover{color:var(--fg)}
.tab.active{background:var(--panel2);color:var(--accent);border-color:var(--border)}
.tab .badge{background:var(--bad);color:#fff;border-radius:9px;padding:0 6px;font-size:11px;margin-left:5px}
.tab .badge.n{background:#30363d;color:var(--fg)}
section{display:none;padding-top:14px}
section.active{display:block}
.card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:14px 16px;margin-bottom:14px}
.card h3{margin:0 0 10px;font-size:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px}
.kv{display:flex;justify-content:space-between;border-bottom:1px solid var(--border);padding:4px 0;gap:10px}
.kv .k{color:var(--muted)}
.kv .v{font-family:var(--mono);text-align:right;word-break:break-all}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600;position:sticky;top:0;background:var(--panel)}
td.mono,.mono{font-family:var(--mono)}
.pill{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11px;font-weight:600}
.pill.bad{background:rgba(248,81,73,.15);color:var(--bad)}
.pill.warn{background:rgba(210,153,34,.15);color:var(--warn)}
.pill.ok{background:rgba(63,185,80,.15);color:var(--ok)}
.pill.info{background:rgba(88,166,255,.15);color:var(--accent)}
.finding{padding:8px 12px;border-left:3px solid var(--warn);background:var(--panel2);border-radius:4px;margin-bottom:6px}
.hash{font-family:var(--mono);font-size:11.5px;background:#0b0f14;border:1px solid var(--border);border-radius:6px;padding:8px;word-break:break-all;position:relative}
.bar{height:9px;background:#0b0f14;border:1px solid var(--border);border-radius:6px;overflow:hidden;margin:8px 0}
.bar>i{display:block;height:100%;width:0;background:var(--accent);transition:width .6s}
.bar>i.done{background:var(--ok)}
.job{border:1px solid var(--border);border-radius:8px;padding:12px 14px;margin-bottom:12px;background:var(--panel)}
.job h4{margin:0 0 6px;font-size:13px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.mini{font-size:11px;color:var(--accent);cursor:pointer;border:1px solid var(--border);border-radius:4px;padding:1px 8px;background:none}
.mini:hover{background:var(--panel2)}
.crackbtn{font-size:11px;color:var(--bad);cursor:pointer;border:1px solid var(--border);border-radius:4px;padding:1px 8px;background:none;margin-left:8px}
.crackbtn:hover{background:rgba(248,81,73,.12)}
.crackbtn[disabled]{opacity:.4;cursor:not-allowed}
.cracked{background:rgba(63,185,80,.1);border:1px solid rgba(63,185,80,.35);border-radius:6px;padding:6px 10px;margin-top:8px;font-family:var(--mono);font-size:12.5px}
.copy{position:absolute;top:6px;right:6px;font-size:11px;cursor:pointer;color:var(--accent);background:none;border:1px solid var(--border);border-radius:4px;padding:1px 7px}
.empty{color:var(--muted);padding:20px;text-align:center}
.banner{padding:10px 14px;border-radius:6px;margin-bottom:14px;font-weight:600}
.banner.ok{background:rgba(63,185,80,.12);color:var(--ok);border:1px solid rgba(63,185,80,.3)}
.banner.bad{background:rgba(248,81,73,.12);color:var(--bad);border:1px solid rgba(248,81,73,.3)}
a.dl{color:var(--accent);font-size:12px;text-decoration:none;border:1px solid var(--border);padding:4px 10px;border-radius:6px}
button.dl{background:none;cursor:pointer;font:inherit;color:var(--accent)}
button.dl:hover,a.dl:hover{background:var(--panel2)}
.sidebar .hint{color:var(--muted);font-size:11px;padding:6px 14px;border-bottom:1px solid var(--border)}
#drop{position:fixed;inset:0;background:rgba(13,17,23,.88);border:3px dashed var(--accent);display:none;align-items:center;justify-content:center;font-size:22px;color:var(--accent);z-index:50}
#drop.show{display:flex}
#modal{position:fixed;inset:0;background:rgba(0,0,0,.62);display:none;align-items:center;justify-content:center;z-index:100}
#modal.show{display:flex}
.dialog{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:18px 20px;width:500px;max-width:92vw;max-height:88vh;overflow:auto}
.dialog h3{margin:0 0 4px;font-size:15px}
.dialog .sub2{color:var(--muted);font-size:12px;margin-bottom:8px;font-family:var(--mono)}
.dialog label{display:block;font-size:12px;color:var(--muted);margin:12px 0 4px}
.dialog select,.dialog input[type=text]{width:100%;background:#0b0f14;border:1px solid var(--border);color:var(--fg);border-radius:6px;padding:7px 9px;font:inherit}
.dialog .actions{display:flex;justify-content:flex-end;gap:8px;margin-top:18px}
.seg{display:inline-flex;border:1px solid var(--border);border-radius:6px;overflow:hidden}
.seg button{background:none;border:none;color:var(--muted);padding:6px 14px;cursor:pointer;font:inherit}
.seg button.on{background:var(--accent);color:#fff}
.btn{border:1px solid var(--border);border-radius:6px;padding:7px 16px;cursor:pointer;background:none;color:var(--fg);font:inherit}
.btn:hover{background:var(--panel2)}
.btn.primary{background:var(--accent);color:#fff;border-color:var(--accent)}
.chip{display:inline-block;border:1px solid var(--border);border-radius:5px;padding:2px 8px;margin:4px 4px 0 0;font-size:11px;cursor:pointer;color:var(--accent);font-family:var(--mono)}
.chip:hover{background:var(--panel2)}
.cklabel{display:flex;align-items:center;gap:8px;margin-top:14px;font-size:13px;color:var(--fg);cursor:pointer}
</style></head>
<body>
<header>
  <h1>pcapscope</h1>
  <span class="sub">authentication-focused PCAP analysis &middot; Kerberos / NTLM / MSSQL / LDAP / HTTP</span>
  <span style="flex:1"></span>
  <input type="file" id="fileinput" accept=".pcap,.pcapng,.cap" style="display:none">
  <button class="dl" id="openbtn">Open pcap&hellip;</button>
  <button class="dl" id="exportbtn" title="Write hashcat files (&lt;pcap&gt;_&lt;type&gt;.txt) next to the capture" style="display:none">Export hashes</button>
  <a class="dl" id="dljson" href="#" download>download JSON</a>
</header>
<div id="drop">Drop a .pcap / .pcapng to open</div>
<div id="modal"></div>
<div class="layout">
  <div class="sidebar">
    <h2>Captures</h2>
    <div class="hint">Click <b>Open pcap&hellip;</b> or drag a file anywhere.</div>
    <div id="files"></div>
  </div>
  <div class="main">
    <div class="tabs" id="tabs"></div>
    <div id="content"><div class="empty">Select a capture on the left.</div></div>
  </div>
</div>
<script>
const INIT_FILE = __INIT_FILE__;
const TOKEN = __TOKEN__;
// attach the auth token to every API call (also satisfies the CSRF/header check)
const _origFetch = window.fetch.bind(window);
window.fetch = (u, o) => { o = Object.assign({}, o); o.headers = Object.assign({}, o.headers, {"X-Auth-Token": TOKEN}); return _origFetch(u, o); };
let DATA = null, CURRENT = null;
const REMOVED = new Set();   // captures removed from analysis this session (file kept)
const TABS = [
 ["overview","Overview"],["findings","Findings"],["kerberos","Kerberos"],
 ["ntlm","NTLM"],["mssql","MSSQL"],["ldap","LDAP"],["tls","TLS/LDAPS"],["radius","RADIUS"],["eap","EAP/PEAP"],["cleartext","Cleartext"],["appauth","DB/App"],["wpa","WPA/Wi-Fi"],["http","HTTP"],
 ["hosts","Hosts"],["dns","DNS"],["risk","Risk"],["flows","Flows"],["netflow","NetFlow"],["talkers","Talkers"],["protocols","Protocols"],["jobs","Cracking"]
];
let JOBS=[], CRACK_CFG=null, jobPoller=null; const EXPANDED=new Set();
let HOST_Q="", DNS_Q="";
let activeTab = "overview";
const TRASH_SVG='<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>';

function h(tag, attrs, ...kids){const e=document.createElement(tag);
 if(attrs)for(const k in attrs){if(k==="class")e.className=attrs[k];else if(k==="html")e.innerHTML=attrs[k];else e.setAttribute(k,attrs[k]);}
 for(const k of kids){if(k==null)continue;e.append(k.nodeType?k:document.createTextNode(k));}return e;}
function esc(s){return (s==null?"":String(s)).replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));}
function bytes(n){if(n==null)return"-";const u=["B","KB","MB","GB","TB"];let i=0;n=+n;while(n>=1024&&i<4){n/=1024;i++;}return (i?n.toFixed(2):n)+" "+u[i];}

async function loadFiles(){
 const r=await fetch("/api/list");const j=await r.json();
 const box=document.getElementById("files");box.innerHTML="";
 const files=j.files.filter(f=>!REMOVED.has(f.name));
 if(!files.length){box.append(h("div",{class:"empty"},"No captures in analysis.<br>Open or drop a pcap."));}
 for(const f of files){
  const info=h("div",{class:"info"},h("div",null,f.name),h("div",{class:"meta"},bytes(f.size)));
  const close=h("button",{class:"act close",title:"Remove from analysis (keeps the file on disk)"},"✕");
  close.onclick=e=>{e.stopPropagation();removeFromAnalysis(f.name);};
  const del=h("button",{class:"act trash",title:"Delete this capture from disk",html:TRASH_SVG});
  del.onclick=e=>{e.stopPropagation();deleteCapture(f.name);};
  const el=h("div",{class:"file"},info,close,del);
  el.dataset.name=f.name;
  el.onclick=()=>selectFile(f.name);box.append(el);
  if(f.name===INIT_FILE)setTimeout(()=>selectFile(f.name),50);
 }
}
async function selectFile(name){
 document.querySelectorAll(".file").forEach(e=>e.classList.toggle("active", e.dataset.name===name));
 CURRENT=name;
 document.getElementById("exportbtn").style.display="";
 document.getElementById("content").innerHTML='<div class="empty">Analyzing '+esc(name)+' ...</div>';
 const r=await fetch("/api/analyze?file="+encodeURIComponent(name));
 DATA=await r.json();
 document.getElementById("dljson").href="/api/analyze?file="+encodeURIComponent(name);
 document.getElementById("dljson").setAttribute("download",name+".json");
 if(DATA.error){document.getElementById("content").innerHTML='<div class="banner bad">Error: '+esc(DATA.error)+'</div>';return;}
 renderTabs();render();
}
function countFor(id){if(id==="jobs")return JOBS.length;if(!DATA)return 0;if(id==="risk")return _riskClients().length;const m={kerberos:DATA.kerberos,ntlm:(DATA.ntlm||[]).filter(x=>x.user),mssql:DATA.mssql,ldap:DATA.ldap,tls:DATA.tls,radius:DATA.radius,eap:DATA.eap,cleartext:DATA.cleartext,appauth:DATA.app_auth,wpa:DATA.wpa,hosts:DATA.hostnames,dns:DATA.dns,http:DATA.http_auth,findings:DATA.findings,flows:DATA.conversations,netflow:DATA.netflow,talkers:DATA.talkers};return (m[id]||[]).length;}
function renderTabs(){
 const t=document.getElementById("tabs");t.innerHTML="";
 for(const [id,label] of TABS){
  const c=countFor(id);
  const tab=h("div",{class:"tab"+(id===activeTab?" active":"")},label);
  if(id==="jobs"){const run=JOBS.filter(j=>j.running).length;
   if(run)tab.append(h("span",{class:"badge"},String(run)));else if(c)tab.append(h("span",{class:"badge n"},String(c)));}
  else if(["kerberos","ntlm","mssql","ldap","http"].includes(id)&&c)tab.append(h("span",{class:"badge"},String(c)));
  else if(id==="findings"&&c)tab.append(h("span",{class:"badge"},String(c)));
  else if(c)tab.append(h("span",{class:"badge n"},String(c)));
  tab.onclick=()=>{activeTab=id;renderTabs();render();};t.append(tab);
 }
}
function render(){
 const c=document.getElementById("content");c.innerHTML="";
 if(!DATA)return;
 ({overview:vOverview,findings:vFindings,kerberos:vKerberos,ntlm:vNtlm,mssql:vMssql,
   ldap:vLdap,tls:vTls,radius:vRadius,eap:vEap,cleartext:vCleartext,appauth:vAppAuth,wpa:vWpa,hosts:vHosts,dns:vDns,risk:vRiskClients,http:vHttp,flows:vFlows,netflow:vNetflow,talkers:vTalkers,protocols:vProtocols,jobs:vJobs}[activeTab]||vOverview)(c);
}
function card(title,...body){const cd=h("div",{class:"card"});if(title)cd.append(h("h3",null,title));for(const b of body)if(b)cd.append(b);return cd;}
function kv(k,v){return h("div",{class:"kv"},h("span",{class:"k"},k),h("span",{class:"v"},v==null?"-":String(v)));}
function table(cols,rows,rowfn){const t=h("table");const tr=h("tr");cols.forEach(c=>tr.append(h("th",null,c)));t.append(h("thead",null,tr));
 const tb=h("tbody");rows.forEach(r=>tb.append(rowfn(r)));t.append(tb);return t;}
function empty(msg){return h("div",{class:"empty"},msg);}

function vOverview(c){
 const v=DATA.validation;
 c.append(h("div",{class:"banner "+(v.valid?"ok":"bad")},
   (v.valid?"VALID CAPTURE":"INVALID / CORRUPT CAPTURE")+" - "+v.format+" - "+v.packets+" packets"));
 const g=h("div",{class:"grid"});
 g.append(card("File",kv("Format",v.format+" v"+v.version),kv("Byte order",v.byte_order||"-"),
   kv("Link type",(v.linktypes||[]).join(", ")),kv("Snap length",v.snaplen||"-"),kv("Timestamp",v.ts_resolution)));
 g.append(card("Volume",kv("Packets",v.packets),kv("Bytes (wire)",bytes(v.bytes_on_wire)),
   kv("Duration",(v.duration||0).toFixed(3)+" s"),kv("Avg rate",((v.avg_rate_bps||0)/1e6).toFixed(3)+" Mbit/s"),
   kv("Truncated",v.truncated_frames)));
 const th=DATA.tcp_health||{};
 g.append(card("TCP health",kv("SYN",th.syn),kv("SYN-ACK",th.synack),kv("RST",th.rst),
   kv("Retrans/OOO",th.retrans),kv("Failed handshakes",th.failed_handshakes)));
 const ks={};(DATA.kerberos||[]).forEach(k=>ks[k.kind]=(ks[k.kind]||0)+1);
 const authCard=card("Authentication summary",
   kv("Kerberos messages",(DATA.kerberos||[]).length),
   kv("NTLM authentications",(DATA.ntlm||[]).filter(x=>x.user).length),
   kv("MSSQL logins",(DATA.mssql||[]).length),
   kv("LDAP binds",(DATA.ldap||[]).length),
   kv("TLS/LDAPS sessions",(DATA.tls||[]).length),
   kv("RADIUS auth",(DATA.radius||[]).length),
   kv("Cleartext creds",(DATA.cleartext||[]).length),
   kv("HTTP auth",(DATA.http_auth||[]).length));
 g.append(authCard);
 c.append(g);
 if((v.errors||[]).length||(v.warnings||[]).length){
  const cd=card("Validation messages");
  (v.errors||[]).forEach(e=>cd.append(h("div",{class:"finding",style:"border-color:var(--bad)"},e)));
  (v.warnings||[]).forEach(e=>cd.append(h("div",{class:"finding"},e)));
  c.append(cd);
 }
}
function vFindings(c){
 const f=DATA.findings||[];
 if(!f.length){c.append(empty("No anomalies flagged."));return;}
 const cd=card("Troubleshooting findings ("+f.length+")");
 f.forEach(x=>{const sev=/cleartext|NTLMv1|recovered|clear|Weak|failed|RST|corrupt/i.test(x)?"border-color:var(--bad)":"";
   cd.append(h("div",{class:"finding",style:sev},x));});
 c.append(cd);
}
function pillE(name){const weak=/rc4|des|md4|md5|exp/i.test(name);return h("span",{class:"pill "+(weak?"bad":"ok")},name);}
function vKerberos(c){
 const K=DATA.kerberos||[];if(!K.length){c.append(empty("No Kerberos traffic."));return;}
 const counts={};K.forEach(k=>counts[k.kind]=(counts[k.kind]||0)+1);
 const cc=card("Message types");const g=h("div",{class:"grid"});
 for(const k in counts)g.append(kv(k,counts[k]));cc.append(g);c.append(cc);
 const er={},eu={};K.forEach(k=>{(k.etypes||[]).forEach(e=>er[e]=(er[e]||0)+1);
   [k.enc_etype,k.ticket_etype].forEach(e=>{if(e)eu[e]=(eu[e]||0)+1;});});
 const ec=card("Encryption types");
 ec.append(h("div",null,h("b",null,"Requested: ")));
 const r1=h("div",{style:"margin:6px 0"});for(const e in er)r1.append(pillE(e+" ×"+er[e])," ");ec.append(r1);
 ec.append(h("div",null,h("b",null,"Used (tickets/enc-part): ")));
 const r2=h("div",{style:"margin:6px 0"});for(const e in eu)r2.append(pillE(e+" ×"+eu[e])," ");
 if(!Object.keys(eu).length)r2.append(empty("none observed"));ec.append(r2);c.append(ec);
 const errs=K.filter(k=>k.error_code);
 if(errs.length){const cd=card("KRB-ERROR");
  cd.append(table(["Error","User","SPN","Realm"],errs,k=>h("tr",null,
   h("td",null,h("span",{class:"pill bad"},k.error+" ("+k.error_code+")")),
   h("td",{class:"mono"},k.cname||"-"),h("td",{class:"mono"},k.sname||"-"),h("td",null,k.realm||"-"))));c.append(cd);}
 const cd=card("Messages");
 cd.append(table(["Type","Client","Server","User","SPN","Etypes","Used","PreAuth"],K,k=>h("tr",null,
   h("td",null,h("span",{class:"pill info"},k.kind)),h("td",{class:"mono"},k.client||"-"),
   h("td",{class:"mono"},k.server||"-"),h("td",{class:"mono"},k.cname||"-"),h("td",{class:"mono"},k.sname||"-"),
   h("td",{class:"mono"},(k.etypes||[]).join(", ")||"-"),
   h("td",{class:"mono"},[k.enc_etype,k.ticket_etype].filter(Boolean).join(", ")||"-"),
   h("td",null,k.kind==="AS-REQ"?(k.preauth?h("span",{class:"pill ok"},"yes"):h("span",{class:"pill warn"},"NO")):"-"))));
 c.append(cd);
 const hashes=[];K.forEach(k=>(k.hashes||[]).forEach(hd=>hashes.push(hd)));
 if(hashes.length){const hc=card("Extracted usernames + crackable hashes ("+hashes.length+")");
  hashes.forEach(hd=>{
   hc.append(h("div",{style:"margin:10px 0 4px"},
     h("span",{class:"pill warn"},hd.type)," ",h("b",null,hd.user||"-"),
     hd.spn?h("span",{class:"mono"}," "+hd.spn):"", " ",
     h("span",{class:"pill "+(/rc4|des/i.test(hd.etype)?"bad":"info")},hd.etype)," ",
     h("span",{style:"color:var(--muted)"},"hashcat -m "+hd.mode)));
   const hh=h("div",{class:"hash"},hd.hash);hh.append(copyBtn(hd.hash));hc.append(hh);
  });
  c.append(hc);}
}
function vTls(c){
 const T=DATA.tls||[];if(!T.length){c.append(empty("No TLS/LDAPS sessions found."));return;}
 T.forEach(t=>{const cd=card((t.service||"TLS")+"   "+t.client+" → "+t.server);
  const weak=/SSL|TLS 1\.0|TLS 1\.1/.test(t.version||"");
  cd.append(h("div",{style:"margin-bottom:8px"},"Version: ",h("span",{class:"pill "+(weak?"bad":"ok")},(t.version||"?")+(t.truncated?"+":""))));
  if(t.truncated)cd.append(h("div",{class:"finding"},"Handshake truncated by capture snaplen — cipher / certificate / exact version unavailable."));
  if(t.sni)cd.append(kv("SNI (client asked)",t.sni));
  if(t.cipher)cd.append(kv("Cipher suite",t.cipher));
  if(t.cert_subject||(t.cert_sans||[]).length){
   cd.append(kv("Cert subject CN",t.cert_subject||"-"));
   if(t.cert_org)cd.append(kv("Cert org",t.cert_org));
   if((t.cert_sans||[]).length)cd.append(kv("Cert SANs",t.cert_sans.join(", ")));
   cd.append(kv("Cert issuer CN",t.cert_issuer||"-"));
   cd.append(kv("Valid",(t.not_before||"?")+"  ..  "+(t.not_after||"?")));
  } else cd.append(h("div",{class:"finding"},"Certificate not in cleartext (TLS 1.3 encrypts it)."));
  c.append(cd);});
}
function copyBtn(text){const b=h("button",{class:"copy"},"copy");b.onclick=()=>{navigator.clipboard.writeText(text);b.textContent="copied";setTimeout(()=>b.textContent="copy",1000);};return b;}
function vNtlm(c){
 const N=(DATA.ntlm||[]).filter(x=>x.user);
 if(!N.length){const obs=(DATA.ntlm||[]).length;c.append(empty(obs?(obs+" NTLM challenge(s) seen but no completed authenticate."):"No NTLM authentication."));return;}
 const vs={};N.forEach(n=>vs[n.version]=(vs[n.version]||0)+1);
 const sc=card("Summary");const g=h("div",{class:"grid"});g.append(kv("Total",N.length));
 for(const v in vs)g.append(kv(v,vs[v]));sc.append(g);c.append(sc);
 N.forEach(n=>{const cd=card((n.domain?n.domain+"\\":"")+n.user+"  ");
  cd.querySelector("h3").append(h("span",{class:"pill "+(n.version==="NTLMv1"?"bad":"warn")},n.version),
    " ",h("span",{class:"pill info"},n.carrier));
  cd.append(kv("Workstation",n.workstation||"-"));cd.append(kv("Path",n.client+" → "+n.server));
  cd.append(kv("Server challenge",n.challenge||"(not captured)"));
  if(n.hashcat){cd.append(h("div",{style:"margin:8px 0 4px;color:var(--muted)"},"hashcat mode "+n.hashcat_mode));
   const hd=h("div",{class:"hash"},n.hashcat);hd.append(copyBtn(n.hashcat));cd.append(hd);}
  else cd.append(h("div",{class:"finding"},"No server challenge in this stream - hash incomplete."));
  c.append(cd);});
}
function vMssql(c){
 const M=DATA.mssql||[];if(!M.length){c.append(empty("No MSSQL/TDS traffic."));return;}
 M.forEach(m=>{const cd=card(m.client+" → "+m.server);
  const enc=m.encryption||"-";const weak=/OFF|NOT_SUP/.test(enc);
  cd.append(h("div",{style:"margin-bottom:8px"},"Encryption: ",h("span",{class:"pill "+(weak?"bad":"ok")},enc)));
  if(m.login){const l=m.login;
   cd.append(kv("Auth type",l.auth_type));
   if(l.username)cd.append(kv("Username",l.username));
   if(l.password){const r=h("div",{class:"kv"},h("span",{class:"k"},"Password (recovered)"),h("span",{class:"v",style:"color:var(--bad)"},l.password));cd.append(r);}
   if(l.hostname)cd.append(kv("Client host",l.hostname+(l.client_mac?" ("+l.client_mac+")":"")));
   if(l.appname)cd.append(kv("Application",l.appname));
   if(l.servername)cd.append(kv("Server name",l.servername));
   if(l.database)cd.append(kv("Database",l.database));
   if(l.sspi_present)cd.append(kv("SSPI/NTLM","present (see NTLM tab)"));
  } else cd.append(empty("pre-login only, no Login7 captured"));
  c.append(cd);});
}
function vLdap(c){
 const L=DATA.ldap||[];if(!L.length){c.append(empty("No LDAP bind traffic (LDAPS is encrypted)."));return;}
 const cd=card("LDAP binds");
 cd.append(table(["Dir","Client","Server","Method/Result","DN / detail"],L,b=>h("tr",null,
   h("td",null,b.kind),h("td",{class:"mono"},b.client||"-"),h("td",{class:"mono"},b.server||"-"),
   h("td",null,b.kind==="request"?h("span",{class:"pill "+(b.cleartext?"bad":"info")},b.method+(b.mechanism?" "+b.mechanism:"")):
     h("span",{class:"pill "+(b.result_code===0?"ok":"bad")},b.result+" ("+b.result_code+")")),
   h("td",{class:"mono"},b.dn?(b.dn+(b.password?"  pass="+b.password:"")):"-"))));
 c.append(cd);
}
function vRadius(c){
 const R=DATA.radius||[];if(!R.length){c.append(empty("No RADIUS traffic (UDP 1812/1813/1645/1646)."));return;}
 const validSec=R.find(f=>f.secret_valid);
 const recoverable=R.some(f=>f.can_recover_secret);
 const sp=card("Shared secret");
 if(validSec){sp.append(h("div",null,"Confirmed shared secret: ",h("b",{style:"color:var(--ok)"},validSec.secret),
   h("span",{style:"color:var(--muted)"}," — PAP passwords below are decrypted.")));}
 else{
  sp.append(h("div",{style:"color:var(--muted);margin-bottom:8px;font-size:12px"},
    recoverable?"Unknown — recoverable from a captured Response/Message-Authenticator.":"Unknown — no verifiable authenticator captured (you can still enter a known secret to decrypt PAP)."));
  const row=h("div",{style:"display:flex;gap:8px;align-items:center;flex-wrap:wrap"});
  const inp=h("input",{type:"text",placeholder:"enter known shared secret",style:"flex:1;min-width:160px;background:#0b0f14;border:1px solid var(--border);color:var(--fg);border-radius:6px;padding:6px 8px"});
  const ap=h("button",{class:"btn"},"Apply secret");ap.onclick=()=>applyRadiusSecret(inp.value);
  const rc=h("button",{class:"btn primary"},"Recover from wordlist");if(!recoverable)rc.setAttribute("disabled","");rc.onclick=recoverRadiusSecret;
  row.append(inp,ap,rc);sp.append(row);
  sp.append(h("div",{id:"radstat",style:"margin-top:8px;font-size:12px;color:var(--muted)"}));
 }
 c.append(sp);
 const cd=card("RADIUS authentications");
 cd.append(table(["Client (NAS)","Server","User","Method","Result","Password / hash"],R,f=>h("tr",null,
   h("td",{class:"mono"},f.client),h("td",{class:"mono"},f.server),h("td",{class:"mono"},f.username||"-"),
   h("td",null,h("span",{class:"pill "+(/MS-CHAP/.test(f.method)?"warn":/PAP/.test(f.method)?"bad":"info")},f.method)),
   h("td",null,h("span",{class:"pill "+(f.result==="Access-Accept"?"ok":f.result==="Access-Reject"?"bad":"info")},f.result)),
   h("td",{class:"mono"},f.password?h("b",{style:"color:var(--ok)"},f.password):(f.hashcat?"MS-CHAP hash (Export→Crack)":(f.has_pap?"PAP (needs secret)":"-"))))));
 c.append(cd);
 const hashes=R.filter(f=>f.hashcat);
 if(hashes.length){const hc=card("Extracted MS-CHAP(v2) hashes — hashcat -m 5500 (Export hashes → Crack)");
  hashes.forEach(f=>{hc.append(h("div",{style:"margin:8px 0 4px"},h("span",{class:"pill warn"},f.version)," ",h("b",null,f.username)));
   const hh=h("div",{class:"hash"},f.hashcat);hh.append(copyBtn(f.hashcat));hc.append(hh);});
  c.append(hc);}
}
async function applyRadiusSecret(secret){
 if(!secret){alert("Enter a shared secret");return;}
 if(!CURRENT)return;
 try{
  const r=await fetch("/api/radius/secret?file="+encodeURIComponent(CURRENT)+"&secret="+encodeURIComponent(secret),{method:"POST"});
  const j=await r.json();
  if(j.error){alert(j.error);return;}
  DATA.radius=j.radius;
  if(activeTab==="radius")render();
  if(!j.valid)alert("Secret could not be confirmed against a captured authenticator — PAP was decrypted but may be wrong.");
 }catch(e){alert("Error: "+e.message);}
}
async function recoverRadiusSecret(){
 if(!CURRENT)return;
 const set=t=>{const s=document.getElementById("radstat");if(s)s.textContent=t;};
 set("starting recovery…");
 try{
  await fetch("/api/radius/recover?file="+encodeURIComponent(CURRENT),{method:"POST"});
  const poll=async()=>{
   const s=await (await fetch("/api/radius/recover_status?file="+encodeURIComponent(CURRENT))).json();
   if(!s.done){set("recovering… "+(s.tested?fmtBig(s.tested)+" tried":""));setTimeout(poll,1000);return;}
   if(s.status==="found"){set("recovered: "+s.secret);applyRadiusSecret(s.secret);}
   else set("recovery "+s.status+(s.tested?(" — tried "+fmtBig(s.tested)):""));
  };
  setTimeout(poll,800);
 }catch(e){set("error: "+e.message);}
}
// ── Risk client aggregator ────────────────────────────────────────────────────
function _riskClients(){
 if(!DATA) return [];
 const W={CRITICAL:10,HIGH:5,MEDIUM:2};
 const P={CRITICAL:4,HIGH:3,MEDIUM:2,INFO:1};
 const cl={};
 function ipOnly(addr){
  if(!addr) return '';
  if(addr.startsWith('[')) return addr.replace(/^\[([^\]]+)\].*$/,'$1'); // [IPv6]:port
  const i=addr.lastIndexOf(':');
  return (i>0&&/^\d+$/.test(addr.slice(i+1)))?addr.slice(0,i):addr;  // IPv4:port
 }
 function add(ip,sev,proto,label,acct){
  ip=ipOnly(ip); if(!ip) return;
  const e=cl[ip]||(cl[ip]={ip,findings:[],score:0,worst:'MEDIUM',n:{CRITICAL:0,HIGH:0,MEDIUM:0}});
  e.findings.push({sev,proto,label,acct:acct||''});
  e.score+=(W[sev]||0);
  e.n[sev]=(e.n[sev]||0)+1;
  if((P[sev]||0)>(P[e.worst]||0)) e.worst=sev;
 }
 // Cleartext credentials on the wire
 (DATA.cleartext||[]).forEach(f=>{
  if(f.password) add(f.client,'CRITICAL',f.protocol,'cleartext password',f.username);
 });
 // MSSQL cleartext login (Login7 with recovered password)
 (DATA.mssql||[]).forEach(f=>{
  if(f.login&&f.login.password) add(f.client,'CRITICAL','MSSQL','cleartext login',f.login.username);
 });
 // LDAP cleartext bind
 (DATA.ldap||[]).forEach(f=>{
  if(f.cleartext&&f.password) add(f.client,'CRITICAL','LDAP','cleartext bind password',f.dn);
 });
 // HTTP Basic auth — password is just base64, effectively cleartext
 (DATA.http_auth||[]).forEach(f=>{
  if(f.scheme==='Basic'&&f.password) add(f.client,'CRITICAL','HTTP','Basic auth (base64 pw)',f.username);
 });
 // RADIUS PAP cleartext
 (DATA.radius||[]).forEach(f=>{
  if(f.password) add(f.client,'CRITICAL','RADIUS','PAP cleartext',f.username);
 });
 // NetNTLM hashes (offline crackable)
 (DATA.ntlm||[]).forEach(f=>{
  if(f.hashcat) add(f.client,'HIGH','NTLM','NetNTLMv'+(f.version||'?')+' hash',f.user);
 });
 // Kerberos crackable hashes (AS-REP roast, Kerberoast)
 (DATA.kerberos||[]).forEach(f=>{
  if(f.hashes&&f.hashes.length) f.hashes.forEach(h=>add(f.client,'HIGH','Kerberos',h.type||'crackable hash',f.cname));
 });
 // App auth hashes (PostgreSQL MD5, MySQL, CRAM-MD5, SIP digest, SNMPv3…)
 (DATA.app_auth||[]).forEach(f=>{
  if(f.hashcat) add(f.client,'HIGH',f.protocol,'hash captured',f.account);
 });
 // RADIUS MS-CHAP / EAP hashes
 (DATA.radius||[]).forEach(f=>{
  if(f.hashcat) add(f.client,'HIGH','RADIUS','MS-CHAP hash',f.username);
 });
 (DATA.eap||[]).forEach(f=>{
  if(f.hashcat) add(f.client,'HIGH','EAP',f.method+' hash',f.identity);
 });
 return Object.values(cl).sort((a,b)=>b.score-a.score);
}

// ── Risk visualization tab ─────────────────────────────────────────────────────
function vRiskClients(c){
 const all=_riskClients();
 if(!all.length){c.append(empty('No risky clients found in this capture.'));return;}

 // ── KPI summary row ──────────────────────────────────────────────────────────
 const SCOLOR={CRITICAL:'var(--bad)',HIGH:'var(--warn)',MEDIUM:'#eab308'};
 const SBG={CRITICAL:'rgba(248,81,73,.12)',HIGH:'rgba(210,153,34,.12)',MEDIUM:'rgba(234,179,8,.12)'};
 const crit=all.filter(x=>x.worst==='CRITICAL');
 const high=all.filter(x=>x.worst==='HIGH');
 const kpi=h('div',{style:'display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px'});
 [[crit,'CRITICAL','Cleartext credential on the wire'],[high,'HIGH','Crackable hash captured']].forEach(([grp,sev,tip])=>{
  const box=h('div',{title:tip,style:'flex:1;min-width:130px;background:'+SBG[sev]+';border:1px solid '+SCOLOR[sev]+';border-radius:8px;padding:12px 16px;'});
  box.append(h('div',{style:'font-size:28px;font-weight:700;color:'+SCOLOR[sev]},grp.length));
  box.append(h('div',{style:'font-size:12px;color:var(--fg);margin-top:2px'},sev));
  box.append(h('div',{style:'font-size:11px;color:var(--muted);margin-top:1px'},tip));
  kpi.append(box);
 });
 c.append(kpi);

 // ── SVG stacked-bar chart ────────────────────────────────────────────────────
 const shown=all.slice(0,30);
 const maxScore=shown[0].score||1;
 const ROW=28, LPAD=168, BPAD=16, svgW=660, barW=svgW-LPAD-BPAD;
 const svgH=ROW*shown.length+24;
 let svgRows='';
 shown.forEach((cl,i)=>{
  const y=i*ROW;
  const totW=Math.max(2,Math.round(cl.score/maxScore*barW));
  const nc=cl.n.CRITICAL||0, nh=cl.n.HIGH||0, nm=cl.n.MEDIUM||0;
  const tot=nc+nh+nm||1;
  const wc=Math.round(nc/tot*totW), wh=Math.round(nh/tot*totW), wm=totW-wc-wh;
  let bx=LPAD;
  const segs=[];
  if(wc>0){segs.push(`<rect x="${bx}" y="${y+7}" width="${wc}" height="14" rx="2" fill="#ef4444"/>`);bx+=wc;}
  if(wh>0){segs.push(`<rect x="${bx}" y="${y+7}" width="${wh}" height="14" rx="2" fill="#f97316"/>`);bx+=wh;}
  if(wm>0){segs.push(`<rect x="${bx}" y="${y+7}" width="${wm}" height="14" rx="2" fill="#eab308"/>`);bx+=wm;}
  const findings=cl.n.CRITICAL+cl.n.HIGH+cl.n.MEDIUM;
  const countLabel=`${nc>0?nc+'c ':''  }${nh>0?nh+'h ':''  }${nm>0?nm+'m':''  }`.trim();
  svgRows+=`<g class="risk-row" data-ip="${cl.ip}" style="cursor:pointer">
   <rect x="0" y="${y}" width="${svgW}" height="${ROW}" fill="transparent" class="risk-hover"/>
   <text x="${LPAD-8}" y="${y+18}" text-anchor="end" fill="#8b949e" font-family="ui-monospace,monospace" font-size="12">${cl.ip}</text>
   <rect x="${LPAD}" y="${y+7}" width="${barW}" height="14" rx="2" fill="#161b22"/>
   ${segs.join('')}
   <text x="${bx+5}" y="${y+18}" fill="#8b949e" font-family="ui-monospace,monospace" font-size="11">${countLabel}</text>
  </g>`;
 });

 const svgLegend=`<g>
  <rect x="${LPAD}" y="${svgH-16}" width="12" height="10" rx="2" fill="#ef4444"/>
  <text x="${LPAD+16}" y="${svgH-7}" fill="#8b949e" font-size="11" font-family="sans-serif">CRITICAL</text>
  <rect x="${LPAD+90}" y="${svgH-16}" width="12" height="10" rx="2" fill="#f97316"/>
  <text x="${LPAD+106}" y="${svgH-7}" fill="#8b949e" font-size="11" font-family="sans-serif">HIGH</text>
  <rect x="${LPAD+160}" y="${svgH-16}" width="12" height="10" rx="2" fill="#eab308"/>
  <text x="${LPAD+176}" y="${svgH-7}" fill="#8b949e" font-size="11" font-family="sans-serif">MEDIUM</text>
  <text x="${LPAD+300}" y="${svgH-7}" fill="#30363d" font-size="10" font-family="sans-serif">c=critical h=high m=medium</text>
 </g>`;

 const chartCard=card('Client risk overview'+(all.length>30?' (top 30 shown)':''));
 const chartWrap=h('div',{style:'overflow-x:auto'});
 chartWrap.innerHTML=`<svg viewBox="0 0 ${svgW} ${svgH+4}" width="100%" style="max-width:${svgW}px;display:block">
  <style>.risk-hover{transition:fill .1s}.risk-row:hover .risk-hover{fill:rgba(255,255,255,.04)}</style>
  ${svgRows}${svgLegend}</svg>`;
 chartCard.append(chartWrap);
 c.append(chartCard);

 // ── Per-client finding cards ──────────────────────────────────────────────────
 const detCard=card('Risky clients — detail ('+all.length+')');
 all.forEach(cl=>{
  const sev=cl.worst;
  const row=h('div',{style:'border:1px solid '+SCOLOR[sev]+';border-radius:8px;margin-bottom:10px;overflow:hidden'});
  // header
  const head=h('div',{style:'display:flex;align-items:center;gap:10px;padding:10px 14px;background:'+SBG[sev]+';cursor:pointer'});
  head.append(
   h('span',{class:'pill '+(sev==='CRITICAL'?'bad':sev==='HIGH'?'warn':''),style:'min-width:76px;text-align:center'},sev),
   h('b',{class:'mono'},cl.ip),
   h('span',{style:'color:var(--muted);font-size:12px;margin-left:4px'},cl.findings.length+' finding'+(cl.findings.length!==1?'s':'')),
   h('span',{style:'color:var(--muted);font-size:11px;margin-left:auto'},'score: '+cl.score)
  );
  const body=h('div',{style:'display:none;padding:10px 14px'});
  // Roll up by sev+proto+label; collect all distinct accounts under each
  const byKey={};
  cl.findings.forEach(f=>{
   const k=f.sev+'\0'+f.proto+'\0'+f.label;
   if(!byKey[k]) byKey[k]={sev:f.sev,proto:f.proto,label:f.label,accts:new Set(),n:0};
   byKey[k].n++;
   if(f.acct) byKey[k].accts.add(f.acct);
  });
  Object.values(byKey).forEach(f=>{
   const acctList=[...f.accts].join(', ');
   const fc=h('div',{style:'display:flex;align-items:baseline;gap:8px;padding:5px 0;border-bottom:1px solid var(--border)'});
   fc.append(
    h('span',{class:'pill '+(f.sev==='CRITICAL'?'bad':'warn'),style:'font-size:10px;min-width:60px;text-align:center'},f.sev),
    h('span',{style:'font-family:var(--mono);font-size:12px;color:var(--accent);min-width:80px'},f.proto),
    h('span',{style:'font-size:13px'},f.label),
    acctList?h('span',{style:'color:var(--muted);font-size:12px;margin-left:4px'},'('+acctList+')'):null,
    f.n>1?h('span',{style:'color:var(--muted);font-size:11px;margin-left:auto'},'\xd7'+f.n):null
   );
   body.append(fc);
  });
  head.onclick=()=>{body.style.display=body.style.display==='none'?'block':'none';};
  row.append(head,body);
  detCard.append(row);
 });
 c.append(detCard);
}
function vDns(c){
 const T=DATA.dns||[];if(!T.length){c.append(empty("No DNS traffic captured."));return;}
 // summary stats
 const answered=T.filter(t=>t.ts_r);
 const nxd=T.filter(t=>t.rcode===3);
 const fail=T.filter(t=>t.rcode>0&&t.rcode!==3);
 const tout=T.filter(t=>t.rcode===-1);
 const lats=answered.map(t=>t.latency_ms).filter(v=>v!=null);
 const avgLat=lats.length?lats.reduce((a,b)=>a+b,0)/lats.length:null;
 const sumCard=card("DNS summary");
 const kpis=h("div",{style:"display:flex;gap:20px;flex-wrap:wrap;margin-bottom:4px"});
 const kp=(l,v,bad)=>h("div",{style:"min-width:90px"},h("div",{style:"font-size:22px;font-weight:700;color:"+(bad?"var(--bad)":"var(--fg)"),},v),h("div",{style:"font-size:11px;color:var(--muted)"},l));
 kpis.append(kp("Queries",T.length),kp("Answered",answered.length),
   kp("NXDOMAIN",nxd.length,nxd.length>0),kp("Failed",fail.length,fail.length>0),
   kp("Timeout",tout.length,tout.length>0),
   kp("Avg latency",avgLat!=null?(avgLat.toFixed(1)+" ms"):"-",avgLat>500));
 sumCard.append(kpis);
 c.append(sumCard);
 // server stats
 const svrs={};T.forEach(t=>{const s=svrs[t.server]||(svrs[t.server]={total:0,answered:0,nxd:0,fail:0,lats:[]});s.total++;if(t.ts_r){s.answered++;if(t.latency_ms!=null)s.lats.push(t.latency_ms);}if(t.rcode===3)s.nxd++;if(t.rcode>0&&t.rcode!==3)s.fail++;});
 const sc=card("DNS servers");
 sc.append(table(["Server","Queries","Answered","NXDOMAIN","Errors","Avg latency"],Object.entries(svrs).sort((a,b)=>b[1].total-a[1].total),([srv,s])=>h("tr",null,
   h("td",{class:"mono"},srv),h("td",null,s.total),h("td",null,s.answered),
   h("td",null,s.nxd?h("b",{style:"color:var(--bad)"},s.nxd):"-"),
   h("td",null,s.fail?h("b",{style:"color:var(--warn)"},s.fail):"-"),
   h("td",null,s.lats.length?(s.lats.reduce((a,b)=>a+b)/s.lats.length).toFixed(1)+" ms":"-"))));
 c.append(sc);
 // top queried names
 const qc={};T.forEach(t=>{const k=t.qname.toLowerCase();if(!qc[k])qc[k]={n:0,types:new Set(),answers:new Set()};qc[k].n++;qc[k].types.add(t.qtype);t.answers.forEach(a=>{if(a[2])qc[k].answers.add(a[2]);});});
 const top=Object.entries(qc).sort((a,b)=>b[1].n-a[1].n).slice(0,30);
 const dc=card("Top queried names");
 dc.append(table(["Name","Types","Count","Resolved to"],top,([name,s])=>h("tr",null,
   h("td",{class:"mono"},name),h("td",null,[...s.types].join(", ")),h("td",null,s.n),
   h("td",{class:"mono"},([...s.answers].slice(0,3).join(", "))||"-"))));
 c.append(dc);
 // failures
 const errs=T.filter(t=>t.rcode!==0&&t.rcode!==-1).concat(tout);
 if(errs.length){const ec=card("Failures / errors");
  ec.append(table(["Time","RCODE","Type","Query","Client","Server"],errs,t=>h("tr",null,
    h("td",{class:"mono"},t.ts_q?new Date(t.ts_q*1000).toISOString().replace("T"," ").replace("Z",""):"-"),
    h("td",null,h("span",{class:"pill "+(t.rcode===3?"warn":"bad")},t.rcode_name)),
    h("td",null,t.qtype),h("td",{class:"mono"},t.qname),
    h("td",{class:"mono"},t.client),h("td",{class:"mono"},t.server))));
  c.append(ec);}
 // searchable transaction log
 const search=h("input",{type:"text",placeholder:"filter transactions by name / IP / type / RCODE…",value:DNS_Q,
   style:"width:100%;box-sizing:border-box;background:#0b0f14;border:1px solid var(--border);color:var(--fg);border-radius:6px;padding:8px 10px;margin-bottom:6px;font:inherit"});
 const logDiv=h("div",null);
 function drawLog(){logDiv.textContent="";const q=DNS_Q.toLowerCase().trim();
  const F=q?T.filter(t=>((t.qname||"")+" "+(t.qtype||"")+" "+(t.rcode_name||"")+" "+(t.client||"")+" "+(t.server||"")).toLowerCase().includes(q)):T;
  const lc=card("Transactions ("+F.length+(q?" of "+T.length:"")+")");
  lc.append(table(["Time","Type","Query","RCODE","Latency","Answers","Client","Server"],F.slice(0,500),t=>h("tr",null,
    h("td",{class:"mono",style:"font-size:11px"},t.ts_q?new Date(t.ts_q*1000).toISOString().slice(11,22)+" UTC":"-"),
    h("td",null,t.qtype),h("td",{class:"mono"},t.qname),
    h("td",null,t.rcode===0?h("span",{class:"pill ok"},"OK"):h("span",{class:"pill "+(t.rcode_name==="TIMEOUT"||t.rcode===3?"warn":"bad")},t.rcode_name)),
    h("td",null,t.latency_ms!=null?t.latency_ms.toFixed(1)+" ms":"-"),
    h("td",{class:"mono",style:"max-width:200px;overflow:hidden;text-overflow:ellipsis"},t.answers.map(a=>a[2]).filter(Boolean).join(", ")||"-"),
    h("td",{class:"mono"},t.client),h("td",{class:"mono"},t.server))));
  if(F.length>500)lc.append(h("div",{style:"color:var(--muted);font-size:12px;margin-top:4px"},"showing first 500 of "+F.length));
  logDiv.append(lc);}
 search.oninput=()=>{DNS_Q=search.value;drawLog();};
 c.append(search);c.append(logDiv);drawLog();
}
function vHosts(c){
 const H=DATA.hostnames||[];if(!H.length){c.append(empty("No hostnames (DNS / SNI / HTTP Host / DHCP / cert)."));return;}
 const search=h("input",{type:"text",placeholder:"filter by name / IP / source / type…",value:HOST_Q,
   style:"width:100%;box-sizing:border-box;background:#0b0f14;border:1px solid var(--border);color:var(--fg);border-radius:6px;padding:8px 10px;margin-bottom:12px;font:inherit"});
 const results=h("div",null);
 function draw(){
  results.textContent="";
  const q=HOST_Q.toLowerCase().trim();
  const F=q?H.filter(x=>((x.name||"")+" "+(x.ip||"")+" "+(x.kind||"")+" "+(x.source||"")).toLowerCase().includes(q)):H;
  const byip={};F.forEach(x=>{if(x.ip){(byip[x.ip]=byip[x.ip]||new Set()).add(x.name);}});
  const ips=Object.keys(byip).sort();
  if(ips.length){const inv=card("Host inventory (IP → names)");
   inv.append(table(["IP","Names"],ips,ip=>h("tr",null,h("td",{class:"mono"},ip),
     h("td",{class:"mono"},Array.from(byip[ip]).sort().join(", ")))));
   results.append(inv);}
  const cd=card("Names ("+F.length+(q?(" of "+H.length):"")+")");
  if(!F.length)cd.append(empty("No matches."));
  else{const sorted=F.slice().sort((a,b)=>a.name.toLowerCase()<b.name.toLowerCase()?-1:1);
   cd.append(table(["Name","Type","IP","Source"],sorted,x=>h("tr",null,
     h("td",{class:"mono"},x.name),
     h("td",null,h("span",{class:"pill info"},x.kind)),
     h("td",{class:"mono"},x.ip||"-"),
     h("td",{class:"mono"},x.source||"-"))));}
  results.append(cd);
 }
 search.oninput=()=>{HOST_Q=search.value;draw();};
 c.append(search);c.append(results);
 draw();
}
function vWpa(c){
 const W=DATA.wpa||[];if(!W.length){c.append(empty("No WPA handshakes/PMKIDs (802.11/radiotap captures only)."));return;}
 const cd=card("WPA / Wi-Fi — hashcat -m 22000 (Export hashes → Crack)");
 cd.append(table(["Type","SSID","BSSID","Client"],W,f=>h("tr",null,
   h("td",null,h("span",{class:"pill "+(f.kind==="PMKID"?"warn":"bad")},f.kind)),
   h("td",{class:"mono"},f.essid||"?"),h("td",{class:"mono"},f.bssid),h("td",{class:"mono"},f.sta))));
 c.append(cd);
 W.forEach(f=>{const hc=card((f.kind)+"  "+(f.essid||f.bssid));
  if(f.note)hc.append(h("div",{class:"finding"},f.note));
  const hh=h("div",{class:"hash"},f.hashcat);hh.append(copyBtn(f.hashcat));hc.append(hh);
  c.append(hc);});
}
function vAppAuth(c){
 const A=DATA.app_auth||[];if(!A.length){c.append(empty("No DB/VoIP/remote auth (PostgreSQL/MySQL/SIP/VNC/RDP/CRAM-MD5/HTTP-Digest)."));return;}
 const cd=card("Database / VoIP / remote-access auth");
 cd.append(table(["Protocol","Account","Crack","Path"],A,f=>h("tr",null,
   h("td",null,h("span",{class:"pill "+(/RDP|HTTP/.test(f.protocol)?"warn":"info")},f.protocol)),
   h("td",{class:"mono"},f.account||"-"),
   h("td",{class:"mono"},f.mode?("hashcat -m "+f.mode):(f.tool==="john"?"john":(f.note?"":"-"))),
   h("td",{class:"mono"},f.client+" → "+f.server))));
 c.append(cd);
 A.filter(f=>f.hashcat||f.note).forEach(f=>{const hc=card(f.protocol+(f.account?(" — "+f.account):""));
  if(f.mode)hc.querySelector("h3").append(" ",h("span",{class:"pill info"},"hashcat -m "+f.mode));
  else if(f.tool==="john")hc.querySelector("h3").append(" ",h("span",{class:"pill warn"},"john"));
  if(f.hashcat){const hh=h("div",{class:"hash"},f.hashcat);hh.append(copyBtn(f.hashcat));hc.append(hh);}
  if(f.note)hc.append(h("div",{style:"color:var(--muted);font-size:12px;margin-top:6px"},f.note));
  c.append(hc);});
}
function vCleartext(c){
 const C=DATA.cleartext||[];if(!C.length){c.append(empty("No cleartext-auth protocols (FTP/TELNET/SMTP/POP3/IMAP/SNMP)."));return;}
 const cd=card("Cleartext / legacy auth — credentials exposed on the wire");
 cd.append(table(["Protocol","Mechanism","Username","Password / community","Result","Path"],C,f=>h("tr",null,
   h("td",null,h("span",{class:"pill bad"},f.protocol)),
   h("td",{class:"mono"},f.mechanism),
   h("td",{class:"mono"},f.username||"-"),
   h("td",{class:"mono"},f.password?h("b",{style:"color:var(--bad)"},f.password):"-"),
   h("td",null,f.result?h("span",{class:"pill "+(f.result==="success"?"ok":"warn")},f.result):(f.note?h("span",{class:"pill warn"},f.note):"-")),
   h("td",{class:"mono"},f.client+" → "+f.server))));
 c.append(cd);
}
function vEap(c){
 const E=DATA.eap||[];if(!E.length){c.append(empty("No EAP traffic (RADIUS EAP-Message or 802.1X EAPOL)."));return;}
 const cd=card("EAP / PEAP exchanges");
 cd.append(table(["Via","Client","Server","Identity","Method","Result","Inner / server cert"],E,f=>h("tr",null,
   h("td",null,h("span",{class:"pill info"},f.carrier||"RADIUS")),
   h("td",{class:"mono"},f.client),h("td",{class:"mono"},f.server),h("td",{class:"mono"},f.identity||"-"),
   h("td",null,h("span",{class:"pill "+(/MD5/.test(f.method)?"bad":/PEAP|TLS|TTLS|FAST/.test(f.method)?"ok":"warn")},f.method)),
   h("td",null,h("span",{class:"pill "+(f.result==="Success"?"ok":f.result==="Failure"?"bad":"info")},f.result||"-")),
   h("td",{class:"mono"},f.cert_subject?("cert "+f.cert_subject+(f.not_after?(" exp "+f.not_after):"")):(f.tunnelled?"encrypted (TLS tunnel)":(f.hashcat?f.version:(f.nak_to?("NAK→"+f.nak_to):"-")))))));
 c.append(cd);
 const hashes=E.filter(f=>f.hashcat);
 if(hashes.length){const hc=card("Extracted EAP hashes — Export hashes → Crack");
  hashes.forEach(f=>{const mode=f.mode||"5500";
   hc.append(h("div",{style:"margin:8px 0 4px"},h("span",{class:"pill warn"},f.version)," ",h("b",null,f.identity||"-"),h("span",{style:"color:var(--muted)"}," hashcat -m "+mode)));
   const hh=h("div",{class:"hash"},f.hashcat);hh.append(copyBtn(f.hashcat));hc.append(hh);});
  c.append(hc);}
}
function vHttp(c){
 const H=DATA.http_auth||[];if(!H.length){c.append(empty("No HTTP auth headers (HTTPS is encrypted)."));return;}
 const cd=card("HTTP authentication");
 cd.append(table(["Dir","Scheme","Host/Server","Detail"],H,a=>h("tr",null,
   h("td",null,a.direction==="request"?"→":"←"),
   h("td",null,h("span",{class:"pill "+(/basic/i.test(a.scheme)?"bad":"info")},a.scheme)),
   h("td",{class:"mono"},a.host||a.server||"-"),
   h("td",{class:"mono"},a.direction==="request"?((a.method||"")+" "+(a.uri||"")+(a.username?"  ["+a.username+(a.password?":"+a.password:"")+"]":"")):
     ((a.status||"")+(a.ntlm?" NTLM":""))))));
 c.append(cd);
}
function nfTime(t){return t?new Date(t*1000).toISOString().replace("T"," ").replace("Z","")+" UTC":"-";}
function vNetflow(c){
 const N=DATA.netflow||[];if(!N.length){c.append(empty("No flows."));return;}
 const cd=card("NetFlow — "+N.length+" unidirectional 5-tuple flows");
 const dl=h("button",{class:"crackbtn",style:"color:var(--accent);margin-bottom:8px"},"⬇ Download CSV");
 dl.onclick=()=>{
  const rows=["ts,te,td,pr,sa,sp,da,dp,flg,ipkt,ibyt,tos"];
  N.forEach(f=>rows.push([nfTime(f.first),nfTime(f.last),(f.duration||0).toFixed(3),f.proto,f.src,f.sport,f.dst,f.dport,f.flags||"",f.packets,f.bytes,f.tos].join(",")));
  const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([rows.join("\n")+"\n"],{type:"text/csv"}));
  a.download=(CURRENT||"netflow")+".csv";a.click();
 };
 cd.append(dl);
 cd.append(table(["Start","Dur","Proto","Source","Destination","Flags","Pkts","Bytes"],N.slice(0,1000),f=>h("tr",null,
   h("td",{class:"mono"},nfTime(f.first)),
   h("td",null,(f.duration||0).toFixed(2)),
   h("td",null,f.proto),
   h("td",{class:"mono"},f.src+(f.sport?(":"+f.sport):"")),
   h("td",{class:"mono"},f.dst+(f.dport?(":"+f.dport):"")),
   h("td",{class:"mono"},f.flags||"-"),
   h("td",null,f.packets),
   h("td",null,bytes(f.bytes)))));
 if(N.length>1000)cd.append(h("div",{style:"color:var(--muted);font-size:12px;margin-top:6px"},"showing first 1000 of "+N.length+" — Download CSV or the CLI for all."));
 c.append(cd);
}
function vFlows(c){
 const F=DATA.conversations||[];if(!F.length){c.append(empty("No conversations."));return;}
 const cd=card("Conversations ("+F.length+")");
 cd.append(table(["Proto","Service","A","B","Pkts","Bytes","Dur(s)","RST","Retr"],F,f=>h("tr",null,
   h("td",null,f.proto),h("td",null,f.service||"-"),h("td",{class:"mono"},f.a),h("td",{class:"mono"},f.b),
   h("td",null,f.packets),h("td",null,bytes(f.bytes)),h("td",null,(f.duration||0).toFixed(2)),
   h("td",null,f.rst||0),h("td",null,f.retrans||0))));
 c.append(cd);
}
function vTalkers(c){
 const T=DATA.talkers||[];if(!T.length){c.append(empty("No talkers."));return;}
 const cd=card("Top talkers");
 cd.append(table(["Host","Bytes","Packets"],T,t=>h("tr",null,
   h("td",{class:"mono"},t.host),h("td",null,bytes(t.bytes)),h("td",null,t.packets))));
 c.append(cd);
}
function vProtocols(c){
 const g=h("div",{class:"grid"});
 const p=card("Layer protocols");for(const k in (DATA.protocols||{}))p.append(kv(k,DATA.protocols[k]));g.append(p);
 const s=card("Services (by port)");const sv=DATA.services||{};
 if(!Object.keys(sv).length)s.append(empty("none"));for(const k in sv)s.append(kv(k,sv[k]));g.append(s);
 c.append(g);
}
async function uploadFile(file){
 if(!file)return;
 document.getElementById("content").innerHTML='<div class="empty">Uploading &amp; analyzing '+esc(file.name)+' ...</div>';
 try{
  const buf=await file.arrayBuffer();
  const r=await fetch("/api/upload",{method:"POST",headers:{"X-Filename":file.name},body:buf});
  const j=await r.json();
  if(j.error){document.getElementById("content").innerHTML='<div class="banner bad">Upload failed: '+esc(j.error)+'</div>';return;}
  REMOVED.delete(j.name);
  await loadFiles();
  selectFile(j.name);
 }catch(e){document.getElementById("content").innerHTML='<div class="banner bad">Upload error: '+esc(e.message)+'</div>';}
}
function closeCapture(){
 DATA=null;CURRENT=null;
 document.querySelectorAll(".file").forEach(e=>e.classList.remove("active"));
 document.getElementById("tabs").innerHTML="";
 document.getElementById("content").innerHTML='<div class="empty">Select a capture on the left, or Open / drop a pcap.</div>';
 document.getElementById("exportbtn").style.display="none";
 const dj=document.getElementById("dljson");dj.removeAttribute("href");dj.removeAttribute("download");
}
async function exportHashes(){
 if(!CURRENT)return;
 try{
  const r=await fetch("/api/export?file="+encodeURIComponent(CURRENT));
  const j=await r.json();
  if(j.error){alert("Export failed: "+j.error);return;}
  const written=j.written||[];
  if(!written.length){alert("No crackable hashes (NTLM/Kerberos) found in this capture.");return;}
  const cd=card("Exported hashes → "+j.dir);cd.style.borderColor="var(--accent)";
  const prio=written.filter(w=>w.kind==="priority"), allf=written.filter(w=>w.kind!=="priority");
  function row(w,good){
   const btn=h("button",{class:"crackbtn"},"Crack");
   if(!CRACK_CFG||!CRACK_CFG.hashcat){btn.setAttribute("disabled","");btn.title="hashcat not found (put it in ./hashcat)";}
   btn.onclick=()=>crackFile(w.file,w.mode);
   return h("div",{class:"kv"},h("span",{class:"k"},w.file+" ("+w.count+")"),
     h("span",{class:"v"},h("span",{class:"mono",style:good?"color:var(--ok)":""},"-m "+w.mode),btn));}
  function batchBtn(label,list){const b=h("button",{class:"crackbtn",style:"color:var(--accent);margin:6px 0 2px"},label);
   if(!CRACK_CFG||!CRACK_CFG.hashcat)b.setAttribute("disabled","");
   b.onclick=()=>crackBatch(list.map(w=>({file:w.file,mode:w.mode})));return b;}
  if(prio.length){
   const hdr=h("div",{style:"margin:4px 0 2px;font-weight:600;color:var(--ok)"},"Priority — user/service accounts, crack these first:");
   cd.append(hdr);
   prio.forEach(w=>cd.append(row(w,true)));
   if(prio.length>1)cd.append(batchBtn("⚡ Crack all priority ("+prio.length+")",prio));
  }
  cd.append(h("div",{style:"margin:12px 0 2px;font-weight:600;color:var(--muted)"},"All hashes by type:"));
  allf.forEach(w=>cd.append(row(w,false)));
  if(allf.length>1)cd.append(batchBtn("Crack all ("+allf.length+")",allf));
  const cls=j.classification||{};
  if(Object.keys(cls).length){
   cd.append(h("div",{style:"margin:10px 0 2px;font-weight:600"},"Account classification:"));
   ["user","service","machine","krbtgt","system","unknown"].forEach(k=>{const a=cls[k]||[];if(!a.length)return;
    const good=k==="user"||k==="service";
    cd.append(h("div",{class:"kv"},
      h("span",{class:"k"},h("span",{class:"pill "+(good?"ok":"warn")},k),"  "+a.length+(good?"  worth cracking":"  skip")),
      h("span",{class:"v mono"},a.slice(0,6).join(", ")+(a.length>6?" …":""))));
   });
  }
  const c=document.getElementById("content");c.insertBefore(cd,c.firstChild);
 }catch(e){alert("Export error: "+e.message);}
}
document.getElementById("exportbtn").onclick=exportHashes;
function removeFromAnalysis(name){
 REMOVED.add(name);
 if(name===CURRENT)closeCapture();
 loadFiles();
}
async function deleteCapture(name){
 if(!confirm("Delete \""+name+"\" from disk?\nThis permanently removes the capture file and cannot be undone."))return;
 try{
  const r=await fetch("/api/delete",{method:"POST",headers:{"X-Filename":name}});
  const j=await r.json();
  if(j.error){alert("Delete failed: "+j.error);return;}
  if(name===CURRENT)closeCapture();
  await loadFiles();
 }catch(e){alert("Delete error: "+e.message);}
}
function fmtSpeed(s){if(!s)return "0 H/s";const u=["H/s","kH/s","MH/s","GH/s","TH/s"];let i=0;while(s>=1000&&i<4){s/=1000;i++;}return s.toFixed(1)+" "+u[i];}
async function loadCrackConfig(){try{CRACK_CFG=await (await fetch("/api/crack/config")).json();}catch(e){CRACK_CFG={hashcat:false,wordlists:[]};}}
const SPEED_EST={"0":5e10,"1000":5e10,"5500":2e10,"5600":3e9,"7500":1e9,"13100":1.2e9,"18200":1e9,"19600":2e6,"19700":1.6e6,"19800":2e6,"19900":1.6e6};
function charsetSize(mask){const map={l:26,u:26,d:10,s:33,a:95,b:256,h:16,H:16};let n=1,i=0;mask=mask||"";while(i<mask.length){if(mask[i]==="?"&&i+1<mask.length){n*=(map[mask[i+1]]||1);i+=2;}else{i++;}}return n;}
function fmtBig(n){if(!isFinite(n))return "∞";if(n>=1e15)return (n/1e15).toFixed(1)+"P";if(n>=1e12)return (n/1e12).toFixed(1)+"T";if(n>=1e9)return (n/1e9).toFixed(2)+"B";if(n>=1e6)return (n/1e6).toFixed(2)+"M";if(n>=1e3)return (n/1e3).toFixed(1)+"K";return ""+Math.round(n);}
function fmtDur(s){if(!isFinite(s))return "∞";if(s<1)return "<1s";const u=[["y",31536000],["d",86400],["h",3600],["m",60],["s",1]];let out=[];for(const x of u){if(s>=x[1]){const cc=Math.floor(s/x[1]);s-=cc*x[1];out.push(cc+x[0]);if(out.length>=2)break;}}return out.join(" ")||"<1s";}
function crackFile(file,mode){if(!CRACK_CFG||!CRACK_CFG.hashcat){alert("hashcat not found. Put it at ./hashcat/hashcat.exe or start serve with --hashcat");return;}openCrackModal([{file:file,mode:mode}]);}
function crackBatch(targets){if(!CRACK_CFG||!CRACK_CFG.hashcat){alert("hashcat not found.");return;}if(targets.length)openCrackModal(targets);}
function closeModal(){const m=document.getElementById("modal");m.classList.remove("show");m.innerHTML="";}
function openCrackModal(targets){
 const cfg=CRACK_CFG||{};
 const m=document.getElementById("modal");m.innerHTML="";
 const d=h("div",{class:"dialog"});
 d.append(h("h3",null,targets.length>1?("Crack "+targets.length+" files"):"Crack hashes"));
 d.append(h("div",{class:"sub2"},targets.length>1?targets.map(t=>t.file).join(", "):(targets[0].file+"   ·   hashcat -m "+targets[0].mode)));
 let attack="0";
 d.append(h("label",null,"Attack mode"));
 const seg=h("div",{class:"seg"});
 const bDict=h("button",{class:"on"},"Dictionary"),bMask=h("button",null,"Brute-force (mask)");
 seg.append(bDict,bMask);d.append(seg);
 const dictBlock=h("div",null);
 dictBlock.append(h("label",null,"Wordlist"));
 const wlSel=h("select",null);
 (cfg.wordlists||[]).forEach(w=>{const o=h("option",{value:w.name},w.name+"  ("+fmtBig(w.lines||0)+" words)");if(w.name===cfg.default_wordlist)o.setAttribute("selected","");wlSel.append(o);});
 if(!(cfg.wordlists||[]).length)wlSel.append(h("option",{value:""},"(no wordlists in ./dictionary)"));
 dictBlock.append(wlSel);
 dictBlock.append(h("label",null,"Rules (optional)"));
 const ruleSel=h("select",null);ruleSel.append(h("option",{value:""},"(none)"));
 (cfg.rules||[]).forEach(r=>ruleSel.append(h("option",{value:r.name},r.name+"  ("+fmtBig(r.lines||0)+" rules)")));
 dictBlock.append(ruleSel);d.append(dictBlock);
 const maskBlock=h("div",{style:"display:none"});
 maskBlock.append(h("label",null,"Mask"));
 const maskIn=h("input",{type:"text",value:"?a?a?a?a?a?a"});maskBlock.append(maskIn);
 const presets=h("div",{style:"margin-top:4px"});
 [["8 lower","?l?l?l?l?l?l?l?l"],["6 any","?a?a?a?a?a?a"],["8 any","?a?a?a?a?a?a?a?a"],["Aa+5+2dig","?u?l?l?l?l?l?d?d"]].forEach(p=>{const cc=h("span",{class:"chip"},p[0]);cc.onclick=()=>{maskIn.value=p[1];upd();};presets.append(cc);});
 maskBlock.append(presets);
 maskBlock.append(h("div",{style:"color:var(--muted);font-size:11px;margin-top:6px"},"?l lower · ?u upper · ?d digit · ?s symbol · ?a all · literals allowed"));
 d.append(maskBlock);
 const optCk=h("input",{type:"checkbox"});
 const optWrap=h("label",{class:"cklabel"});optWrap.append(optCk,document.createTextNode(" Optimized kernels (-O) — faster, caps length ~31"));d.append(optWrap);
 const readout=h("div",{style:"margin-top:14px;font-size:12px;padding:8px 10px;border:1px solid var(--border);border-radius:6px"});d.append(readout);
 function upd(){
  let ks;
  if(attack==="0"){const wl=(cfg.wordlists||[]).find(w=>w.name===wlSel.value);const rl=(cfg.rules||[]).find(r=>r.name===ruleSel.value);ks=(wl?wl.lines:0)*((rl&&rl.lines)?rl.lines:1);}
  else{ks=charsetSize((maskIn.value||"").trim());}
  let eta=0;targets.forEach(t=>{eta+=ks/(SPEED_EST[t.mode]||1e6);});
  readout.innerHTML="";
  readout.append(h("div",null,"Keyspace: ~"+fmtBig(ks)+" candidates"+(targets.length>1?(" × "+targets.length+" files"):"")));
  readout.append(h("div",{style:"color:var(--muted)"},"Rough ETA: "+fmtDur(eta)+" (estimated on this GPU; live ETA shown once running)"));
  readout.style.borderColor=eta>2592000?"var(--bad)":eta>86400?"var(--warn)":"var(--border)";
  if(eta>86400)readout.append(h("div",{style:"margin-top:4px;color:"+(eta>2592000?"var(--bad)":"var(--warn)")},"⚠ This may take a very long time — try a rule + wordlist or a shorter mask."));
 }
 bDict.onclick=()=>{attack="0";bDict.classList.add("on");bMask.classList.remove("on");dictBlock.style.display="";maskBlock.style.display="none";upd();};
 bMask.onclick=()=>{attack="3";bMask.classList.add("on");bDict.classList.remove("on");dictBlock.style.display="none";maskBlock.style.display="";upd();};
 wlSel.onchange=upd;ruleSel.onchange=upd;maskIn.oninput=upd;
 const act=h("div",{class:"actions"});
 const cancel=h("button",{class:"btn"},"Cancel");cancel.onclick=closeModal;
 const start=h("button",{class:"btn primary"},targets.length>1?("Start "+targets.length+" jobs"):"Start cracking");
 start.onclick=()=>{const opts={attack:attack,optimized:optCk.checked};if(attack==="0"){opts.wordlist=wlSel.value;opts.rules=ruleSel.value;}else{opts.mask=(maskIn.value||"").trim();if(!opts.mask){alert("Enter a mask");return;}}startCrack(targets,opts);};
 act.append(cancel,start);d.append(act);
 m.append(d);m.classList.add("show");m.onclick=e=>{if(e.target===m)closeModal();};
 upd();
}
async function startCrack(targets,opts){
 try{
  for(const t of targets){
   let qs="file="+encodeURIComponent(t.file)+"&mode="+encodeURIComponent(t.mode)+"&attack="+opts.attack+(opts.optimized?"&optimized=1":"");
   if(opts.attack==="0"){qs+="&wordlist="+encodeURIComponent(opts.wordlist||"");if(opts.rules)qs+="&rules="+encodeURIComponent(opts.rules);}
   else qs+="&mask="+encodeURIComponent(opts.mask);
   const r=await fetch("/api/crack?"+qs,{method:"POST"});const j=await r.json();
   if(j.error)alert("Crack failed for "+t.file+": "+j.error);
  }
  closeModal();startJobPolling();await refreshJobs();activeTab="jobs";renderTabs();render();
 }catch(e){alert("Crack error: "+e.message);}
}
async function refreshJobs(){
 try{JOBS=((await (await fetch("/api/jobs")).json()).jobs)||[];}catch(e){return;}
 if(DATA){renderTabs();if(activeTab==="jobs")render();}
}
function startJobPolling(){if(!jobPoller)jobPoller=setInterval(refreshJobs,2000);}
async function stopJob(id){try{await fetch("/api/stop_job?id="+encodeURIComponent(id),{method:"POST"});}catch(e){}refreshJobs();}
function statusPill(s){const m={running:"info",queued:"info",init:"info",autotune:"info",cracked:"ok",partial:"warn",exhausted:"warn",stopped:"warn",error:"bad"};return h("span",{class:"pill "+(m[s]||"info")},s);}
function vJobs(c){
 if(!CRACK_CFG||!CRACK_CFG.hashcat){c.append(h("div",{class:"banner bad"},"hashcat not found — place it at ./hashcat/hashcat.exe (or start with --hashcat). Cracking disabled."));}
 else c.append(h("div",{style:"color:var(--muted);margin-bottom:10px;font-size:12px"},"hashcat ready · wordlist: "+(CRACK_CFG.default_wordlist||"none")+" · launch jobs from the Kerberos/NTLM tabs via Export hashes → Crack."));
 if(!JOBS.length){c.append(empty("No crack jobs yet."));return;}
 JOBS.forEach(j=>{
  const job=h("div",{class:"job"});
  const head=h("h4",null,statusPill(j.status)," ",h("span",{class:"mono"},j.file),
    h("span",{style:"color:var(--muted);font-weight:400"},"-m "+j.mode+" · "+(j.attack_desc||j.wordlist)));
  if(j.running){const sb=h("button",{class:"mini",style:"margin-left:auto;color:var(--bad);border-color:var(--bad)"},"Stop");sb.onclick=()=>stopJob(j.id);head.append(sb);}
  job.append(head);
  const bar=h("div",{class:"bar"});const fill=h("i",{class:(j.status==="cracked"||j.status==="partial")?"done":""});fill.style.width=(j.progress||0)+"%";bar.append(fill);job.append(bar);
  let line=(j.progress||0).toFixed(1)+"%  ·  "+fmtSpeed(j.speed)+"  ·  recovered "+(j.recovered[0]||0)+"/"+(j.recovered[1]||0)+"  ·  "+j.elapsed+"s";
  if(j.running&&j.eta_seconds)line+="  ·  ETA "+fmtDur(j.eta_seconds);
  if(j.error)line+="  ·  "+j.error;
  job.append(h("div",{style:"font-size:12px;color:var(--muted)"},line));
  if(j.cracked&&j.cracked.length){
   j.cracked.forEach(cr=>job.append(h("div",{class:"cracked"},h("b",null,cr.account||"?"),"  →  ",h("b",{style:"color:var(--ok)"},cr.password))));
  } else if(!j.running){
   job.append(h("div",{style:"margin-top:6px;color:var(--muted);font-size:12px"},"No password recovered ("+j.status+")."));
  }
  const exp=EXPANDED.has(j.id);
  const tog=h("div",{style:"margin-top:8px;font-size:12px;color:var(--accent);cursor:pointer"},(exp?"▾ ":"▸ ")+"details");
  tog.onclick=()=>{if(EXPANDED.has(j.id))EXPANDED.delete(j.id);else EXPANDED.add(j.id);render();};
  job.append(tog);
  if(exp){
   const g=h("div",{class:"grid",style:"margin-top:8px"});
   const dt=(k,v)=>g.append(h("div",{class:"kv"},h("span",{class:"k"},k),h("span",{class:"v mono"},v)));
   dt("Hash type",j.mode_name+" (-m "+j.mode+")");
   dt("Hashes in file",String(j.hash_count));
   dt("Recovered",(j.recovered[0]||0)+" / "+(j.recovered[1]||0));
   dt("Attack",j.attack_desc);
   dt("Attempts",fmtBig(j.attempts||0)+" / "+fmtBig(j.keyspace||0));
   dt("Progress",(j.progress||0).toFixed(2)+"%");
   dt("Speed",fmtSpeed(j.speed));
   dt("ETA",j.running?(j.eta_seconds?fmtDur(j.eta_seconds):"—"):"finished");
   dt("Elapsed",j.elapsed+"s");
   dt("Status",j.status);
   job.append(g);
  }
  c.append(job);
 });
}
loadCrackConfig();startJobPolling();
window.addEventListener("keydown",e=>{if(e.key==="Escape")closeModal();});
document.getElementById("openbtn").onclick=()=>document.getElementById("fileinput").click();
document.getElementById("fileinput").onchange=e=>{if(e.target.files[0])uploadFile(e.target.files[0]);e.target.value="";};
const drop=document.getElementById("drop");let dragc=0;
window.addEventListener("dragenter",e=>{e.preventDefault();dragc++;drop.classList.add("show");});
window.addEventListener("dragover",e=>e.preventDefault());
window.addEventListener("dragleave",e=>{e.preventDefault();if(--dragc<=0)drop.classList.remove("show");});
window.addEventListener("drop",e=>{e.preventDefault();dragc=0;drop.classList.remove("show");
 const f=e.dataTransfer.files&&e.dataTransfer.files[0];if(f)uploadFile(f);});
loadFiles();
</script>
</body></html>
"""
