"""End-to-end regression tests over a freshly generated synthetic capture.

Run with:  python -m unittest discover -s tests   (or)  python tests/test_basic.py
No third-party dependencies.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pcapscope.analyze import analyze
from pcapscope.reader import CaptureError
from tools import make_sample


class SyntheticCaptureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.path = os.path.join(cls.tmp, "sample.pcap")
        make_sample.build(cls.path)
        cls.r = analyze(cls.path)

    def test_valid(self):
        self.assertFalse(self.r.info.errors)
        self.assertEqual(self.r.info.fmt, "pcap")
        self.assertGreater(self.r.info.packet_count, 20)

    def test_kerberos(self):
        kinds = {f.msg.kind for f in self.r.kerberos}
        self.assertIn("AS-REQ", kinds)
        self.assertIn("KRB-ERROR", kinds)
        self.assertIn("AS-REP", kinds)
        # weak etype RC4 (23) requested + used
        all_req = [e for f in self.r.kerberos for e in f.msg.etypes]
        self.assertIn(23, all_req)
        self.assertIn(18, all_req)
        errs = [f.msg.error_code for f in self.r.kerberos if f.msg.error_code]
        self.assertIn(25, errs)  # PREAUTH_REQUIRED

    def test_ntlm_netntlmv2(self):
        auths = [f for f in self.r.ntlm if f.auth]
        self.assertEqual(len(auths), 1)
        a = auths[0]
        self.assertEqual(a.auth.ntlm_version, "NTLMv2")
        self.assertEqual(a.auth.user, "alice")
        self.assertEqual(a.auth.domain, "EXAMPLE")
        self.assertTrue(a.hashcat.startswith("alice::EXAMPLE:1122334455667788:"))
        self.assertIn("5600", a.mode)

    def test_mssql(self):
        self.assertEqual(len(self.r.tds), 1)
        info = self.r.tds[0].info
        self.assertEqual(info.encryption_raw, 0)  # ENCRYPT_OFF
        self.assertEqual(info.login.username, "sa")
        self.assertEqual(info.login.password, "P@ssw0rd!")
        self.assertEqual(info.login.database, "master")

    def test_ldap(self):
        reqs = [f.bind for f in self.r.ldap if f.bind.kind == "request"]
        self.assertTrue(any(b.method == "simple" and b.password == "Secret123!" for b in reqs))
        resps = [f.bind for f in self.r.ldap if f.bind.kind == "response"]
        self.assertTrue(any(b.result_code == 0 for b in resps))

    def test_http_basic(self):
        reqs = [f.auth for f in self.r.http_auth if f.auth.direction == "request"]
        self.assertTrue(any(a.username == "alice" and a.password == "Password1" for a in reqs))

    def test_tls_ldaps(self):
        self.assertTrue(self.r.tls, "expected a TLS/LDAPS session")
        info = self.r.tls[0].info
        self.assertEqual(info.sni, "demodc1.lab.local")
        self.assertEqual(info.server_version, "TLS 1.2")
        self.assertEqual(info.cert_subject, "demodc1.lab.local")
        self.assertEqual(info.cert_issuer, "LAB-CA")
        self.assertIn("lab.local", info.cert_sans)

    def test_kerberos_hashes(self):
        all_hashes = [h for f in self.r.kerberos for h in f.msg.extractable_hashes()]
        kinds = {h["type"] for h in all_hashes}
        self.assertIn("Kerberoast (TGS-REP)", kinds)
        self.assertIn("AS-REP roast", kinds)
        for h in all_hashes:
            self.assertTrue(h["hash"].startswith("$krb5"))

    def test_radius_mschapv2(self):
        self.assertTrue(self.r.radius, "expected a RADIUS auth")
        f = self.r.radius[0]
        self.assertEqual(f.username, "rad-user")
        self.assertEqual(f.method, "MS-CHAPv2")
        self.assertEqual(f.result, "Access-Accept")
        self.assertEqual(f.mode, "5500")
        # hashcat -m 5500 format: user::::<24-byte NT>:<8-byte challenge>
        parts = f.hashcat.split(":")
        self.assertEqual(parts[0], "rad-user")
        self.assertEqual(len(parts[4]), 48)   # NT response = 24 bytes hex
        self.assertEqual(len(parts[5]), 16)   # challenge hash = 8 bytes hex

    def test_radius_secret_recovery(self):
        from pcapscope.analyze import analyze, apply_radius_secret, recover_radius_secret
        r = analyze(self.path)                      # fresh result (don't mutate shared)
        self.assertTrue(any(f.userpw_enc for f in r.radius), "expected a PAP request")
        # recover the shared secret
        sec = recover_radius_secret(r, iter([b"nope", b"testing123", b"zzz"]))
        self.assertEqual(sec, "testing123")
        # apply the known secret -> confirmed + PAP decrypted
        self.assertTrue(apply_radius_secret(r, "testing123"))
        self.assertTrue(any(f.password == "S3cret!" for f in r.radius))
        # a wrong secret must not validate
        self.assertFalse(apply_radius_secret(r, "wrongsecret"))

    def test_eap(self):
        methods = {f.method for f in self.r.eap}
        self.assertIn("MD5-Challenge", methods)
        self.assertIn("PEAP", methods)
        md5 = next(f for f in self.r.eap if f.method == "MD5-Challenge")
        self.assertEqual(md5.identity, "eap-user")
        self.assertEqual(md5.mode, "4800")
        self.assertEqual(len(md5.hashcat.split(":")), 3)   # resp:challenge:id
        peap = next(f for f in self.r.eap if f.method == "PEAP")
        self.assertTrue(peap.tunnelled)
        self.assertEqual(peap.identity, "anonymous")
        # EAP-TLS server certificate extracted from the (cleartext) handshake
        self.assertEqual(peap.cert_subject, "radius.lab.local")
        self.assertEqual(peap.cert_issuer, "LAB-CA")
        # wired 802.1X (EAPOL) EAP also decoded
        eapol = [f for f in self.r.eap if f.carrier == "802.1X"]
        self.assertTrue(eapol)
        self.assertEqual(eapol[0].identity, "wired-user")
        self.assertEqual(eapol[0].mode, "4800")

    def test_cleartext(self):
        by = {f.protocol: f for f in self.r.cleartext}
        self.assertEqual(by["FTP"].username, "bob")
        self.assertEqual(by["FTP"].password, "s3cr3t")
        self.assertEqual(by["TELNET"].password, "telnetpass")
        self.assertEqual(by["SMTP"].username, "bob")
        self.assertEqual(by["SMTP"].password, "smtppass")
        self.assertEqual(by["POP3"].password, "popsecret")
        self.assertEqual(by["IMAP"].username, "imapuser")
        self.assertEqual(by["SNMP"].password, "public")
        self.assertEqual(by["SNMP"].note, "DEFAULT community")

    def test_appauth(self):
        by = {f.protocol: f for f in self.r.app_auth}
        self.assertEqual(by["PostgreSQL"].hashcat,
                         "$postgres$pguser*01020304*5f4dcc3b5aa765d61d8327deb882cf99")
        self.assertEqual(by["PostgreSQL"].mode, "11100")
        self.assertTrue(by["MySQL"].hashcat.startswith("$mysqlna$") and by["MySQL"].mode == "11200")
        self.assertTrue(by["CRAM-MD5"].hashcat.startswith("$cram_md5$") and by["CRAM-MD5"].mode == "10200")
        self.assertEqual(by["SIP"].mode, "11400")
        self.assertTrue(by["VNC"].hashcat.startswith("$vnc$") and by["VNC"].tool == "john")
        self.assertEqual(by["RDP"].account, "rdpuser")
        self.assertIn("NLA", by["RDP"].note)
        self.assertEqual(by["HTTP-Digest"].account, "httpuser")
        self.assertEqual(by["SNMPv3"].account, "snmpv3user")
        self.assertEqual(by["SNMPv3"].mode, "25100")
        self.assertTrue(by["SNMPv3"].hashcat.startswith("$SNMPv3$1$40000$")
                        and by["SNMPv3"].hashcat.endswith("$" + "aa" * 12))

    def test_wpa(self):
        from pcapscope.analyze import analyze
        wp = os.path.join(self.tmp, "wifi.pcap")
        make_sample.build_wifi(wp)
        r = analyze(wp)
        kinds = {f.kind for f in r.wpa}
        self.assertIn("PMKID", kinds)
        self.assertIn("EAPOL", kinds)
        for f in r.wpa:
            self.assertEqual(f.essid, "TestNet")
            self.assertEqual(f.bssid, "00:11:22:33:44:55")
            self.assertTrue(f.hashcat.startswith("WPA*") and f.mode == "22000")

    def test_hostnames(self):
        names_set = {h.name for h in self.r.hostnames}
        for expected in ("www.lab.local", "laptop-01", "printer.local",
                         "web.example.com", "demodc1.lab.local"):
            self.assertIn(expected, names_set)
        a = [h for h in self.r.hostnames if h.kind == "A" and h.name == "www.lab.local"]
        self.assertTrue(a and a[0].ip == "10.0.0.50")
        kinds = {h.kind for h in self.r.hostnames}
        self.assertTrue({"dns-query", "DHCP", "mDNS", "SNI", "SPN"} <= kinds)

    def test_export_hashcat(self):
        from pcapscope import report
        d = tempfile.mkdtemp()
        written = report.export_hashcat(self.r, self.path, d)
        fmts = {w["format"] for w in written}
        self.assertIn("netntlmv2", fmts)
        self.assertIn("krb5tgs", fmts)
        self.assertIn("krb5asrep", fmts)
        for w in written:
            self.assertTrue(w["file"].startswith("sample_") and w["file"].endswith(".txt"))
            with open(w["path"], encoding="utf-8") as fh:
                lines = [l for l in fh.read().splitlines() if l]
            self.assertEqual(len(lines), w["count"])
            self.assertTrue(all(l and " " not in l for l in lines))   # valid hash lines

    def test_dns(self):
        txns = self.r.dns
        self.assertGreater(len(txns), 0, "expected DNS transactions")

        # Answered A query
        answered = [t for t in txns if t.answered]
        self.assertTrue(any(t.qname == "www.lab.local" and t.qtype == "A" for t in answered),
                        "expected answered A record for www.lab.local")

        # NXDOMAIN responses present
        nxd = [t for t in txns if t.rcode == 3]
        self.assertGreaterEqual(len(nxd), 2, "expected at least 2 NXDOMAIN transactions")
        nxd_names = {t.qname for t in nxd}
        self.assertIn("nohost.lab.local", nxd_names)
        self.assertIn("badhost.corp.local", nxd_names)

        # Timeout (unanswered query)
        timeouts = [t for t in txns if t.rcode == -1]
        self.assertGreaterEqual(len(timeouts), 1)
        self.assertEqual(timeouts[0].rcode_name, "TIMEOUT")

        # Latency computed for answered transactions
        for t in answered:
            self.assertIsNotNone(t.latency_ms)
            self.assertGreaterEqual(t.latency_ms, 0.0)

        # CNAME response recorded
        cname_txn = [t for t in txns if t.qname == "webmail.lab.local"]
        self.assertTrue(cname_txn, "expected webmail.lab.local transaction")
        ans_types = {a[1] for a in cname_txn[0].answers}
        self.assertIn("CNAME", ans_types)

        # PTR lookup answered
        ptr_txn = [t for t in txns if "in-addr.arpa" in t.qname]
        self.assertTrue(ptr_txn, "expected PTR lookup transaction")

        # Per-server: 10.0.0.53 should have most queries
        by_svr = {}
        for t in txns:
            by_svr[t.server] = by_svr.get(t.server, 0) + 1
        self.assertIn("10.0.0.53", by_svr)

        # Anomalies include DNS findings
        joined = " ".join(self.r.anomalies)
        self.assertIn("NXDOMAIN", joined)
        self.assertIn("timeout", joined.lower())

    def test_findings(self):
        joined = " ".join(self.r.anomalies)
        self.assertIn("Weak Kerberos", joined)
        self.assertIn("cleartext", joined)
        self.assertIn("ENCRYPT_OFF", joined)

    def test_tcp_health(self):
        self.assertGreaterEqual(self.r.reset_conns, 1)
        self.assertGreaterEqual(self.r.failed_handshakes, 1)


class MalformedInputTest(unittest.TestCase):
    def test_empty(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            path = f.name
        with self.assertRaises(CaptureError):
            analyze(path)
        os.unlink(path)

    def test_garbage(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(b"not a pcap file at all, just text" * 4)
            path = f.name
        with self.assertRaises(CaptureError):
            analyze(path)
        os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
