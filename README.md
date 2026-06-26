# pcapscope

A **zero-dependency** PCAP/PCAPNG analysis tool for **authentication troubleshooting**.
Pure Python standard library — no scapy, no tshark/Wireshark, no pip installs.
Works anywhere Python 3.9+ runs (built/tested on Python 3.14, Windows).

It does two jobs:

1. **Check & validate** capture files — format, integrity, truncation, corruption,
   plus capinfos-style metadata (packets, bytes, duration, rate, link types).
2. **Extract the key auth material & packets** you chase when troubleshooting
   logins: Kerberos message types and **encryption types**, NTLM / **NetNTLMv1+v2**
   hashes, MSSQL/TDS logins, LDAP binds, and HTTP authentication — with the
   weaknesses and failures flagged.

---

## Quick start

```bash
# Full report (validation + flows + all auth findings)
python pcapscope.py capture.pcapng

# Just validate / integrity-check
python pcapscope.py validate capture.pcap

# Focused views
python pcapscope.py kerberos capture.pcapng     # message types, etypes, errors + crackable hashes
python pcapscope.py ntlm     capture.pcap        # NetNTLM hashes (hashcat format)
python pcapscope.py mssql    capture.pcap        # TDS logins + encryption negotiation
python pcapscope.py ldap     capture.pcap        # binds (cleartext / SASL / result codes)
python pcapscope.py tls      capture.pcap        # TLS/LDAPS: version, SNI, server certificate
python pcapscope.py radius   capture.pcap        # RADIUS auth + MS-CHAPv2 hashes
python pcapscope.py cleartext capture.pcap       # FTP/TELNET/SMTP/POP3/IMAP/SNMP creds
python pcapscope.py http     capture.pcap        # Authorization / WWW-Authenticate
python pcapscope.py hosts    capture.pcap        # hostnames: DNS/SNI/HTTP/DHCP/cert + IP map
python pcapscope.py netflow  capture.pcap --csv flows.csv   # unidirectional flow records

# Pipe-friendly extraction
python pcapscope.py extract --kind creds  capture.pcap   # all recovered credentials
python pcapscope.py extract --kind ntlm   capture.pcap   # hashcat lines only
python pcapscope.py extract --kind json   capture.pcap   # full JSON to stdout

# Export hashcat files (named <pcap>_<hashtype>.txt, one per -m mode)
python pcapscope.py export capture.pcap                   # + a _priority.txt of crackable accounts
python pcapscope.py export capture.pcap --out-dir hashes  # into a folder

# Machine-readable
python pcapscope.py report capture.pcap --json out.json

# Local web dashboard (opens a browser at http://127.0.0.1:8088)
python pcapscope.py serve capture.pcapng
python pcapscope.py serve --dir ./captures        # browse a folder of captures

# Windows: a launcher that finds Python, starts the dashboard and prints the token URL
.\start-dashboard.ps1                             # defaults: port 8090, this folder
.\start-dashboard.ps1 -Port 9000 -Dir C:\captures
# if scripts are blocked:  powershell -ExecutionPolicy Bypass -File .\start-dashboard.ps1
```

The dashboard has tabbed views (Overview / Findings / Kerberos / NTLM / MSSQL / LDAP /
TLS-LDAPS / HTTP / Flows / Talkers / **Cracking**), copy-to-clipboard buttons for
recovered hashes, an **Open pcap…** button (or drag-and-drop), per-capture **×** (close)
and **🗑** (delete), and an **Export hashes** button.

**Security:** since the dashboard exposes recovered credentials, it's **token-authenticated**.
A random token is generated per run; the auto-opened URL includes it
(`http://127.0.0.1:8088/?token=…`) and every API call requires it. The server also enforces
a **Host allowlist** (blocks DNS-rebinding) and **header-based auth on POST** (blocks CSRF),
sends `nosniff`, and defaults to loopback-only (binding elsewhere prints a warning — prefer
an SSH tunnel). Use `--token <value>` for a fixed token (scripting/tests).

### Cracking from the dashboard (background jobs)

If a local **hashcat** and a wordlist are present, the dashboard can launch crack
jobs in the background and show live progress + recovered passwords:

```bash
python pcapscope.py serve --dir . --hashcat ./hashcat/hashcat.exe --wordlist-dir ./dictionary
# (both are auto-detected if placed at ./hashcat/hashcat.exe and ./dictionary/)
```

Open a capture → **Export hashes** → click **Crack** on a file. A **cracking-options
modal** opens:

- **Dictionary** (wordlist + optional rules) or **Brute-force (mask)** with presets.
- A live **keyspace + rough-ETA** estimate (warns before you start an 8×`?a` run that
  won't finish), computed from wordlist×rules line counts or the mask charset.
- **Optimized kernels (-O)** toggle.
- **⚡ Crack all priority** fans the chosen settings across every `_priority.txt` at once.

The **Cracking** tab shows each job: status, progress bar, speed (H/s), recovered
count, live ETA, a **Stop** button, the cracked `account → password` results, and a
**▸ details** expander (hash type, hash count, attempts/keyspace, ETA, elapsed). Jobs
run server-side via `hashcat --status-json`; results are parsed from its outfile and
mapped back to the originating account. Bind stays on localhost.

Running `python pcapscope.py <file>` with no subcommand prints the full report.

---

## Capturing live traffic on Windows (no Wireshark)

Use the built-in **pktmon** (requires an elevated/Administrator shell). The helper
[`tools/lab_capture.ps1`](tools/lab_capture.ps1) captures full packets filtered to a
target, generates SMB auth (by IP → NTLM, by FQDN → Kerberos), optionally points the
target domain's DNS at the DC via a scoped, auto-removed NRPT rule (needed when your
resolver doesn't know the lab domain), and converts to `.pcapng`:

```powershell
# in an elevated terminal
powershell -NoProfile -File tools\lab_capture.ps1 -Dc 192.168.119.136 `
    -Fqdn demodc1.lab.local -Domain LAB -Realm lab.local -User administrator
# prompts for the password (masked), produces lab_capture.pcapng
```

Manual pktmon, if you prefer:

```powershell
pktmon filter remove
pktmon filter add MyHost -i <target-ip>
pktmon start --capture --pkt-size 0 --file-name cap.etl   # --pkt-size 0 = FULL packets
# ... reproduce the issue ...
pktmon stop
pktmon etl2pcap cap.etl --out cap.pcapng
```

> **pktmon duplicates packets.** It records each packet at *every* monitored
> component (NIC + stack layers), so a capture often contains each frame 2-4×.
> This inflates packet/byte counts and the retransmission heuristic. pcapscope
> auto-detects this and tells you; pass **`--dedup`** to drop exact-duplicate
> frames for accurate counts:
>
> ```bash
> python pcapscope.py lab_capture.pcapng --dedup
> ```

---

## What it detects

### Kerberos (TCP/UDP 88, 464)
- Message types: AS-REQ, AS-REP, TGS-REQ, TGS-REP, AP-REQ/REP, KRB-ERROR (counts + detail).
- **Encryption types** requested (REQ etype list) *and* actually used (ticket / enc-part),
  with **weak crypto flagged**: RC4 (`rc4-hmac`, etype 23) and DES.
  - RC4 service tickets → **Kerberoasting** exposure.
  - AS-REP without pre-auth → **AS-REP roasting** exposure (pre-auth state shown per AS-REQ).
- KDC error codes decoded for troubleshooting: `PREAUTH_FAILED` (wrong password),
  `CLIENT_REVOKED` (locked/disabled), `KEY_EXPIRED`, `C_PRINCIPAL_UNKNOWN` (bad user),
  `S_PRINCIPAL_UNKNOWN` (bad SPN), `ETYPE_NOSUPP`, `SKEW` (clock), etc.
- **Crackable hashes** extracted (username + etype + impacket-format string, hashcat mode noted):
  Kerberoast (TGS-REP, `-m 13100/19600/19700`), AS-REP roast (`-m 18200`), and
  AS-REQ pre-auth timestamps (`-m 7500/19800/19900`).
- **`export`** writes hashcat-ready files plus a **`_priority.txt`** that keeps only
  *worth-cracking* accounts — it classifies each account as user / service (crack
  these) vs machine (`$`), `krbtgt`, or system (`HealthMailbox*`) which have random,
  uncrackable passwords. So a 21-hash Kerberoast dump becomes a 3-hash target list.

### RADIUS (UDP 1812/1813, 1645/1646)
- Decodes Access-Request/Accept/Reject/Challenge; correlates request → result.
- Auth method: PAP / CHAP / MS-CHAP / MS-CHAPv2 / EAP (with EAP sub-type), plus
  User-Name, NAS, and Calling-Station-Id (often the client MAC).
- **MS-CHAP / MS-CHAPv2 → NetNTLMv1 hash** reconstructed (ChallengeHash via the
  peer+authenticator challenges) for cracking with **hashcat -m 5500**; flows into
  `export` (`<pcap>_mschapv2.txt`) and the dashboard's Crack workflow.
- **Shared-secret recovery & PAP decryption.** The shared secret is verified offline
  against a captured **Response-Authenticator** (request/response pair) or
  **Message-Authenticator**, so it can be dictionary-attacked; once known, PAP
  `User-Password` decrypts to **cleartext**:

  ```bash
  pcapscope radius cap.pcap --recover-secret              # dictionary-attack the secret
  pcapscope radius cap.pcap --recover-secret --wordlist secrets.txt
  pcapscope radius cap.pcap --secret testing123          # known secret -> decrypt PAP
  ```

  In the dashboard's **RADIUS** tab: enter a known secret (**Apply**) or **Recover
  from wordlist** (background job) — confirmed secrets decrypt PAP passwords inline.
  Flags PAP and Access-Reject failures.

### EAP / PEAP — via RADIUS **and** 802.1X EAPOL
- Decoded from RADIUS `EAP-Message` **and** wired/wireless **EAPOL** (ethertype
  0x888e) — each finding shows its carrier (`RADIUS` or `802.1X`).
- Reassembles the EAP exchange and surfaces the **outer identity** (flags PEAP/TTLS
  leaking a real identity instead of `anonymous`), the negotiated **method**
  (PEAP / EAP-TLS / EAP-TTLS / MD5 / MSCHAPv2 / GTC / FAST …), NAK-requested method,
  and Success/Failure.
- Crackable hashes for the non-tunnelled methods: **EAP-MD5 → hashcat -m 4800** and
  **EAP-MSCHAPv2 → -m 5500** (flow into `export` + the Crack workflow). Flags EAP-MD5 as weak.
- **EAP-TLS / PEAP / TTLS server certificate**: reassembles the fragmented (cleartext)
  TLS handshake inside EAP and extracts the **RADIUS server cert** (subject CN, SANs,
  issuer, validity) + SNI — the data you need for the #1 802.1X failure (untrusted/
  wrong/expired NPS/RADIUS certificate).

### WPA / Wi-Fi (802.11 / radiotap captures)
- Decodes **802.11** (radiotap, PPI, AVS, raw link types), pulls **SSIDs** from beacons,
  and reconstructs the WPA/WPA2 **EAPOL 4-way handshake**.
- Builds **hashcat -m 22000** hashes: **PMKID** (`WPA*01*…`, from message 1 — no full
  handshake needed) and **EAPOL** (`WPA*02*…`, M1+M2 with the MIC zeroed). Flows into
  `export` (`<pcap>_wpa.txt`) and the dashboard Crack workflow.

### Database / VoIP / remote-access auth (crackable challenge-response)
- **PostgreSQL** MD5 (5432) → hashcat **-m 11100**, **MySQL** native (3306) → **-m 11200**,
  **CRAM-MD5** (SMTP/POP3/IMAP) → **-m 10200**, **SIP** digest (5060) → **-m 11400**
  (all flow into `export` + the Crack workflow).
- **VNC/RFB** (5900) challenge/response → john `$vnc$` format. **HTTP Digest** components
  surfaced (crackable offline).
- **SNMPv3 USM** (161): the authenticated message → hashcat **-m 25100** (HMAC-MD5) /
  **-m 25200** (SHA1) / **267xx** (SHA-2), with the auth params zeroed in the packet.
- **RDP** (3389): recovers the **`mstshash` username** (sent in cleartext in the connection
  request, even with NLA) and the negotiated **security** (Standard RDP / TLS / CredSSP-NLA);
  the RDP server certificate shows in the TLS tab. Flags Standard-Security (no-TLS) RDP.

### Cleartext / legacy app auth (FTP, TELNET, SMTP, POP3, IMAP, SNMP)
- Recovers credentials sent in the clear: **FTP** `USER`/`PASS`, **TELNET** login,
  **SMTP/POP3/IMAP** `AUTH PLAIN`/`LOGIN` (base64) and `USER`/`PASS`/`LOGIN`, and
  **SNMP v1/v2c community strings** (flags defaults like `public`/`private`).
- Each is also an assurance flag ("this protocol is unencrypted"). CRAM-MD5 / APOP
  are detected and marked as crackable (extraction TBD). Feeds `extract --kind creds`.

### TLS / LDAPS (636, 3269, 443, and any TLS stream)
- Negotiated TLS version, client **SNI**, cipher suite.
- **Server certificate** from the (cleartext, TLS 1.2) handshake: subject CN, org,
  **SANs**, issuer CN, validity window — the data you need when an LDAPS bind fails
  on a name/expiry/trust problem. Legacy SSL3/TLS1.0/1.1 is flagged.

### NTLM / NetNTLM (any carrier: SMB, HTTP, LDAP, MSSQL/TDS, RPC)
- Finds `NTLMSSP` Negotiate/Challenge/Authenticate messages by signature, regardless of port.
- Correlates the server **Challenge** with the client **Authenticate** to reconstruct
  **NetNTLMv1 (hashcat 5500)** and **NetNTLMv2 (hashcat 5600)** hashes — ready to crack
  or to prove weak/legacy auth.
- Flags **NTLMv1** specifically (weak, should be disabled).

### MSSQL / TDS (TCP 1433)
- Pre-login **encryption negotiation** (`ENCRYPT_OFF`/`ON`/`REQ`) — clear-text logins surfaced.
- **Login7**: username, the trivially-reversible obfuscated **SQL password**, app name,
  host, server, target database, client MAC.
- Detects **integrated (Windows) auth** vs SQL auth (SSPI/NTLM blob handed to NTLM analyzer).

### LDAP (TCP 389, 3268)
- **Simple binds** — cleartext DN + password on plain 389 surfaced as a finding.
- **SASL binds** — mechanism (GSSAPI / GSS-SPNEGO / DIGEST-MD5).
- Bind **result codes**: `invalidCredentials` (49), `strongerAuthRequired` (8 = signing demanded), …

### HTTP authentication (TCP 80, 8080, 8000, 3128, 5985, or any HTTP stream)
- `Authorization` / `WWW-Authenticate` / `Proxy-Authenticate`.
- **Basic** decoded to `user:pass`; **Bearer** token; **NTLM** / **Negotiate** (SPNEGO) detected.

### Hostnames / name intelligence
- Aggregates every host identity in the capture into one view + a **per-IP inventory**:
  **DNS** queries and A/AAAA/PTR/CNAME/SRV answers (new DNS parser, with name
  compression), **mDNS**/**LLMNR**, **DHCP** client hostnames/FQDNs (+ MAC), TLS **SNI**,
  TLS **certificate** CN/SANs, **HTTP Host** headers, Kerberos **SPN** hosts, and MSSQL
  server names. Great for "what is this host?" and asset discovery.

### General troubleshooting
- Capture validation: PCAP (LE/BE, µs/ns) and PCAPNG (multi-section, SLL/SLL2/raw/loopback links),
  truncation & corruption detection, snaplen clipping.
- Protocol & service breakdown, top talkers, conversation/flow table.
- **NetFlow view** — aggregates packets into **unidirectional 5-tuple flow records**
  (NetFlow v5 fields: src/dst IP+port, proto, packets, bytes, start/end/duration,
  cumulative TCP flags, ToS). `netflow --csv flows.csv` writes nfdump-style CSV; the
  dashboard's NetFlow tab has a one-click CSV download.
- TCP health: SYN/SYN-ACK/RST/FIN counts, failed handshakes (refused/filtered),
  resets, and a retransmission/out-of-order heuristic.
- A consolidated **Findings** list ranking the things worth acting on.

---

## Project layout

```
pcapscope.py            entry point  (python pcapscope.py ...)
pcapscope/
  reader.py             PCAP + PCAPNG parsing & validation
  layers.py             Ethernet/IP/TCP/UDP decode + TCP stream reassembly
  asn1.py               minimal DER decoder (Kerberos / LDAP)
  kerberos.py           Kerberos message + encryption-type analysis
  ntlm.py               NTLMSSP decode + NetNTLM hash reconstruction
  tds.py                MSSQL/TDS pre-login + Login7
  ldap.py               LDAP bind analysis
  httpauth.py           HTTP auth header extraction
  analyze.py            the engine (one pass + per-connection auth analysis)
  report.py             text + JSON renderers
  cli.py                command-line interface
  serve.py             local web dashboard (stdlib http.server)
tools/make_sample.py    synthetic capture generator (demo + test fixture)
tests/test_basic.py     end-to-end regression tests
```

## Test it now

```bash
python tools/make_sample.py sample.pcap     # build a demo capture
python pcapscope.py sample.pcap             # analyze it
python -m unittest discover -s tests        # run the test suite
```

---

## Notes & limitations

- **Intended use:** troubleshooting and security review of **captures you are authorized to
  analyze**. Recovering NetNTLM hashes / clear-text credentials from a pcap is standard practice
  for diagnosing weak or failing authentication and for confirming what is exposed on the wire.
- TLS-wrapped traffic (LDAPS 636, HTTPS 443, SMB/TDS with encryption ON) is opaque without keys —
  the tool reports *that* encryption is in use but cannot read inside it.
- TCP reassembly is lightweight and bounded (auth handshakes live at connection start). Heavily
  out-of-order or IP-fragmented captures may yield partial app-layer decode.
- Kerberos/NTLM cipher *contents* are not decrypted (no keys); the tool reports metadata
  (types, principals, challenges/responses, errors), which is what troubleshooting needs.
