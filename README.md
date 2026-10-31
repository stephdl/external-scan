# external-scan

A monthly scan of what a network exposes to the Internet. It runs from a VPS
outside the network, against a fixed list of public IP addresses.

For each address it:

1. finds every open TCP port and its service with nmap,
2. compares the open ports with the previous scan,
3. checks certificates and TLS settings with testssl.sh,
4. checks SSH settings with ssh-audit,
5. scans each named web site with nuclei, when `web_scan` is on,
6. writes a plain text report, and a PDF for the owner when `pdf_report` is on.

## Software used

`install.sh` installs everything.

| Software | Role | Source |
|---|---|---|
| [nmap](https://nmap.org) | open TCP and UDP ports and their services | distribution package |
| [vulners](https://github.com/vulnersCom/nmap-vulners) | known CVEs for each announced version | shipped with nmap |
| [testssl.sh](https://testssl.sh) | certificates, protocols, ciphers, known TLS attacks | git clone, pinned tag |
| [ssh-audit](https://github.com/jtesta/ssh-audit) | SSH algorithms and known SSH CVEs | git clone, pinned tag |
| OpenSSH client | asks which SSH login methods are accepted, without trying any | distribution package |
| [nuclei](https://github.com/projectdiscovery/nuclei) | known web flaws, critical and high templates | release binary, SHA-256 checked |
| [typst](https://typst.app) | renders the PDF | release binary, SHA-256 checked |
| python3, bash | run the scan and write the reports | distribution package |
| systemd | monthly run, unprivileged user with the raw socket right | distribution package |

Helpers: socat, openssl, dig and hexdump for testssl.sh, git and curl to fetch
the tools, ndiff to compare two nmap scans when the distribution ships it.
Pinned versions are at the top of `install.sh`. Each PDF prints the versions
that ran.

Each scan asks GitHub for the release tags. When a newer one exists,
`SUMMARY.txt`, the journal and the tools list of the PDF say so. Without
access to GitHub the check is skipped, with a line in `scan.log`.

## Before you scan

**Get written permission from the owner of every address.** List only those
addresses. Ranges, host names and IPv6 are refused, and the scan never
connects to an address outside the config.

**nuclei is a vulnerability scan, not a port scan.** It stays off until
`web_scan on`. Turn it on only when the permission covers it.

**Ask the owner to whitelist the VPS IP** in CrowdSec, the IDS (Suricata on
OPNsense...), fail2ban or similar. Otherwise the scan gets blocked halfway and
shows fewer open ports than there are.

## Install

Everything lives in `/var/lib/external-scan`: the git clone, the home of the
`external-scan` system user, the config, the tools and the results.

As root. The same commands install or update to the current release:

```
[ -d /var/lib/external-scan ] || git clone https://github.com/stephdl/external-scan.git /var/lib/external-scan
cd /var/lib/external-scan
git fetch --tags
git checkout -q 1.0.3
./install.sh
```

`install.sh` works on Debian, Ubuntu, Rocky and Fedora, and is safe to run
again. It installs the packages, creates the `external-scan` user, fetches the
pinned tools into `tools/`, creates `external-scan.conf` from the example if
missing, and copies the systemd units to `/etc/systemd/system`. It does not
enable the timer.

Your `external-scan.conf` and the results are not in git, an update keeps
them. If `install.sh` fails on a package repository, the code is still
updated: run it again later.

## Configure

Edit `/var/lib/external-scan/external-scan.conf`, the only config file. It
never goes to git. `external-scan.conf.example` explains every line. In short:

```
cert_warn_days 30
keep_months    12
web_scan       off

target 203.0.113.10 firewall.example.com
  web_scan on
  https cloud.example.com 443
  smtp  mail.example.com  587
  tls   mail.example.com  993
```

Modes: `https` for web sites, `tls` for TLS from the first byte on any
protocol (`smtps`, `imaps` and `pop3s` are aliases), and `smtp`, `imap`,
`pop3` for STARTTLS.

### What a name adds

Every open port is found on the IP alone, with or without names. testssl.sh
then tests each port nmap sees as TLS, and each SMTP, IMAP or POP3 port
through STARTTLS. SSH gets ssh-audit and a password login check. Other ports,
like plain HTTP on 80, are only listed, with their known CVEs.

A name under the target adds three things:

- the real certificate: a reverse proxy picks it from the name, so without
  one you only see its default certificate,
- a DNS check that the name resolves to the target IP,
- nuclei, on `https` lines only, when `web_scan` is on.

A port with a name is not tested again on the IP alone. A named port that is
closed is skipped with a note. nuclei only speaks HTTPS: a site served in
plain HTTP only cannot be web scanned.

### Web application scan

Behind a reverse proxy nmap only sees the proxy. nuclei looks at the sites
themselves: outdated Nextcloud or Mattermost, exposed admin pages, files like
`.git` or `.env`. A global `web_scan` sets the default, and a `web_scan` line
under a target overrides it.

Limits:

- critical and high templates only, without the dos, intrusive and fuzz tags,
- at most 20 requests per second,
- connects to the target IP only, the name goes in SNI and Host, redirects are
  never followed,
- no out-of-band test (interactsh), so nuclei sends nothing to third parties.

It is still an attack for the target: about 5000 requests in 5 minutes per
name, many with real payloads (path traversal, SQL injection, XSS, a few PUT
and DELETE). Logs, WAF and IDS will report it. Without the whitelist the VPS
gets banned halfway.

Templates are downloaded from GitHub at each scan, so a new finding can come
from a new template, not from a change on the site.

### Find the names on a NethServer 8 cluster

On the leader node, for each Traefik instance (`traefik1`, `traefik2`...):

```
api-cli run module/traefik1/list-routes --data '{"expand_list": true}' | jq -r '.[] | select(.host) | .host' | sort -u
```

Routes without a host, like `cluster-admin`, only answer with the default
certificate and are not listed. The mail server name is not a route. Find it
in the MX record or in the certificates:

```
api-cli run module/traefik1/list-certificates --data '{"expand_list": true}'
```

## Run

Commands run as root, which only asks systemd to start the service. The scan
itself runs as `external-scan`. Started directly as root, it refuses to run.

```
systemctl start external-scan.service
```

This returns when the scan ends: a few minutes to over an hour per address.
A second start while a scan runs does nothing: systemd joins the running one.
Started directly, the script stops with "another scan is already running".

To get the prompt back and follow it:

```
systemctl start --no-block external-scan.service
journalctl -u external-scan -f
```

The journal only shows the start and the end. Details go to
`results/<date>_<time>/scan.log`, and `results/latest` points to the last
finished run:

```
cat /var/lib/external-scan/results/latest/SUMMARY.txt
```

A config change needs no restart. The next scan reads it.

After a first good manual scan, enable the monthly run (the 1st, at a random
time between 03:00 and 04:00):

```
systemctl enable --now external-scan.timer
```

systemd gives the raw socket right for the nmap SYN scan. Run outside
systemd, the scan falls back to a slower TCP connect scan and skips UDP.

## Read the results

One directory per scan, named after its start time:

```
results/2026-11-01_0312/
  SUMMARY.txt                     one line per address, read this first
  scan.log                        what ran and when, tool errors
  203.0.113.10_firewall.example.com/
    REPORT_firewall.example.com_2026-11-01_0312.txt
                                  the report for this address
    REPORT_firewall.example.com_2026-11-01_0312.pdf
                                  the report for the owner, when pdf_report is on
    report.json                   the data of the PDF, when pdf_report is on
    nmap.txt  nmap.xml            nmap output, TCP
    nmap-udp.txt  nmap-udp.xml    nmap output, UDP, when it ran
    ports.tsv                     open TCP and UDP ports, compared next month
    ndiff.txt                     TCP diff with the previous scan, when ndiff is installed
    testssl/                      testssl.sh output per name and port
    ssh-audit_22.json             ssh-audit output
    nuclei/                       nuclei output per name and port, when web_scan is on
    findings.tsv                  every finding with its key, compared next month
```

A second scan in the same minute replaces the first.

Status of a report:

- **OK**: nothing to look at.
- **ATTENTION**: read "What changed" and "Needs attention". A new open port,
  a finding not accepted, or a failed tool (`failed/...`). A closed port and
  the CVEs by version never change the status.
- **ERROR**: the nmap TCP scan did not finish, nothing else was tested. The
  script exits with an error and keeps the old results.

A finding is a problem found: a serious TLS or SSH weakness, a certificate
expiring soon, SSH accepting passwords, an open sensitive port
(`sensitive_ports`), a nuclei match, or a name resolving to another address.
Each has a stable key, like `tls/www.example.com/443/BREACH`.

The report starts with:

- **What changed**: ports and findings that appeared or went away.
- **Needs attention**: findings not accepted.
- **Accepted risks**: each `accept` line that matched, with the count and the reason.
- **Suggested accept lines**: ready to copy into the config.

Then the open ports, the certificates, the CVEs by version and the notes.

### Accept known risks

The first scan often lists the same finding on several ports. Fix what you
can. For a risk kept on purpose, copy its suggested line under the target,
with a review date and the real reason:

```
target 203.0.113.10 firewall.example.com
  accept sensitive/9090 until 2027-06-30 "firewall GUI, CrowdSec bans brute force, VPN planned"
  accept tls/*/*/BREACH until 2027-06-30 "HTTP compression needed, no secret in the pages"
```

The status then only turns to ATTENTION for something new or not accepted. An
accepted finding comes back after its date. An accept line that matches
nothing is noted, unless a tool failed, since the finding may only be missing
because of that.

The first scan of an address is the baseline, with no new ports. Each scan
is compared with the last earlier run where nmap finished. UDP is compared
only when both runs scanned it.

Results older than `keep_months` are deleted after each scan without ERROR.

### PDF report for the owner

`pdf_report on` adds `REPORT_<name>_<date>_<time>.pdf` per address, in
English. `<name>` is the first word of the target label, or the IP. It says
who scanned, from which machine, when, and what was tested. Then what
changed, the findings, the accepted risks, the open ports with how nmap
identified them, the TLS services with the tests testssl could not run, SSH,
the web sites and the notes.

The annex holds the rest: the nmap command, the tool versions, every TLS
attack tested and its result, testssl LOW and MEDIUM results except per cipher
suite, each certificate, the SSH algorithms, host key fingerprint and
ssh-audit notes, what nuclei ran, the CVEs by version on TCP ports, and the
SHA-256 of every file of the target folder except `report.json` and the PDF.
An empty section says "None.", so it never looks like a check that did not
run. The annex also says what is left out: testssl INFO and OK results apart
from the attacks, and results per cipher suite. They stay in the raw files,
kept `keep_months` months on the scanning machine.

The PDF adds no advice and no judgment, and cuts no text. Messages come from
the tools, and from the script for its own checks (DNS, sensitive ports, SSH
login, certificate expiry, failed checks). Severities are those of testssl and
nuclei. An expired acceptance is said next to its message. Findings with the
same check and the same message share one line with all their places. The
check is the test name for testssl and nuclei, the port and algorithm type for
ssh-audit, and the finding key for the others. A check that did not complete
is a "Test not completed" finding, and its row is marked in the TLS, SSH and
web tables.

`operator` and `authorization` print who scans and under which permission.
Without them the PDF says they are not set.

typst, fetched into `tools/` with its own fonts, renders the template
`report.typ`. A failed PDF is noted in `SUMMARY.txt` and `scan.log` and never
changes the status. When only typst failed, `report.json` stays, so you can
render it again:

```
tools/typst/typst compile --root / --ignore-system-fonts \
    --input data=$PWD/results/<date>_<time>/<target>/report.json \
    report.typ /tmp/report.pdf
```

## Test on the VPS itself

Scan only the loopback:

```
mkdir -p /tmp/es-test
echo "target 127.0.0.1 self" > /tmp/es-test/external-scan.conf
chmod -R a+rwX /tmp/es-test
sudo -u external-scan /var/lib/external-scan/external-scan \
    --config /tmp/es-test/external-scan.conf --output /tmp/es-test/results
```

## Good to know

- Many VPS providers block outgoing port 25. The SMTP test on 25 then fails,
  465 and 587 still work.
- Time limits: nmap 6 hours TCP and 4 hours UDP per address, testssl.sh 30
  minutes per port, nuclei 30 minutes per name, ssh-audit 5 minutes, the whole
  run 24 hours. A tool over its limit gives a `failed/...` finding, nmap TCP
  gives ERROR.
- nuclei stops on a site that stops answering, with a `failed/web/...` line.
  It is usually a ban: check the whitelist.
- The vulners script sends the versions it finds to vulners.com. It matches
  on the version string only, so distro backports show as false positives.
  They never change the status.
- All TCP ports are scanned, UDP only a short list (DNS, NTP, SNMP, VPN, QUIC,
  telephony...) set by `udp_ports` and `udp_ports_extra`. A full UDP scan
  would take about 18 hours. UDP needs the raw socket right, so it only runs
  through systemd. Run by hand, the report says it was skipped.

## Uninstall

```
systemctl disable --now external-scan.timer
rm -f /etc/systemd/system/external-scan.service /etc/systemd/system/external-scan.timer
systemctl daemon-reload
rm -rf /var/lib/external-scan
userdel external-scan
```
