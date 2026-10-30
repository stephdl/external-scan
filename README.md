# external-scan

A small monthly scan of what a network exposes to the Internet. It runs from a
VPS outside the network, against a fixed list of public IP addresses.

For each address it:

1. finds every open TCP port with nmap, and the service behind it,
2. compares the open ports with the previous scan,
3. checks certificates and TLS settings with testssl.sh,
4. checks SSH settings with ssh-audit,
5. scans each web site name with nuclei, when `web_scan` is on,
6. writes a short plain text report, and a PDF for the owner when `pdf_report` is on.

## Software used

The scan relies on free software. `install.sh` installs all of it.

| Software | What it does here | Comes from |
|---|---|---|
| [nmap](https://nmap.org) | finds the open TCP and UDP ports and the service behind each | distribution package |
| [vulners](https://github.com/vulnersCom/nmap-vulners) | nmap script that lists known CVEs for the version a service announces | shipped with nmap |
| [testssl.sh](https://testssl.sh) | checks certificates, protocols, ciphers and known TLS attacks | git clone, pinned tag |
| [ssh-audit](https://github.com/jtesta/ssh-audit) | checks SSH algorithms and known SSH CVEs | git clone, pinned tag |
| OpenSSH client | asks an SSH server which login methods it accepts, without trying any | distribution package |
| [nuclei](https://github.com/projectdiscovery/nuclei) | looks for known web flaws with its critical and high templates | release binary, SHA-256 checked |
| [typst](https://typst.app) | renders the PDF report | release binary, SHA-256 checked |
| python3 | reads the tool results and writes the reports | distribution package |
| bash | runs the scan | distribution package |
| systemd | runs the scan monthly as an unprivileged user with the raw socket right | distribution package |

Helpers: socat, openssl, dig and hexdump for testssl.sh, git to fetch and
update the cloned tools, curl for Uptime Kuma, and ndiff to compare two nmap
scans when the distribution ships it.

The pinned versions are at the top of `install.sh`. Each PDF report prints the
versions that ran the scan.

## Before you scan

**Get written permission from the owner of every address you scan.** Only
list those addresses in the config. The script refuses ranges and host names,
and never connects to an address that is not in the config.

**The nuclei web scan is a vulnerability scan, not a port scan.** It stays off
until `web_scan on` is set. Turn it on only for owners whose written
permission covers a vulnerability scan.

**Ask the owner to whitelist the IP of the scanning VPS** in CrowdSec, the
firewall IDS (Suricata on OPNsense, for example), fail2ban or anything similar.
Otherwise the scan gets blocked halfway and the report shows fewer open ports
than there really are.

## Install

Everything lives in one directory: `/var/lib/external-scan`. It is the git
clone, the home of the `external-scan` system user, and the place for the
config, the tools and the results.

```
git clone https://github.com/stephdl/external-scan.git /var/lib/external-scan
/var/lib/external-scan/install.sh
```

`install.sh` works on Debian, Ubuntu, Rocky and Fedora. It is safe to run
again. It does the following:

- installs nmap, python3 and the other packages,
- creates the `external-scan` system user,
- fetches pinned versions of testssl.sh, ssh-audit, nuclei and typst into `tools/`,
- creates `external-scan.conf` from the example if it does not exist,
- copies the systemd service and timer to `/etc/systemd/system`.

It does not enable the timer.

To update, run `git pull` in `/var/lib/external-scan`, then `install.sh` again.

## Configure

Edit `/var/lib/external-scan/external-scan.conf`. It is the only config file.
The example in the file explains each line. A short version:

```
cert_warn_days 30
keep_months    12
web_scan       off

target 203.0.113.10 firewall.example.com
  web_scan on
  https cloud.example.com 443
  smtp  mail.example.com  587
  imaps mail.example.com  993
```

The modes are `https`, `smtps`, `imaps` and `pop3s` for TLS from the first
byte, `smtp`, `imap` and `pop3` for STARTTLS, and `tls` for TLS from the first
byte on any other protocol. `tls` also still works on the mail ports.

Every open port is scanned anyway. Without any indented line, testssl.sh
still tests each port that nmap sees as SSL, and each SMTP, IMAP or POP3 port
through STARTTLS, on the bare IP. The indented lines add a name to the test.
A reverse proxy picks the certificate from the name, so without them you only
see its default certificate.

### Web application scan

Behind a reverse proxy nmap only sees the proxy, never the applications. When
`web_scan` is on, nuclei scans every `https` line: outdated Nextcloud or
Mattermost versions, exposed admin pages, files like `.git` or `.env`.

`web_scan off` at the start of the config turns it off for every target, and
`web_scan on` under a target turns it on for that one only. The opposite works
too.

The scan stays safe for the target:

- only templates rated critical or high, without the dos, intrusive and fuzz
  tags,
- at most 20 requests per second,
- it connects to the target IP only, with the name in SNI and in the Host
  header, and never follows a redirect,
- no out-of-band test (interactsh), so nothing goes to third party servers.

It is still an attack from the point of view of the target. Each name gets
about 5000 requests in 5 minutes, and many carry real exploit payloads: path
traversal, SQL injection, XSS, a few PUT and DELETE on known APIs. Expect the
web server logs, a WAF or an IDS to report them. Without the whitelist the
scanning VPS gets banned halfway.

The templates are downloaded from GitHub again at the start of each scan, so
a new finding can come from a new template, not from a change on the site.

The config file never goes to git.

### Find the names on a NethServer 8 cluster

Each Traefik instance holds its own routes. Run this on the leader node for
every Traefik instance of the cluster (`traefik1`, `traefik2`, ...):

```
api-cli run module/traefik1/list-routes --data '{"expand_list": true}' | jq -r '.[] | select(.host) | .host' | sort -u
```

Routes without a host, like `cluster-admin`, are routed by path and only
answer with the default certificate, so they are not listed. The mail server
name is not a route. Look for it in the MX record or in the certificates:

```
api-cli run module/traefik1/list-certificates --data '{"expand_list": true}'
```

## Run

All commands below run as root. Root only asks systemd to start the service:
the scan itself runs as the `external-scan` user. Started directly as root,
the script refuses to run.

Run a scan by hand:

```
systemctl start external-scan.service
```

The command returns when the scan is over. A scan can take from a few minutes
to an hour or more per address. To get the prompt back at once and follow the
scan:

```
systemctl start --no-block external-scan.service
journalctl -u external-scan -f
```

The journal only shows the start and the end. The details go to
`results/<date>_<time>/scan.log`. `results/latest` points to the last run. Then read the summary:

```
cat /var/lib/external-scan/results/latest/SUMMARY.txt
```

A change in `external-scan.conf` needs no restart or reinstall. The next
scan reads it.

To scan every month on the 1st, at a random time between 03:00 and 04:00, run
this once after a first good manual scan:

```
systemctl enable --now external-scan.timer
```

The script runs as the `external-scan` user, never as root. systemd gives it
the raw socket right that the nmap SYN scan needs. Run outside systemd, it
falls back to a slower TCP connect scan.

## Read the results

Every scan gets its own directory, named after the day and the time it started:

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
    nmap.txt  nmap.xml            full nmap output
    nmap-udp.txt  nmap-udp.xml    nmap output of the UDP ports, unless no UDP port is set
    ndiff.txt                     nmap diff with the previous scan
    testssl/                      full testssl.sh output per name and port
    ssh-audit_22.json             full ssh-audit output
    nuclei/                       full nuclei output per name and port
    findings.tsv                  every finding with its key, compared next month
```

Each report has a status:

- **OK**: nothing needs a look.
- **ATTENTION**: read "What changed" and "Needs attention". It can be a new
  open port, or a finding that is not accepted in the config.
- **ERROR**: the scan did not complete.

A finding is a problem the scan found: a serious TLS or SSH weakness, a
certificate that expires soon, SSH that accepts passwords, a sensitive port
open to the Internet (see `sensitive_ports`), a nuclei match, or a name that
resolves to another address. Each finding has a stable key, like `tls/www.example.com/443/BREACH`.

The report starts with what matters:

- **What changed**: ports that appeared or disappeared, and findings that are
  new or fixed since the previous scan.
- **Needs attention**: findings that are not accepted.
- **Accepted risks**: one line per `accept` line of the config, with the
  number of findings it covers and the reason.
- **Suggested accept lines**: ready to copy into the config.

Then come the open ports, the certificates, the CVEs by version and the notes.

### Accept known risks

The first scan usually lists many findings, often the same one on several
ports. Look at each one. Fix what can be fixed. For a risk you keep on
purpose, copy its suggested line under the target in the config, set a review
date and write the real reason:

```
target 203.0.113.10 firewall.example.com
  accept sensitive/9090 until 2027-06-30 "firewall GUI, CrowdSec bans brute force, VPN planned"
  accept tls/*/*/cert_revocation until 2027-06-30 "no OCSP on the internal CA"
```

From then on the status only turns to ATTENTION for something new or not yet
accepted. An accepted finding comes back after its date. An accept line that
matches nothing is reported, so the config stays clean.

The first scan of an address is the baseline. It does not report new ports.

Results older than `keep_months` are deleted after each successful scan.

### PDF report for the owner

Set `pdf_report on` in the config to also get a `REPORT_<name>_<date>_<time>.pdf` in English per
address, to send to its owner. `<name>` is the first word of the target
label, or the IP without a label. The report says who ran the scan, from which
machine, when it started and ended, and what was tested. Then it gives what
changed, the findings to fix, the accepted risks, the open ports with how nmap
identified each service, the TLS services with the tests testssl could not
run, SSH, the web sites, and the notes.

A technical annex gives the rest of the data: the nmap command and the tool
versions, every known attack testssl tested with its result, its LOW and
MEDIUM results except the ones per cipher suite, each certificate, the SSH
algorithms with the host key fingerprint and the notes of ssh-audit, what
nuclei ran, the CVEs by version on TCP ports like the text report, and the
SHA-256 of every file of the target folder, except `report.json` and
the PDF. A section with nothing in it says "None.", so an empty result
never looks like a check that did not run. The annex also says what is not in
the PDF: the testssl results rated INFO or OK apart from the attacks tested,
and its results per cipher suite. They stay in the raw files, which are kept
on the scanning machine for `keep_months` months.

The PDF adds no advice and no judgment of its own, and cuts no text. Messages
come from the tools, and from the script for its own checks (DNS, sensitive ports, SSH
login, certificate expiry, failed checks). The severity shown is the one
testssl and nuclei give. An expired acceptance is said next to the message.
In each section, findings with the same check and the exact same message
share one line, with the places where they were seen. The check is the test
name for testssl and nuclei, the port and algorithm type for ssh-audit, and
the finding key for the others. A check that did not complete is a finding of
the "Test not completed" category, and the TLS, SSH and web tables mark its
row.

Add `operator` once and `authorization` under each target to print who scans
and under which permission. Without them the PDF says they are not set.

The PDF is rendered by [typst](https://typst.app), a single binary that
`install.sh` fetches into `tools/`, with its own fonts. The template is
`report.typ`. A PDF that fails is noted in `SUMMARY.txt` and `scan.log`, it
never changes the status. When only typst fails, `report.json` stays, so the
PDF can be rendered again by hand:

```
tools/typst/typst compile --root / --ignore-system-fonts \
    --input data=$PWD/results/<date>_<time>/<target>/report.json \
    report.typ /tmp/report.pdf
```

## Uptime Kuma (optional)

Set `kuma_url` in the config to the URL of a Push monitor. After each scan
the script sends `up` when the status is OK, and `down` otherwise: an error,
a new open port or a finding that is not accepted. The URL contains a token, so it is never written to the
logs.

## Test on the VPS itself

Scan only the VPS loopback when testing:

```
mkdir -p /tmp/es-test
echo "target 127.0.0.1 self" > /tmp/es-test/external-scan.conf
chmod -R a+rwX /tmp/es-test
sudo -u external-scan /var/lib/external-scan/external-scan \
    --config /tmp/es-test/external-scan.conf --output /tmp/es-test/results
```

## Good to know

- Many VPS providers block outgoing port 25. The SMTP test on port 25 then
  fails, while 465 and 587 still work.
- nuclei stops scanning a site that stops answering. The report then shows a
  `failed/web/...` line. It is usually a ban: check the whitelist of the
  scanning VPS.
- The nmap vulners script sends the software versions it finds to
  vulners.com. Its matches use the version string only, so backported distro
  fixes show up as false positives. They do not change the status.
- All TCP ports are scanned, but only a short list of UDP ports (DNS, NTP,
  SNMP, VPN, QUIC, telephony...), set by `udp_ports` and `udp_ports_extra`. A full UDP scan would take
  about 18 hours. The UDP scan needs the raw socket right, so it only runs
  through systemd. Run by hand, the report says it was skipped.

## Uninstall

```
systemctl disable --now external-scan.timer
rm -f /etc/systemd/system/external-scan.service /etc/systemd/system/external-scan.timer
systemctl daemon-reload
rm -rf /var/lib/external-scan
userdel external-scan
```
