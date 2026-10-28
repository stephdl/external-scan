# external-scan

A small monthly scan of what a network exposes to the Internet. It runs from a
VPS outside the network, against a fixed list of public IP addresses.

For each address it:

1. finds every open TCP port with nmap, and the service behind it,
2. compares the open ports with the previous scan,
3. checks certificates and TLS settings with testssl.sh,
4. checks SSH settings with ssh-audit,
5. writes a short plain text report.

## Before you scan

**Get written permission from the owner of every address you scan.** Only
list those addresses in the config. The script refuses ranges and host names,
and never connects to an address that is not in the config.

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
- fetches pinned versions of testssl.sh and ssh-audit into `tools/`,
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

target 203.0.113.10 firewall.example.com
  https cloud.example.com 443
  smtp  mail.example.com  587
  tls   mail.example.com  993
```

Every open port is scanned anyway. Without any indented line, testssl.sh
still tests each port that nmap sees as SSL, and each SMTP, IMAP or POP3 port
through STARTTLS, on the bare IP. The indented lines add a name to the test.
A reverse proxy picks the certificate from the name, so without them you only
see its default certificate.

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
`results/<date>/scan.log`. Then read the summary:

```
cat /var/lib/external-scan/results/$(date +%F)/SUMMARY.txt
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

Every scan gets its own directory:

```
results/2026-11-01/
  SUMMARY.txt                     one line per address, read this first
  scan.log                        what ran and when, tool errors
  203.0.113.10_firewall.example.com/
    REPORT.txt                    the report for this address
    nmap.txt  nmap.xml            full nmap output
    ndiff.txt                     nmap diff with the previous scan
    testssl/                      full testssl.sh output per name and port
    ssh-audit_22.json             full ssh-audit output
    findings.tsv                  every finding with its key, compared next month
```

Each report has a status:

- **OK**: nothing needs a look.
- **ATTENTION**: read "What changed" and "Needs attention". It can be a new
  open port, or a finding that is not accepted in the config.
- **ERROR**: the scan did not complete.

A finding is a problem the scan found: a serious TLS or SSH weakness, a
certificate that expires soon, SSH that accepts passwords, a sensitive port
open to the Internet (see `sensitive_ports`), or a name that resolves to
another address. Each finding has a stable key, like `tls/www.example.com/443/BREACH`.

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
- The nmap vulners script sends the software versions it finds to
  vulners.com. Its matches use the version string only, so backported distro
  fixes show up as false positives. They do not change the status.
- All TCP ports are scanned, but only a short list of UDP ports (DNS, NTP,
  SNMP, VPN, QUIC, SIP...), set by `udp_ports`. A full UDP scan would take
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
