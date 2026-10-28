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
- links the systemd service and timer.

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

Every open port is scanned anyway. The indented lines are for testssl.sh. A
reverse proxy picks the certificate from the name, so without them you only
see its default certificate.

The config file never goes to git.

## Run

Run a scan by hand:

```
systemctl start external-scan.service
```

The command returns when the scan is over. A scan of all ports can take an
hour or more per address.

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
    ssh-audit_22.txt              full ssh-audit output
```

Each report has a status:

- **OK**: nothing needs a look.
- **ATTENTION**: read the report. It can be a new open port, a certificate
  that expires soon, a serious TLS or SSH finding, or a name that resolves to
  another address.
- **ERROR**: the scan did not complete.

The first scan of an address is the baseline. It does not report new ports.

Results older than `keep_months` are deleted after each successful scan.

## Uptime Kuma (optional)

Set `kuma_url` in the config to the URL of a Push monitor. After each scan
the script sends `up` when there is no error and no new open port, and
`down` otherwise. The URL contains a token, so it is never written to the
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
- Only TCP is scanned. A full UDP scan would take hours.

## Uninstall

```
systemctl disable --now external-scan.timer
systemctl disable external-scan.service
rm -rf /var/lib/external-scan
userdel external-scan
```
