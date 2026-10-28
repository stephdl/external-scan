# Ideas for v2

These are ideas, not commitments. Each one says what it finds, how risky it
is for the scanned network and what it costs to add. "Passive" means no packet
goes to the target addresses.

## 1. SSH password login

The nmap script `ssh-auth-methods` lists the login methods the SSH server
offers, so the report can say if passwords are accepted or only keys.
ssh-audit does not check this. It takes a few seconds and tries no login.

Risk: none. Cost: small.

## 2. Admin ports always flagged

Keep a list of well known admin ports (9090, 8443, 10000, 3389, 5900, 980...)
and set the status to ATTENTION whenever one is open, not only when it is new.
An exposed firewall web UI would then show up every month.

Risk: none. Cost: small.

## 3. Mail security in DNS (passive)

Check SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DNSSEC and CAA for each mail domain,
with dig or checkdmarc. This finds domains that anyone can spoof.

Risk: none. Cost: small.

## 4. Spam blocklists (passive)

Check if each target IP is listed on Spamhaus, Barracuda and other DNS
blocklists. Spamhaus refuses queries through public resolvers such as 8.8.8.8
or 1.1.1.1, so this needs a local resolver like unbound.

Risk: none. Cost: medium, because of the resolver.

## 5. Forgotten names from certificate logs (passive)

Query crt.sh for every certificate issued for the domain, resolve each name and
report the names that point to a target IP but are not in the config. This
finds forgotten sites and DNS records left behind after a service was removed.
The scan still never connects to a name outside the targets.

Risk: none. Cost: medium.

## 6. TLS and SSH changes month to month

Today only ports are compared with the previous scan. Also report a TLS or SSH
finding that was not there last month, so a regression stands out.

Risk: none. Cost: medium.

## 7. Web application scan

Behind a reverse proxy nmap only sees the proxy, so vulners never sees the
applications. A web scanner run on each configured name would find outdated
Nextcloud, Mattermost or SOGo versions, exposed admin pages and files like
`.git` or `.env`.

Candidates:

- nuclei, template based and fast. Limit it with
  `-severity critical,high -exclude-tags dos,intrusive,fuzz` and a rate limit.
- Nikto, older and noisier, but simple.
- OWASP ZAP baseline scan, passive by default, good for HTTP headers and
  cookies.
- Greenbone OpenVAS, a full vulnerability scanner. Thorough but heavy, it
  needs its own database and services.

Risk: real. These tools send many requests and some templates probe for
vulnerabilities. Check that the written permission covers a vulnerability scan
and not only a port scan, and whitelist the scanner first.

Cost: medium for nuclei, high for OpenVAS.

## 8. Shodan or Censys (passive)

Compare the scan with what Shodan or Censys already see for each IP, with their
history. Useful as a cross check, but it mostly repeats the scan. Needs an API
key.

Risk: none. Cost: small.
