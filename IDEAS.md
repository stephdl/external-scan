# Ideas for v2

These are ideas, not commitments. Each one says what it finds, how risky it
is for the scanned network and what it costs to add. "Passive" means no packet
goes to the target addresses.

## Decisions

- Done: 1 and 2 in #2 (`sshpw/<port>` and `sensitive_ports`), 6 in #2
  (findings compared with the previous scan), 7 with nuclei and `web_scan`.
  They are removed from this list.
- 3, 4, 5 and 8 are dropped.
  - 3: a broken SPF or DMARC shows up within hours as rejected mail. A
    monthly scan only adds value for a policy that is too loose, and that
    rarely changes.
  - 4: a monthly check sees a blocklisting weeks too late. Hourly monitoring
    is the right place for it.
  - 5: a wildcard certificate hides every subdomain from the certificate
    logs, so crt.sh finds nothing useful.
  - 8: it mostly repeats the scan.
- Open: 9 and 10.

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

## 8. Shodan or Censys (passive)

Compare the scan with what Shodan or Censys already see for each IP, with their
history. Useful as a cross check, but it mostly repeats the scan. Needs an API
key.

Risk: none. Cost: small.

## 9. Structured findings

findings.tsv holds a key and a sentence per finding. The PDF report of #5
gets the tool, the severity, the place and the message back from that
sentence with regexes. If someone rewords a sentence in add_finding, the
regexes stop matching without any error: findings lose their severity and
are no longer grouped.

add_finding could write these as separate columns of findings.tsv, and the
text and PDF reports would read the columns. classify_findings and
compare_findings read findings.tsv too, so they would change with it.

Risk: none. Cost: medium.

## 10. IPv6 targets

The config refuses IPv6 addresses today. Supporting them needs `-6` for nmap,
testssl.sh and ssh-audit, `-6` in the nmap command printed in the PDF, and a
refusal of IPv4-mapped addresses such as `::ffff:203.0.113.5`, which would be
scanned over IPv6. A first try that only fixed nmap is #17, closed for that
reason. No Constance name has an AAAA record yet, so nothing can test it.

Risk: none. Cost: small, plus a reachable IPv6 target to test.
