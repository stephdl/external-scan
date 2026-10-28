#!/usr/bin/env python3
"""Read nmap, testssl.sh, ssh-audit and nuclei output for external-scan.

Each subcommand prints tab separated lines that the bash script reads.
Empty fields are printed as "-" because bash "read" merges consecutive tabs.
"""

import ipaddress
import json
import socket
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


def clean(text, limit=200):
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def key_part(text):
    # Finding keys are copied into "accept" lines: no spaces, no glob characters, no "#" (a config comment).
    return "".join(c if c.isalnum() or c in "._:@-" else "_" for c in str(text)).strip("_") or "-"


def check_ip(value):
    # ip_address() rejects ranges and host names, which nmap would happily expand.
    print(ipaddress.ip_address(value).compressed)


def resolve(name):
    infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    print(" ".join(sorted({info[4][0] for info in infos})))


def load_nmap(path):
    root = ET.parse(path).getroot()
    if root.find("runstats/finished") is None:
        raise ValueError(f"{path}: nmap did not finish")
    return root


def open_ports(root):
    for port in root.iter("port"):
        state = port.find("state")
        if state is not None and state.get("state") == "open":
            yield port


def ports(path):
    for port in open_ports(load_nmap(path)):
        name = tunnel = detail = ""
        service = port.find("service")
        if service is not None:
            name = service.get("name", "")
            tunnel = service.get("tunnel", "")
            detail = " ".join(
                service.get(key) for key in ("product", "version", "extrainfo") if service.get(key)
            )
        print(f"{port.get('portid')}/{port.get('protocol')}\t{name or '-'}\t{tunnel or '-'}\t{clean(detail) or '-'}")


def vulners(path):
    for port in open_ports(load_nmap(path)):
        scores = []
        for script in port.findall("script"):
            if script.get("id") != "vulners":
                continue
            for elem in script.iter("elem"):
                if elem.get("key") == "cvss":
                    try:
                        scores.append(float(elem.text))
                    except (TypeError, ValueError):
                        pass
        if scores:
            high = sum(1 for score in scores if score >= 7.0)
            print(f"{port.get('portid')}/{port.get('protocol')}\t{high}\t{max(scores):.1f}\t{len(scores)}")


def testssl(path):
    with open(path) as handle:
        findings = json.load(handle)
    if not isinstance(findings, list):
        raise ValueError(f"{path}: expected the flat JSON format (--jsonfile)")
    now = datetime.now(timezone.utc)
    for item in findings:
        ident = item.get("id", "")
        severity = item.get("severity", "")
        finding = item.get("finding", "")
        # With several certificates the id gets a suffix like "cert_notAfter <hostCert#1>".
        if ident.startswith("cert_notAfter"):
            try:
                end = datetime.strptime(finding.strip(), "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            print(f"CERT\t{finding.strip()}\t{(end - now).days}")
        # One line per offered cipher would flood the report, cipherlist_* already sums them up.
        # The overall grade only repeats the other findings.
        elif ident.startswith(("cipher-", "cipher_order-")) or ident == "overall_grade":
            continue
        elif severity == "FATAL":
            print(f"FATAL\t{key_part(ident)}\t{clean(finding) or '-'}")
        elif severity in ("HIGH", "CRITICAL"):
            print(f"ISSUE\t{severity}\t{key_part(ident)}\t{clean(finding) or '-'}")


def ssh_audit(path):
    with open(path) as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or not isinstance(data.get("banner"), dict):
        raise ValueError(f"{path}: unexpected ssh-audit JSON")
    # On a failed connection ssh-audit still writes a JSON skeleton, with an empty banner.
    if not data["banner"].get("raw"):
        raise ValueError(f"{path}: no SSH banner received")
    for kind in ("kex", "key", "enc", "mac"):
        for alg in data.get(kind) or []:
            notes = alg.get("notes") if isinstance(alg, dict) else None
            if not isinstance(notes, dict):
                continue
            for note in notes.get("fail") or []:
                # Algorithms newer than ssh-audit, like the post-quantum mlkem ones, are not a weakness.
                if note == "using unknown algorithm":
                    continue
                print(f"FAIL\t{kind}\t{key_part(alg.get('algorithm', '?'))}\t{clean(note) or '-'}")
    for cve in data.get("cves") or []:
        print(f"CVE\t{key_part(cve.get('name', '?'))}\t{cve.get('cvssv2', '?')}\t{clean(cve.get('description', '')) or '-'}")


def nuclei(path):
    # One template can match several URLs, one line per template keeps one finding per key.
    found = {}
    with open(path) as handle:
        for line in handle:
            if not line.strip():
                continue
            item = json.loads(line)
            info = item.get("info") or {}
            ident = key_part(item.get("template-id", "?"))
            entry = found.setdefault(ident, [info.get("severity", "?"), info.get("name", ""), []])
            entry[2].append(item.get("matched-at", ""))
    for ident, (severity, name, urls) in sorted(found.items()):
        more = f" and {len(urls) - 1} more" if len(urls) > 1 else ""
        print(f"ISSUE\t{str(severity).upper()}\t{ident}\t{clean(f'{name} at {urls[0]}{more}') or '-'}")


COMMANDS = {
    "check-ip": check_ip,
    "resolve": resolve,
    "ports": ports,
    "vulners": vulners,
    "testssl": testssl,
    "ssh-audit": ssh_audit,
    "nuclei": nuclei,
}


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in COMMANDS:
        sys.exit(f"usage: parse.py {{{'|'.join(COMMANDS)}}} ARG")
    try:
        COMMANDS[sys.argv[1]](sys.argv[2])
    except Exception as error:
        sys.exit(f"parse.py {sys.argv[1]}: {error}")


if __name__ == "__main__":
    main()
