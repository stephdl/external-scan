#!/usr/bin/env python3
"""Read nmap, testssl.sh, ssh-audit and nuclei output for external-scan.

Each subcommand prints tab separated lines that the bash script reads.
Empty fields are printed as "-" because bash "read" merges consecutive tabs.
"""

import hashlib
import ipaddress
import json
import os
import re
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


def vulners_rows(path):
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
            yield f"{port.get('portid')}/{port.get('protocol')}", high, max(scores), len(scores)


def vulners(path):
    for port, high, top, total in vulners_rows(path):
        print(f"{port}\t{high}\t{top:.1f}\t{total}")


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


def read_tsv(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return [line.rstrip("\n").split("\t") for line in handle if line.strip()]
    except FileNotFoundError:
        return []


def local_time(epoch):
    return datetime.fromtimestamp(int(epoch)).astimezone().strftime("%Y-%m-%d %H:%M %z")


def tls_endpoints(path, ip):
    endpoints = []
    folder = os.path.join(path, "testssl")
    for name in sorted(os.listdir(folder)) if os.path.isdir(folder) else []:
        if not name.endswith(".json"):
            continue
        host, _, port = name[:-5].rpartition("_")
        try:
            with open(os.path.join(folder, name), encoding="utf-8") as handle:
                items = json.load(handle)
        except (OSError, ValueError):
            continue
        first = {}
        for item in items if isinstance(items, list) else []:
            # With several certificates the id gets a suffix like "cert_notAfter <hostCert#1>", the first one is kept.
            first.setdefault(str(item.get("id", "")).split(" ")[0], item)
        found = {key: clean(item.get("finding", ""), 120) for key, item in first.items()}
        days = ""
        try:
            end = datetime.strptime(found.get("cert_notAfter", ""), "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
            days = (end - datetime.now(timezone.utc)).days
        except ValueError:
            pass
        endpoints.append({
            "name": ip if host == "ip" else host,
            "port": port,
            "protocols": [label for key, label in (("SSLv2", "SSLv2"), ("SSLv3", "SSLv3"), ("TLS1", "TLS 1.0"),
                          ("TLS1_1", "TLS 1.1"), ("TLS1_2", "TLS 1.2"), ("TLS1_3", "TLS 1.3"))
                          if found.get(key, "").startswith("offered")],
            "grade": found.get("overall_grade", ""),
            "subject": found.get("cert_commonName", ""),
            "issuer": found.get("cert_caIssuers", ""),
            "trust": found.get("cert_chain_of_trust", ""),
            "expires": found.get("cert_notAfter", ""),
            "days": days,
            "hsts": found.get("HSTS", ""),
        })
    return endpoints


def ssh_servers(path):
    servers = []
    for name in sorted(os.listdir(path)):
        match = re.fullmatch(r"ssh-audit_(\d+)\.json", name)
        if not match:
            continue
        try:
            with open(os.path.join(path, name), encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            continue
        fail = warn = 0
        for kind in ("kex", "key", "enc", "mac"):
            for alg in data.get(kind) or []:
                notes = alg.get("notes") if isinstance(alg, dict) else None
                if isinstance(notes, dict):
                    fail += any(note != "using unknown algorithm" for note in notes.get("fail") or [])
                    warn += bool(notes.get("warn"))
        servers.append({
            "port": match.group(1),
            "software": clean((data.get("banner") or {}).get("raw", ""), 80),
            "fail": fail,
            "warn": warn,
            "cves": len(data.get("cves") or []),
        })
    return servers


def web_sites(path):
    sites = []
    folder = os.path.join(path, "nuclei")
    for name in sorted(os.listdir(folder)) if os.path.isdir(folder) else []:
        if not name.endswith(".jsonl"):
            continue
        host, _, port = name[:-6].rpartition("_")
        matches = []
        with open(os.path.join(folder, name), encoding="utf-8", errors="replace") as handle:
            for line in handle:
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                info = item.get("info") or {}
                matches.append({
                    "severity": str(info.get("severity", "")).upper(),
                    "name": clean(info.get("name", ""), 120),
                    "url": clean(item.get("matched-at", ""), 120),
                })
        sites.append({"name": host, "port": port, "matches": matches})
    return sites


def checksums(path):
    files = []
    for root, dirs, names in os.walk(path):
        dirs.sort()
        for name in sorted(names):
            full = os.path.join(root, name)
            relative = os.path.relpath(full, path)
            # Both are written from this data, after the hashes.
            if relative in ("report.json", "REPORT.pdf"):
                continue
            digest = hashlib.sha256()
            with open(full, "rb") as handle:
                for chunk in iter(lambda: handle.read(1 << 16), b""):
                    digest.update(chunk)
            files.append({"file": relative, "sha256": digest.hexdigest()})
    return files


def group_findings(findings):
    """Merges findings with the same check and the same tool message, and lists where each one was seen.

    Only identical messages are merged: the text of the tools is kept as is, nothing is reworded.
    """
    groups = {}
    for finding in findings:
        check, where, message = finding["key"], "", finding["text"]
        tool = re.fullmatch(r"(?:testssl|nuclei) \w+ on (\S+): (.*)", message)
        ssh = re.fullmatch(r"ssh-audit on port (\d+), (\w+) (\S+): (.*)", message)
        if tool:
            check, where, message = finding["key"].split("/")[-1], tool.group(1), tool.group(2)
        elif ssh:
            check, where, message = f"port {ssh.group(1)}, {ssh.group(2)}", ssh.group(3), ssh.group(4)
        group = groups.setdefault((finding["state"], finding["category"], check, message), {
            "state": finding["state"],
            "category": finding["category"],
            "check": check,
            "message": message,
            "severity": finding["severity"],
            "where": [],
            "count": 0,
        })
        group["count"] += 1
        if where and where not in group["where"]:
            group["where"].append(where)
    return list(groups.values())


def report(path):
    """Prints report.json for the PDF, from the scan folder and the lines bash sends on stdin.

    Each stdin line is "<kind>\\t<value>". Kinds in LISTS repeat, the others are single values.
    """
    lists = {"change": "changes", "note": "notes", "check": "checks", "accepted": "accepted",
             "attention": "attention", "version": "versions"}
    data = {name: [] for name in lists.values()}
    for line in sys.stdin.buffer.read().decode("utf-8", "replace").splitlines():
        kind, _, value = line.partition("\t")
        if kind in lists:
            data[lists[kind]].append(value.split("\t"))
        elif kind:
            data[kind] = value
    data["changes"] = [row[0] for row in data["changes"]]
    data["notes"] = [row[0] for row in data["notes"]]
    data["checks"] = [dict(zip(("mode", "name", "port"), row[0].split())) for row in data["checks"]]
    data["versions"] = [{"tool": row[0], "version": row[1] if len(row) > 1 else ""} for row in data["versions"]]
    data["accepted"] = [dict(zip(("pattern", "count", "until", "reason"), row)) for row in data["accepted"]]
    attention = {row[0] for row in data.pop("attention")}
    data["duration_minutes"] = max(0, (int(data["finished"]) - int(data["started"])) // 60)
    data["started"] = local_time(data["started"])
    data["finished"] = local_time(data["finished"])
    data["generated"] = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %z")

    sensitive = set(data.get("sensitive_ports", "").split(","))
    data["ports"] = [
        {"port": row[0], "service": row[1], "detail": row[3] if len(row) > 3 else "-",
         "sensitive": row[0].endswith("/tcp") and row[0].split("/")[0] in sensitive}
        for row in read_tsv(os.path.join(path, "ports.tsv"))
    ]
    data["findings"] = []
    for row in read_tsv(os.path.join(path, "findings.tsv")):
        key, text = row[0], row[1] if len(row) > 1 else ""
        severity = re.match(r"(?:testssl|nuclei) (\w+) on ", text)
        data["findings"].append({
            "key": key,
            "category": key.split("/")[0],
            "text": text,
            "severity": severity.group(1).upper() if severity else "",
            "state": "open" if key in attention else "accepted",
        })
    data["groups"] = group_findings(data["findings"])
    data["vulners"] = []
    for name in ("nmap.xml", "nmap-udp.xml"):
        try:
            data["vulners"] += [{"port": port, "high": high, "max": f"{top:.1f}", "total": total}
                                for port, high, top, total in vulners_rows(os.path.join(path, name))]
        except (OSError, ValueError, ET.ParseError):
            pass
    data["tls"] = tls_endpoints(path, data.get("ip", ""))
    data["ssh"] = ssh_servers(path)
    data["web"] = web_sites(path)
    data["files"] = checksums(path)
    # Bytes, so the output stays UTF-8 under the LC_ALL=C of the bash script.
    sys.stdout.buffer.write(json.dumps(data, ensure_ascii=False, indent=1).encode("utf-8"))


COMMANDS = {
    "check-ip": check_ip,
    "resolve": resolve,
    "ports": ports,
    "vulners": vulners,
    "testssl": testssl,
    "ssh-audit": ssh_audit,
    "nuclei": nuclei,
    "report": report,
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
