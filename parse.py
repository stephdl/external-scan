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


def clean(text):
    # One line only, for the TSV files. Nothing is cut: the reports show the tool output in full.
    return " ".join(str(text).split())


def key_part(text):
    # Finding keys are copied into "accept" lines: no spaces, no glob characters, no "#" (a config comment).
    return "".join(c if c.isalnum() or c in "._:@-" else "_" for c in str(text)).strip("_") or "-"


def check_ip(value):
    # IPv4Address() rejects ranges and host names, which nmap would happily expand.
    # IPv6 is refused until nmap, testssl.sh and ssh-audit all get their -6 option.
    print(ipaddress.IPv4Address(value).compressed)


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


def vulners_cves(path):
    """One entry per vulners result, as nmap wrote it, highest score first."""
    rows = []
    for port in open_ports(load_nmap(path)):
        for script in port.findall("script"):
            if script.get("id") != "vulners":
                continue
            for table in script.iter("table"):
                elems = {elem.get("key"): elem.text or "" for elem in table.findall("elem")}
                if "id" not in elems:
                    continue
                try:
                    score = float(elems.get("cvss", ""))
                except ValueError:
                    score = -1.0
                rows.append({
                    "port": f"{port.get('portid')}/{port.get('protocol')}",
                    "_port": int(port.get("portid", "0")),
                    "id": elems["id"],
                    "type": elems.get("type", ""),
                    "cvss": elems.get("cvss", ""),
                    "exploit": elems.get("is_exploit", ""),
                    "_score": score,
                })
    rows.sort(key=lambda row: (row["_port"], row["port"], -row["_score"], row["id"]))
    for row in rows:
        del row["_score"], row["_port"]
    return rows


def vulners_summary(rows):
    """One line per port: how many entries vulners gave, how many score 7.0 or more, and the highest score."""
    ports = {}
    for row in rows:
        entry = ports.setdefault(row["port"], {"port": row["port"], "total": 0, "high": 0, "max": None})
        entry["total"] += 1
        try:
            score = float(row["cvss"])
        except ValueError:
            continue
        entry["high"] += score >= 7.0
        entry["max"] = score if entry["max"] is None else max(entry["max"], score)
    return [{**e, "max": "" if e["max"] is None else f"{e['max']:.1f}"} for e in ports.values()]


def load_testssl(path):
    with open(path, encoding="utf-8") as handle:
        findings = json.load(handle)
    if not isinstance(findings, list):
        raise ValueError(f"{path}: expected the flat JSON format (--jsonfile)")
    return findings


def cert_days(not_after):
    """Days left before a testssl cert_notAfter date, None when it is not a date."""
    try:
        end = datetime.strptime(not_after.strip(), "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return (end - datetime.now(timezone.utc)).days


def testssl(path):
    for item in load_testssl(path):
        ident = item.get("id", "")
        severity = item.get("severity", "")
        finding = item.get("finding", "")
        # With several certificates the id gets a suffix like "cert_notAfter <hostCert#1>".
        if ident.startswith("cert_notAfter"):
            days = cert_days(finding)
            if days is not None:
                print(f"CERT\t{finding.strip()}\t{days}")
        # One line per offered cipher would flood the report, cipherlist_* already sums them up.
        # The overall grade only repeats the other findings.
        elif ident.startswith(("cipher-", "cipher_order-")) or ident == "overall_grade":
            continue
        elif severity == "FATAL":
            print(f"FATAL\t{key_part(ident)}\t{clean(finding) or '-'}")
        elif severity in ("HIGH", "CRITICAL"):
            print(f"ISSUE\t{severity}\t{key_part(ident)}\t{clean(finding) or '-'}")


def load_ssh_audit(path):
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or not isinstance(data.get("banner"), dict):
        raise ValueError(f"{path}: unexpected ssh-audit JSON")
    # On a failed connection ssh-audit still writes a JSON skeleton, with an empty banner.
    if not data["banner"].get("raw"):
        raise ValueError(f"{path}: no SSH banner received")
    return data


def ssh_notes(data):
    """Yields (kind, algorithm, level, note) for each fail and warn note of ssh-audit."""
    for kind in ("kex", "key", "enc", "mac"):
        for alg in data.get(kind) or []:
            notes = alg.get("notes") if isinstance(alg, dict) else None
            if not isinstance(notes, dict):
                continue
            for level in ("fail", "warn"):
                for note in notes.get(level) or []:
                    # Algorithms newer than ssh-audit, like the post-quantum mlkem ones, are not a weakness.
                    if note != "using unknown algorithm":
                        yield kind, alg.get("algorithm", "?"), level, note


def ssh_audit(path):
    data = load_ssh_audit(path)
    for kind, alg, level, note in ssh_notes(data):
        if level == "fail":
            print(f"FAIL\t{kind}\t{key_part(alg)}\t{clean(note) or '-'}")
    for cve in data.get("cves") or []:
        print(f"CVE\t{key_part(cve.get('name', '?'))}\t{cve.get('cvssv2', '?')}\t{clean(cve.get('description', '')) or '-'}")


def read_nuclei(path):
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def nuclei(path):
    # One template can match several URLs, one line per template keeps one finding per key.
    found = {}
    for item in read_nuclei(path):
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


def tls_endpoints(path, ip, failed):
    endpoints = []
    folder = os.path.join(path, "testssl")
    for name in sorted(os.listdir(folder)) if os.path.isdir(folder) else []:
        if not name.endswith(".json"):
            continue
        host, _, port = name[:-5].rpartition("_")
        host = ip if host == "ip" else host
        try:
            items = load_testssl(os.path.join(folder, name))
        except (OSError, ValueError):
            items = []
        first = {}
        for item in items:
            # With several certificates the id gets a suffix like "cert_notAfter <hostCert#1>", the first one is kept.
            first.setdefault(str(item.get("id", "")).split(" ")[0], item)
        found = {key: clean(item.get("finding", "")) for key, item in first.items()}
        days = cert_days(found.get("cert_notAfter", ""))
        endpoints.append({
            "name": host,
            "port": port,
            "completed": bool(items) and f"failed/tls/{host}/{port}" not in failed,
            "protocols": [label for key, label in (("SSLv2", "SSLv2"), ("SSLv3", "SSLv3"), ("TLS1", "TLS 1.0"),
                          ("TLS1_1", "TLS 1.1"), ("TLS1_2", "TLS 1.2"), ("TLS1_3", "TLS 1.3"))
                          if found.get(key, "").startswith("offered")],
            "grade": found.get("overall_grade", ""),
            "grade_severity": first.get("overall_grade", {}).get("severity", ""),
            "subject": found.get("cert_commonName", ""),
            # Every name the certificate is valid for, the common name alone can look wrong.
            "san": clean(first.get("cert_subjectAltName", {}).get("finding", "")),
            "trust": found.get("cert_chain_of_trust", ""),
            "trust_severity": first.get("cert_chain_of_trust", {}).get("severity", ""),
            "expires": found.get("cert_notAfter", ""),
            "days": "" if days is None else days,
        })
    return endpoints


def ssh_servers(path):
    servers = []
    for name in sorted(os.listdir(path)):
        match = re.fullmatch(r"ssh-audit_(\d+)\.json", name)
        if not match:
            continue
        try:
            data = load_ssh_audit(os.path.join(path, name))
        except (OSError, ValueError):
            servers.append({"port": match.group(1), "completed": False})
            continue
        notes = list(ssh_notes(data))
        servers.append({
            "port": match.group(1),
            "completed": True,
            "software": clean(data["banner"]["raw"]),
            "fail": len({(kind, alg) for kind, alg, level, _ in notes if level == "fail"}),
            "warn": len({(kind, alg) for kind, alg, level, _ in notes if level == "warn"}),
            "cves": len(data.get("cves") or []),
            "algorithms": {kind: [alg.get("algorithm", "") for alg in data.get(kind) or []]
                           for kind in ("kex", "key", "enc", "mac")},
            "fingerprints": [f"{fp.get('hostkey', '')} {fp.get('hash_alg', '')}:{fp.get('hash', '')}"
                             for fp in data.get("fingerprints") or [] if fp.get("hash_alg") == "SHA256"],
            "notes": [clean(note) for note in data.get("additional_notes") or []],
        })
    return servers


# testssl checks for known TLS attacks, in the order testssl runs them.
TLS_ATTACKS = ("heartbleed", "CCS", "ticketbleed", "opossum", "ROBOT", "secure_renego", "secure_client_renego",
               "CRIME_TLS", "BREACH", "POODLE_SSL", "fallback_SCSV", "SWEET32", "FREAK", "DROWN", "LOGJAM",
               "LOGJAM-common_primes", "BEAST", "BEAST_CBC_TLS1", "LUCKY13", "winshock", "RC4")
CERT_FIELDS = ("cert_commonName", "cert_caIssuers", "cert_keySize", "cert_signatureAlgorithm", "cert_notBefore",
               "cert_notAfter", "cert_fingerprintSHA256")


def nmap_details(path):
    """What the PDF tables leave out of nmap.xml: how each service was identified, reverse DNS, closed ports."""
    details = {"services": {}, "hostnames": [], "not_open": []}
    for name in ("nmap.xml", "nmap-udp.xml"):
        try:
            root = load_nmap(os.path.join(path, name))
        except (OSError, ValueError, ET.ParseError):
            continue
        for hostname in root.iter("hostname"):
            entry = f"{hostname.get('name')} ({hostname.get('type')})"
            if entry not in details["hostnames"]:
                details["hostnames"].append(entry)
        for extra in root.iter("extraports"):
            for reason in extra.findall("extrareasons") or [extra]:
                details["not_open"].append({"proto": reason.get("proto", ""), "state": extra.get("state", ""),
                                            "count": reason.get("count", extra.get("count", "")),
                                            "reason": reason.get("reason", "")})
        for port in open_ports(root):
            service = port.find("service")
            if service is None:
                continue
            details["services"][f"{port.get('portid')}/{port.get('protocol')}"] = {
                "method": service.get("method", ""), "conf": service.get("conf", ""),
                "cpe": [cpe.text for cpe in service.findall("cpe") if cpe.text]}
    return details


def host_port(host, port):
    """Same spelling as the bash script, so an IPv6 address and its port stay apart."""
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def group_rows(rows):
    """Merges testssl rows with the same id, severity and finding, and lists where each was seen."""
    groups = {}
    for where, item in rows:
        places = groups.setdefault((item["id"], item["severity"], item["finding"]), [])
        if where not in places:
            places.append(where)
    return [{"id": i, "severity": s, "finding": f, "where": w} for (i, s, f), w in groups.items()]


def tls_details(path, ip):
    """testssl results the main TLS table leaves out: attacks tested, lower severities, certificates, skipped tests."""
    attacks, lower, skipped, certs = [], [], [], {}
    folder = os.path.join(path, "testssl")
    for name in sorted(os.listdir(folder)) if os.path.isdir(folder) else []:
        if not name.endswith(".json"):
            continue
        host, _, port = name[:-5].rpartition("_")
        where = host_port(ip if host == "ip" else host, port)
        try:
            items = load_testssl(os.path.join(folder, name))
        except (OSError, ValueError):
            continue
        # One entry per certificate the server presented: ids end with "<hostCert#1>", "<hostCert#2>"...
        server_certs = {}
        for item in items:
            row = {"id": str(item.get("id", "")), "severity": str(item.get("severity", "")),
                   "finding": clean(item.get("finding", ""))}
            base = row["id"].split(" ")[0]
            if base in TLS_ATTACKS:
                attacks.append((where, row))
            elif row["severity"] == "WARN":
                skipped.append((where, row))
            elif row["severity"] in ("LOW", "MEDIUM") and not base.startswith(("cipher-", "cipher_order-")):
                lower.append((where, row))
            if base in CERT_FIELDS:
                server_certs.setdefault(row["id"][len(base):].strip(), {}).setdefault(base, row["finding"])
        for cert in server_certs.values():
            if cert.get("cert_fingerprintSHA256"):
                entry = certs.setdefault(cert["cert_fingerprintSHA256"], {**cert, "where": []})
                if where not in entry["where"]:
                    entry["where"].append(where)
    order = {name: index for index, name in enumerate(TLS_ATTACKS)}
    attack_groups = group_rows(attacks)
    attack_groups.sort(key=lambda g: (order.get(g["id"].split(" ")[0], 99), g["severity"] == "OK"))
    return {"attacks": attack_groups, "lower": group_rows(lower), "skipped": group_rows(skipped),
            "certs": list(certs.values())}


def nuclei_runs(path):
    """The nuclei log lines that say how much was tested, as nuclei wrote them."""
    runs = []
    folder = os.path.join(path, "nuclei")
    for name in sorted(os.listdir(folder)) if os.path.isdir(folder) else []:
        if not name.endswith(".log"):
            continue
        host, _, port = name[:-4].rpartition("_")
        lines = []
        try:
            with open(os.path.join(folder, name), errors="replace") as handle:
                for line in handle:
                    if re.search(r"Templates loaded for current scan|Scan completed in|unresponsive", line):
                        lines.append(clean(re.sub(r"\x1b\[[0-9;]*m", "", line)))
        except OSError:
            pass
        runs.append({"site": f"{host}:{port}", "lines": lines})
    return runs


def web_sites(path, failed):
    sites = []
    folder = os.path.join(path, "nuclei")
    for name in sorted(os.listdir(folder)) if os.path.isdir(folder) else []:
        if not name.endswith(".jsonl"):
            continue
        host, _, port = name[:-6].rpartition("_")
        matches = []
        try:
            for item in read_nuclei(os.path.join(folder, name)):
                info = item.get("info") or {}
                matches.append({
                    "severity": str(info.get("severity", "")).upper(),
                    "name": clean(info.get("name", "")),
                    "url": clean(item.get("matched-at", "")),
                })
        except (OSError, ValueError):
            pass
        sites.append({"name": host, "port": port, "matches": matches,
                      "completed": f"failed/web/{host}/{port}" not in failed})
    return sites


def checksums(path, skip):
    files = []
    for root, dirs, names in os.walk(path):
        dirs.sort()
        for name in sorted(names):
            full = os.path.join(root, name)
            relative = os.path.relpath(full, path)
            # Both are written from this data, after the hashes.
            if relative in skip:
                continue
            digest = hashlib.sha256()
            with open(full, "rb") as handle:
                for chunk in iter(lambda: handle.read(1 << 16), b""):
                    digest.update(chunk)
            files.append({"file": relative, "sha256": digest.hexdigest()})
    return files


def port_services(ports, methods=None):
    """Maps "25" to "smtp, Postfix smtpd" for TCP ports, as nmap recognised them."""
    methods = methods or {}
    services = {}
    for row in ports:
        if row["port"].endswith("/tcp"):
            label = row["service"] if row["detail"] in ("", "-") else f"{row['service']}, {row['detail']}"
            # nmap only named it after the port number, it did not recognise it.
            if methods.get(row["port"], {}).get("method") == "table":
                label += ", guessed from the port number"
            services[row["port"].split("/")[0]] = label
    return services


def group_findings(findings, services=None):
    """Merges findings with the same check and the exact same tool message, and lists where each was seen."""
    services = services or {}
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
    for group in groups.values():
        # Same order as "where", so the PDF can print the service next to each place.
        group["services"] = [services.get(place.rpartition(":")[2], "") for place in group["where"]]
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
    for name in ("operator", "authorization", "scanner", "source", "previous", "keep_months"):
        data.setdefault(name, "")
    data["changes"] = [row[0] for row in data["changes"]]
    data["notes"] = [row[0] for row in data["notes"]]
    data["checks"] = [dict(zip(("mode", "name", "port"), row[0].split())) for row in data["checks"]]
    data["versions"] = [{"tool": row[0], "version": row[1] if len(row) > 1 else ""} for row in data["versions"]]
    data["accepted"] = [dict(zip(("pattern", "count", "until", "reason"), row)) for row in data["accepted"]]
    # The attention text can say that an acceptance has expired, findings.tsv does not.
    attention = {row[0]: row[1] if len(row) > 1 else "" for row in data.pop("attention")}
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
        key = row[0]
        text = attention.get(key) or (row[1] if len(row) > 1 else "")
        severity = re.match(r"(?:testssl|nuclei) (\w+) on ", text)
        data["findings"].append({
            "key": key,
            "category": key.split("/")[0],
            "text": text,
            "severity": severity.group(1).upper() if severity else "",
            "state": "open" if key in attention else "accepted",
        })
    data["nmap"] = nmap_details(path)
    services = port_services(data["ports"], data["nmap"]["services"])
    data["groups"] = group_findings(data["findings"], services)
    # TCP only, like the text report.
    try:
        data["vulners"] = vulners_cves(os.path.join(path, "nmap.xml"))
        data["vulners_summary"] = vulners_summary(data["vulners"])
    except (OSError, ValueError, ET.ParseError):
        data["vulners"] = []
        data["vulners_summary"] = []
    failed = {f["key"] for f in data["findings"] if f["category"] == "failed"}
    data["tls"] = tls_endpoints(path, data.get("ip", ""), failed)
    for endpoint in data["tls"]:
        endpoint["service"] = services.get(endpoint["port"], "")
    data["ssh"] = ssh_servers(path)
    data["web"] = web_sites(path, failed)
    data["web_runs"] = nuclei_runs(path)
    data["tls_details"] = tls_details(path, data.get("ip", ""))
    for port in data["ports"]:
        port.update(data["nmap"]["services"].get(port["port"], {"method": "", "conf": "", "cpe": []}))
    # A check that failed before writing its output file still gets a "not completed" row.
    for key in sorted(failed):
        parts = key.split("/")
        if len(parts) != 4 or parts[1] not in ("tls", "web"):
            continue
        table = data["tls"] if parts[1] == "tls" else data["web"]
        if not any(row["name"] == parts[2] and row["port"] == parts[3] for row in table):
            table.append({"name": parts[2], "port": parts[3], "completed": False, "matches": [], "protocols": [],
                          "grade": "", "grade_severity": "", "subject": "", "trust": "", "trust_severity": "",
                          "expires": "", "days": ""})
    data["files"] = checksums(path, {"report.json", data.get("pdf", "")})
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
