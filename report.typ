// PDF report for the owner of a target, rendered by typst from report.json.
// external-scan runs: typst compile --root / --input data=<report.json> report.typ REPORT_<label>_<date>.pdf
#let data = json(sys.inputs.data)

#let strings = (
  kicker: "Security report",
  title: "External exposure scan",
  subtitle: "What this address shows to the Internet",
  confidential: "Confidential, for the owner of the address only",
  not-set: "not set in the configuration",
  empty: "None.",
  unknown: "unknown",
  status-OK: "OK",
  status-ATTENTION: "Attention",
  status-ERROR: "Error",
  status-text-OK: "Nothing needs action. The findings, if any, are known risks accepted by the owner.",
  status-text-ATTENTION: "Some points need a look: a new open port, or a finding that is not accepted yet.",
  status-text-ERROR: "The scan did not complete. This report is partial.",
  fig-ports: "open ports",
  fig-open: "points to fix",
  fig-accepted: "accepted risks",
  fig-new: "new ports",
  scan-date: "Scan date",
  operator: "Performed by",
  authorization: "Authorization",
  generated: "Report generated",
  summary: "Summary",
  summary-intro: "This scan looks at the address from the Internet, without any login. Each problem found is a finding. A finding is either to fix, or accepted by the owner with a reason and a review date.",
  category: "Category",
  to-fix: "To fix",
  accepted: "Accepted",
  scope: "Scope and method",
  who: "Who",
  when: "When",
  what: "What",
  how: "How",
  target: "Target",
  scanner: "Scanning machine",
  source: "Local source address",
  start: "Start",
  end: "End",
  duration: "Duration",
  minutes: "min",
  previous: "Previous scan",
  first-scan: "none, this scan is the baseline",
  tcp: "TCP ports",
  tcp-all: "all, 1 to 65535",
  udp: "UDP ports",
  udp-none: "not scanned",
  udp-skipped: "not scanned, see the notes",
  names: "Names tested",
  names-none: "no name, the bare address only",
  names-not-run: "none, the port scan did not finish",
  not-completed: "not completed",
  web-scan: "Web application scan",
  on: "yes",
  off: "no",
  scan-type: "Port scan",
  tools: "Tools and versions",
  steps: "Steps of the scan",
  step-nmap: "Find every open TCP port and the service behind it with nmap. Compare them with the previous scan.",
  step-tls: "Check the certificates and the TLS settings of each encrypted service with testssl.sh.",
  step-ssh: "Check the SSH algorithms with ssh-audit, and ask the server which login methods it accepts, without trying any password.",
  step-web: "Scan each web site with nuclei, critical and high templates only, without intrusive or denial of service tests, 20 requests per second at most.",
  step-compare: "Compare the findings with the previous scan and with the risks accepted by the owner.",
  limits: "This scan shows the exposure at one point in time, seen from one address on the Internet. It does not log in, does not try passwords and does not exploit anything. It does not replace a full audit or a penetration test.",
  changes: "What changed",
  changes-since: "since",
  open-findings: "Points to fix",
  open-findings-intro: "Findings that are not accepted. Findings with the same check and the same message are on one line, with the places where they were seen. The message is the one of the tool.",
  check: "Check",
  seen-on: "Seen on:",
  detail: "Detail",
  accepted-risks: "Accepted risks",
  accepted-intro: "Risks the owner keeps on purpose, with the reason. They come back in the points to fix after the review date.",
  rule: "Rule",
  count: "Findings",
  until: "Review on",
  reason: "Reason",
  ports: "Open ports",
  ports-intro: "Ports that answer from the Internet, with the service recognised. A sensitive port is a remote access, admin, database or file sharing port.",
  port: "Port",
  service: "Service",
  sensitive: "sensitive",
  tls: "Encrypted services (TLS)",
  tls-intro: "One line per name and port tested. The grade, the trust message and their colors come from testssl.sh.",
  name: "Name",
  grade: "Grade",
  protocols: "Protocols",
  certificate: "Certificate",
  expires: "Expires",
  days-left: "days left",
  ssh: "SSH",
  ssh-intro: "Weak algorithms are the ones ssh-audit rates as failed. Login methods are in the points to fix when passwords are accepted.",
  software: "Software",
  weak: "Weak algorithms",
  warnings: "Warnings",
  cves: "Known CVEs",
  web: "Web applications",
  web-intro: "Matches of the nuclei templates on each web site.",
  site: "Site",
  severity: "Severity",
  match: "Match",
  no-match: "no match",
  vulners: "Known vulnerabilities by version",
  vulners-all: "Known vulnerabilities by version, every entry",
  vulners-intro: "Entries that the nmap vulners script lists for the version the service announces, as it gives them. The installed package was not checked. They do not change the status.",
  vulners-summary-intro: "Count per port of the entries the nmap vulners script lists for the version the service announces. The installed package was not checked. They do not change the status. Every entry is in the technical annex.",
  vid: "ID",
  vtype: "Type",
  cvss: "CVSS",
  exploit: "Exploit known to vulners",
  san: "Also valid for:",
  not-open: "Ports not open",
  not-open-value: "ports, state",
  why-not-open: "reason",
  udp-hidden: "For UDP, nmap reports a port that does not answer as open|filtered: it cannot tell closed from open. Only the UDP ports that answered are in the open ports list.",
  reverse-dns: "Reverse DNS",
  identified: "Identified",
  method-probed: "probed",
  method-table: "guessed from the port number",
  confidence: "confidence",
  filter-note: "testssl results are shown here when testssl rates them HIGH or CRITICAL. Its LOW and MEDIUM results are in the technical annex, and its results per cipher suite only in the raw files.",
  annex-part: "Technical annex",
  annex-part-intro: "The rest of the data of this scan, as the tools gave it. Two kinds of testssl results are not in this PDF: the ones testssl rates INFO or OK, apart from the attacks tested below, and its results per cipher suite. They are in the raw files of the target folder, listed with their SHA-256 at the end of this annex.",
  annex-kept: "The raw files stay on the scanning machine for",
  annex-kept-unit: "months after the scan.",
  attacks: "Known TLS attacks tested",
  attacks-intro: "Each attack testssl tested, with its result. One line per result, with the places where it was seen.",
  lower: "Lower severity results",
  lower-intro: "testssl results rated LOW or MEDIUM, except the results per cipher suite.",
  skipped: "Tests that could not run",
  skipped-intro: "testssl warnings: these tests did not run, so their result is unknown.",
  certs: "Certificates",
  certs-intro: "One line per certificate, as testssl read it, with the places where it was presented.",
  issuer: "Issuer",
  key: "Key",
  signature: "Signature",
  valid-from: "Valid from",
  fingerprint: "SHA-256 fingerprint",
  result: "Result",
  check-id: "Test",
  where: "Where",
  ssh-details: "Algorithms and host key",
  host-key: "Host key",
  ssh-notes: "Notes from ssh-audit",
  web-runs: "What nuclei ran",
  total: "Entries",
  high: "Score 7.0 or more",
  highest: "Highest score",
  notes: "Notes",
  notes-intro: "Checks that were skipped or could not finish.",
  annex: "Raw results",
  annex-intro: "Every raw result of this scan is kept on the scanning machine. Their SHA-256 fingerprints prove that they were not changed after the report.",
  file: "File",
  cat-tls: "TLS settings",
  cat-cert: "Certificate expiry",
  cat-ssh: "SSH algorithms",
  cat-sshpw: "SSH login",
  cat-sensitive: "Sensitive port open",
  cat-dns: "DNS name",
  cat-web: "Web application",
  cat-failed: "Test not completed",
)
#let t(key) = strings.at(key)

#let ink = rgb("#1f2933")
#let muted = rgb("#616e7c")
#let accent = rgb("#1d4e89")
#let rule-color = rgb("#d5dbe2")
#let header-fill = rgb("#edf1f5")
#let status-colors = (OK: rgb("#2f855a"), ATTENTION: rgb("#c05621"), ERROR: rgb("#c53030"))
// Colors only show the severity the tool itself gave.
#let severity-colors = (CRITICAL: rgb("#c53030"), HIGH: rgb("#c05621"), MEDIUM: rgb("#b7791f"), LOW: rgb("#4a6fa5"), OK: rgb("#2f855a"))
#let tool-color(severity) = severity-colors.at(severity, default: ink)

#let or-default(value, fallback) = if value == none or value == "" { fallback } else { value }
#let mono(value) = text(font: "DejaVu Sans Mono", size: 7.5pt, value.replace("/", "/\u{200B}"))
#let place-list(g) = g.where.join(", ")
// Brackets an IPv6 address like the rest of the report, so the port stays apart.
#let place(name, port) = if name.contains(":") { "[" + name + "]:" + port } else { name + ":" + port }
#let empty-line = text(fill: muted, style: "italic", t("empty"))
#let intro(body) = par(text(fill: muted, size: 9.5pt, body))
#let pill(label, color) = box(
  fill: color.lighten(85%), stroke: 0.5pt + color, radius: 2pt, inset: (x: 4pt, y: 1.5pt), baseline: 15%,
  text(size: 7.5pt, weight: "bold", fill: color, label),
)

#let data-table(columns, header, rows) = {
  if rows.len() == 0 { return empty-line }
  set text(size: 8.5pt)
  table(
    columns: columns,
    stroke: (x, y) => (bottom: 0.5pt + rule-color),
    inset: (x: 5pt, y: 4pt),
    align: left + top,
    fill: (x, y) => if y == 0 { header-fill },
    table.header(..header.map(h => text(weight: "bold", h))),
    ..rows.flatten(),
  )
}

#let key-values(rows) = table(
  columns: (32%, 1fr),
  stroke: (x, y) => (bottom: 0.5pt + rule-color),
  inset: (x: 5pt, y: 4.5pt),
  align: left + top,
  ..rows.map(((key, value)) => (text(fill: muted, key), value)).flatten(),
)

#let open-findings = data.findings.filter(f => f.state == "open")
#let accepted-findings = data.findings.filter(f => f.state == "accepted")
#let status = data.status
#let status-color = status-colors.at(status)

#set document(title: t("title") + " " + data.label)
#set text(font: "Libertinus Serif", size: 10.5pt, fill: ink, lang: "en")
#set par(leading: 0.62em, spacing: 0.9em)
#set heading(numbering: "1.")
#show heading.where(level: 1): it => {
  v(1em, weak: true)
  block(below: 0.7em, {
    text(size: 15pt, weight: "bold", fill: accent, it)
    v(-0.5em)
    line(length: 100%, stroke: 0.6pt + rule-color)
  })
}
#show heading.where(level: 2): it => block(above: 1em, below: 0.5em, text(size: 11.5pt, weight: "bold", fill: ink, it))

#set page(
  paper: "a4",
  margin: (x: 2cm, top: 2.3cm, bottom: 2.2cm),
  header: context {
    if counter(page).get().first() > 1 {
      set text(size: 8pt, fill: muted)
      [#t("title") · #data.label (#data.ip) #h(1fr) #data.date]
      v(-0.6em)
      line(length: 100%, stroke: 0.4pt + rule-color)
    }
  },
  footer: context {
    set text(size: 8pt, fill: muted)
    [#t("confidential") #h(1fr) #counter(page).display("1 / 1", both: true)]
  },
)

#v(2.5cm)
#text(size: 10pt, fill: muted, tracking: 1.5pt, upper(t("kicker")))
#v(0.2em)
#text(size: 28pt, weight: "bold", fill: accent, t("title"))
#v(-0.3em)
#text(size: 12pt, fill: muted, t("subtitle"))
#v(1.4cm)
#text(size: 17pt, weight: "bold", data.label)
#linebreak()
#text(size: 12pt, font: "DejaVu Sans Mono", fill: muted, data.ip)
#v(1cm)
#block(
  width: 100%, fill: status-color.lighten(90%), stroke: (left: 4pt + status-color), inset: 12pt, radius: 2pt,
  grid(
    columns: (auto, 1fr), gutter: 14pt, align: horizon,
    box(fill: status-color, radius: 3pt, inset: (x: 12pt, y: 7pt),
      text(size: 13pt, weight: "bold", fill: white, upper(t("status-" + status)))),
    text(size: 10.5pt, t("status-text-" + status)),
  ),
)
#v(0.8cm)
#grid(
  columns: (1fr, 1fr, 1fr, 1fr), gutter: 10pt,
  ..(
    (data.ports.len(), t("fig-ports"), ink),
    (open-findings.len(), t("fig-open"), if open-findings.len() > 0 { status-colors.ATTENTION } else { ink }),
    (accepted-findings.len(), t("fig-accepted"), ink),
    (int(data.new_ports), t("fig-new"), if int(data.new_ports) > 0 { status-colors.ATTENTION } else { ink }),
  ).map(((number, label, color)) => block(
    width: 100%, stroke: 0.6pt + rule-color, radius: 3pt, inset: 10pt,
    align(center)[#text(size: 22pt, weight: "bold", fill: color, str(number)) \ #text(size: 8.5pt, fill: muted, label)],
  )),
)
#v(1fr)
#key-values((
  (t("scan-date"), data.date),
  (t("operator"), or-default(data.operator, text(style: "italic", t("not-set")))),
  (t("authorization"), or-default(data.authorization, text(style: "italic", t("not-set")))),
  (t("generated"), data.generated),
))
#pagebreak()

= #t("summary")
#t("summary-intro")

#let categories = data.findings.map(f => f.category).dedup()
#data-table(
  (1fr, auto, auto),
  (t("category"), t("to-fix"), t("accepted")),
  categories
    .map(c => (
      t("cat-" + c),
      {
        let n = open-findings.filter(f => f.category == c).len()
        if n > 0 { text(weight: "bold", fill: status-colors.ATTENTION, str(n)) } else { "0" }
      },
      str(accepted-findings.filter(f => f.category == c).len()),
    )),
)

= #t("scope")
== #t("who")
#key-values((
  (t("operator"), or-default(data.operator, text(style: "italic", t("not-set")))),
  (t("authorization"), or-default(data.authorization, text(style: "italic", t("not-set")))),
  (t("scanner"), or-default(data.scanner, t("unknown"))),
  (t("source"), or-default(data.source, t("unknown"))),
))
== #t("when")
#key-values((
  (t("start"), data.started),
  (t("end"), data.finished),
  (t("duration"), str(data.duration_minutes) + " " + t("minutes")),
  (t("previous"), or-default(data.previous, t("first-scan"))),
))
== #t("what")
#key-values((
  (t("target"), [#data.label · #mono(data.ip)]),
  (t("tcp"), t("tcp-all")),
  (t("udp"), if data.udp_ports == "" { t("udp-none") } else if data.udp_done != "1" {
    t("udp-skipped")
  } else { data.udp_ports.replace(",", ", ") }),
  (t("names"), if data.nmap_done != "1" { t("names-not-run") } else if data.checks.len() == 0 {
    t("names-none")
  } else {
    data.checks.map(c => [#c.name:#c.port (#c.mode)]).join(linebreak())
  }),
  (t("web-scan"), if data.web_ran == "1" { t("on") } else { t("off") }),
  (t("not-open"), if data.nmap.not_open.len() == 0 { t("empty") } else {
    data.nmap.not_open.map(n => [#n.count #n.proto #t("not-open-value") #n.state, #t("why-not-open") #n.reason]).join(linebreak())
  }),
  (t("reverse-dns"), if data.nmap.hostnames.len() == 0 { t("empty") } else { data.nmap.hostnames.join(linebreak()) }),
))
#if data.udp_done == "1" { intro(t("udp-hidden")) }
#block(fill: header-fill, inset: 9pt, radius: 2pt, width: 100%, text(size: 9pt, t("limits")))

= #t("changes") #if data.previous != "" [#t("changes-since") #data.previous]
#if data.changes.len() == 0 { empty-line } else {
  set text(size: 9pt)
  list(..data.changes.map(c => c))
}

= #t("open-findings")
#intro(t("open-findings-intro"))
#intro(t("filter-note"))
#data-table(
  (30%, 1fr),
  (t("check"), t("detail")),
  data
    .groups
    .filter(g => g.state == "open")
    .map(g => (
      [#mono(g.check) \ #text(size: 7.5pt, fill: muted, t("cat-" + g.category))],
      [
        #if g.severity in severity-colors { pill(g.severity, severity-colors.at(g.severity)) } #g.message
        #if g.where.len() > 0 [
          \ #text(size: 8pt, fill: muted)[#t("seen-on") #g.where.zip(g.services).map(((w, s)) => if s == "" { w } else { w + " (" + s + ")" }).join(", ")]
        ]
      ],
    )),
)

= #t("accepted-risks")
#intro(t("accepted-intro"))
#data-table(
  (30%, auto, auto, 1fr),
  (t("rule"), t("count"), t("until"), t("reason")),
  data.accepted.map(a => (mono(a.pattern), a.count, a.until, a.reason)),
)

= #t("ports")
#intro(t("ports-intro"))
#data-table(
  (auto, auto, 1fr, auto),
  (t("port"), t("service"), t("detail"), t("identified")),
  data.ports.map(p => (
    [#mono(p.port) #if p.sensitive { pill(t("sensitive"), status-colors.ATTENTION) }],
    p.service,
    [#if p.detail != "-" [#p.detail] #if p.cpe.len() > 0 [\ #text(size: 7pt, fill: muted, p.cpe.join(", "))]],
    text(size: 7.5pt, fill: muted, if p.method == "table" { t("method-table") } else if p.method == "" { "" } else {
      t("method-probed") + ", " + t("confidence") + " " + p.conf + "/10"
    }),
  )),
)

= #t("tls")
#intro(t("tls-intro"))
#data-table(
  (1fr, auto, auto, 1.1fr, auto),
  (t("name"), t("grade"), t("protocols"), t("certificate"), t("expires")),
  data.tls.map(e => (
    [#place(e.name, e.port) #if e.service != "" [\ #text(size: 7.5pt, fill: muted, e.service)] #if not e.completed [\ #pill(t("not-completed"), status-colors.ERROR)]],
    text(weight: "bold", fill: tool-color(e.grade_severity), e.grade),
    e.protocols.join(", "),
    [#e.subject #if e.san != "" [\ #text(size: 7.5pt, fill: muted)[#t("san") #e.san]] #if e.trust != "" [\ #text(size: 7.5pt, fill: tool-color(e.trust_severity), e.trust)]],
    if e.expires == "" { "" } else {
      [#e.expires.slice(0, calc.min(10, e.expires.len())) \ #text(size: 7.5pt, fill: if type(e.days) == int and e.days < int(data.cert_warn_days) {
        status-colors.ERROR
      } else { muted }, [#e.days #t("days-left")])]
    },
  )),
)

#if data.tls_details.skipped.len() > 0 [
  == #t("skipped")
  #intro(t("skipped-intro"))
  #data-table(
    (auto, 1fr, 1fr),
    (t("check-id"), t("result"), t("where")),
    data.tls_details.skipped.map(g => (mono(g.id), [#g.severity #g.finding], text(size: 7.5pt, fill: muted, place-list(g)))),
  )
]
= #t("ssh")
#intro(t("ssh-intro"))
#data-table(
  (auto, 1fr, auto, auto, auto),
  (t("port"), t("software"), t("weak"), t("warnings"), t("cves")),
  data.ssh.map(s => if not s.completed {
    (s.port, pill(t("not-completed"), status-colors.ERROR), "", "", "")
  } else {
    (
      s.port,
      s.software,
      if s.fail > 0 { text(weight: "bold", fill: status-colors.ATTENTION, str(s.fail)) } else { "0" },
      str(s.warn),
      str(s.cves),
    )
  }),
)
#if data.web_ran == "1" or data.web.len() > 0 [
  = #t("web")
  #intro(t("web-intro"))
  #data-table(
    (30%, auto, 1fr),
    (t("site"), t("severity"), t("match")),
    data.web.map(s => {
      let rows = s.matches.map(m => (
        [#place(s.name, s.port)],
        if m.severity in severity-colors { pill(m.severity, severity-colors.at(m.severity)) } else { m.severity },
        [#m.name \ #mono(m.url)],
      ))
      // A site that stopped answering may have more matches than listed, so it never reads as clean.
      if not s.completed {
        rows.push(([#place(s.name, s.port)], "", pill(t("not-completed"), status-colors.ERROR)))
      } else if rows.len() == 0 {
        rows.push(([#place(s.name, s.port)], "", text(fill: muted, t("no-match"))))
      }
      rows
    }).flatten().chunks(3),
  )
]

= #t("vulners")
#intro(t("vulners-summary-intro"))
#data-table(
  (auto, auto, auto, 1fr),
  (t("port"), t("total"), t("high"), t("highest")),
  data.vulners_summary.map(v => (mono(v.port), str(v.total), str(v.high), v.max)),
)

= #t("notes")
#intro(t("notes-intro"))
#if data.notes.len() == 0 { empty-line } else {
  set text(size: 9pt)
  list(..data.notes.map(n => n))
}

#pagebreak()
#heading(numbering: none, t("annex-part"))
#intro[#t("annex-part-intro") #if data.keep_months != "" [#t("annex-kept") #data.keep_months #t("annex-kept-unit")]]
#counter(heading).update(0)
#set heading(numbering: "A.1.")

= #t("how")
#key-values((
  (t("scan-type"), [#data.scan_type \ #mono("nmap " + data.nmap_args)]),
  (t("tools"), data.versions.map(v => [#v.tool #or-default(v.version, t("unknown"))]).join(linebreak())),
))
#v(0.4em)
*#t("steps")*
#if data.nmap_done != "1" { enum(t("step-nmap")) } else {
  enum(
    t("step-nmap"),
    t("step-tls"),
    t("step-ssh"),
    ..if data.web_ran == "1" { (t("step-web"),) },
    t("step-compare"),
  )
}

= #t("attacks")
#intro(t("attacks-intro"))
#data-table(
  (auto, 1fr, 1fr),
  (t("check-id"), t("result"), t("where")),
  data.tls_details.attacks.map(g => (
    mono(g.id),
    [#if g.severity in severity-colors { pill(g.severity, severity-colors.at(g.severity)) } else { g.severity } #g.finding],
    text(size: 7.5pt, fill: muted, place-list(g)),
  )),
)
= #t("lower")
#intro(t("lower-intro"))
#data-table(
  (auto, 1fr, 1fr),
  (t("check-id"), t("result"), t("where")),
  data.tls_details.lower.map(g => (
    mono(g.id),
    [#pill(g.severity, severity-colors.at(g.severity, default: ink)) #g.finding],
    text(size: 7.5pt, fill: muted, place-list(g)),
  )),
)

= #t("certs")
#intro(t("certs-intro"))
#data-table(
  (1fr, 1fr, 1fr, 1fr),
  (t("name"), t("issuer"), t("key"), t("fingerprint")),
  data.tls_details.certs.map(c => (
    [#c.at("cert_commonName", default: "") \ #text(size: 7.5pt, fill: muted, c.where.join(", "))],
    [#c.at("cert_caIssuers", default: "") \ #text(size: 7.5pt, fill: muted)[#t("valid-from") #c.at("cert_notBefore", default: "")]],
    [#c.at("cert_keySize", default: "") \ #text(size: 7.5pt, fill: muted, c.at("cert_signatureAlgorithm", default: ""))],
    // Breaks every 16 hex digits so the fingerprint fits the column.
    mono(c.at("cert_fingerprintSHA256", default: "").clusters().chunks(16).map(x => x.join()).join("\u{200B}")),
  )),
)

#for s in data.ssh.filter(s => s.completed) [
  = #t("ssh-details") (#s.port)
  #key-values((
    (t("host-key"), s.fingerprints.map(f => mono(f)).join(linebreak())),
    ..("kex", "key", "enc", "mac").map(k => (k, text(size: 8pt, s.algorithms.at(k).join(", ")))),
    ..if s.notes.len() > 0 { ((t("ssh-notes"), text(size: 8pt, s.notes.join(linebreak()))),) },
  ))
]

#if data.web_runs.len() > 0 [
    = #t("web-runs")
    #key-values(data.web_runs.map(r => (r.site, text(size: 8pt, r.lines.join(linebreak())))))
]

= #t("vulners-all")
#intro(t("vulners-intro"))
#data-table(
  (auto, auto, auto, auto, 1fr),
  (t("port"), t("vid"), t("vtype"), t("cvss"), t("exploit")),
  data.vulners.map(v => (mono(v.port), mono(v.id), v.type, v.cvss, v.exploit)),
)

= #t("annex")
#intro(t("annex-intro"))
#{
  set text(size: 7.5pt)
  table(
    columns: (auto, 1fr),
    stroke: (x, y) => (bottom: 0.4pt + rule-color),
    inset: (x: 4pt, y: 3pt),
    fill: (x, y) => if y == 0 { header-fill },
    table.header(text(weight: "bold", t("file")), text(weight: "bold", "SHA-256")),
    ..data.files.map(f => (mono(f.file), text(font: "DejaVu Sans Mono", size: 6.5pt, f.sha256))).flatten(),
  )
}
