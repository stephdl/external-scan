#!/usr/bin/env bash
# Install or update external-scan. Safe to run again at any time.
# Run it as root from the clone in /var/lib/external-scan.
set -euo pipefail

TESTSSL_REF=v3.2.4
SSH_AUDIT_REF=v3.3.0
SCAN_USER=external-scan
INSTALL_DIR=/var/lib/external-scan
BASE=$(dirname "$(readlink -f "$0")")

say() { echo "==> $*"; }
die() { echo "install.sh: $*" >&2; exit 1; }

(( EUID == 0 )) || die "run me as root"
# The systemd units use absolute paths, so the clone must live here.
[[ $BASE == "$INSTALL_DIR" ]] || die "clone the repository into $INSTALL_DIR, not $BASE"

install_packages() {
    if command -v apt-get >/dev/null; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -q
        apt-get install -y -q nmap git python3 curl openssl bind9-dnsutils bsdextrautils procps ca-certificates
        apt-get install -y -q ndiff || say "ndiff is not available, ndiff.txt will not be written"
    elif command -v dnf >/dev/null; then
        dnf install -y -q nmap git python3 curl openssl bind-utils util-linux procps-ng ca-certificates
        dnf install -y -q ndiff || say "ndiff is not available, ndiff.txt will not be written"
    else
        die "no apt-get or dnf found, install the packages by hand"
    fi
}

git_checkout() {
    local url=$1 dir=$2 ref=$3
    if [[ -d $dir/.git ]]; then
        git -C "$dir" fetch -q --tags origin
    else
        git clone -q "$url" "$dir"
    fi
    git -C "$dir" -c advice.detachedHead=false checkout -q "$ref"
}

say "installing packages"
install_packages

say "checking the nmap vulners script"
nmap --script-help vulners 2>/dev/null | grep -q '^vulners' \
    || die "the nmap vulners script is missing, update nmap or add vulners.nse"

if id "$SCAN_USER" >/dev/null 2>&1; then
    say "user $SCAN_USER already exists"
else
    say "creating system user $SCAN_USER"
    useradd --system --home-dir "$INSTALL_DIR" --no-create-home --shell /usr/sbin/nologin "$SCAN_USER"
fi

say "fetching testssl.sh $TESTSSL_REF and ssh-audit $SSH_AUDIT_REF"
mkdir -p "$BASE/tools"
git_checkout https://github.com/testssl/testssl.sh.git "$BASE/tools/testssl.sh" "$TESTSSL_REF"
git_checkout https://github.com/jtesta/ssh-audit.git "$BASE/tools/ssh-audit" "$SSH_AUDIT_REF"

say "setting permissions"
# Only results/ is writable by the scan user, so a compromised tool cannot change the code or the targets.
find "$BASE" -path "$BASE/results" -prune -o -exec chown root:root {} +
chmod 755 "$BASE" "$BASE/external-scan" "$BASE/parse.py"
install -d -o "$SCAN_USER" -g "$SCAN_USER" -m 750 "$BASE/results"
if [[ -e $BASE/external-scan.conf ]]; then
    say "keeping existing external-scan.conf"
else
    say "creating external-scan.conf from the example, edit it before the first scan"
    cp "$BASE/external-scan.conf.example" "$BASE/external-scan.conf"
fi
chown "root:$SCAN_USER" "$BASE/external-scan.conf"
chmod 640 "$BASE/external-scan.conf"

say "installing systemd units"
# Copied, not linked: SELinux refuses to start a unit file labelled var_lib_t.
for unit in external-scan.service external-scan.timer; do
    rm -f "/etc/systemd/system/$unit"
    install -m 644 "$BASE/systemd/$unit" "/etc/systemd/system/$unit"
done
systemctl daemon-reload

say "done"
echo "The timer is not enabled. After a first manual scan, enable it with:"
echo "  systemctl enable --now external-scan.timer"
