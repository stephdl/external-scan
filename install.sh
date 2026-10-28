#!/usr/bin/env bash
# Install or update external-scan. Safe to run again at any time.
# Run it as root from the clone in /var/lib/external-scan.
set -euo pipefail

TESTSSL_REF=v3.2.4
SSH_AUDIT_REF=v3.3.0
# external-scan greps nuclei's "found unresponsive" warning: check it still exists before a bump.
NUCLEI_VERSION=3.11.1
NUCLEI_SHA256_amd64=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
NUCLEI_SHA256_arm64=8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07
# report.typ is written for this version: check it still renders before a bump.
TYPST_VERSION=0.13.1
TYPST_SHA256_x86_64=7d214bfeffc2e585dc422d1a09d2b144969421281e8c7f5d784b65fc69b5673f
TYPST_SHA256_aarch64=4f5b7ee6e57fb639019ee0f6bffcf940edad228ede6ff5269a9f05a1544ceed4
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
        apt-get install -y -q nmap openssh-client git python3 curl openssl bind9-dnsutils bsdextrautils procps ca-certificates xz-utils iproute2 socat
        apt-get install -y -q ndiff || say "ndiff is not available, ndiff.txt will not be written"
    elif command -v dnf >/dev/null; then
        dnf install -y -q nmap openssh-clients git python3 curl openssl bind-utils util-linux procps-ng ca-certificates xz iproute socat
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

install_nuclei() {
    local dir=$BASE/tools/nuclei arch sum
    case $(uname -m) in
        x86_64) arch=amd64 sum=$NUCLEI_SHA256_amd64 ;;
        aarch64) arch=arm64 sum=$NUCLEI_SHA256_arm64 ;;
        *) die "no nuclei build for $(uname -m)" ;;
    esac
    if [[ -x $dir/nuclei && $(cat "$dir/VERSION" 2>/dev/null) == "$NUCLEI_VERSION" ]]; then
        say "nuclei $NUCLEI_VERSION already installed"
        return
    fi
    say "fetching nuclei $NUCLEI_VERSION"
    # Global, not local: the EXIT trap runs after the function is gone, also when set -e stops the script.
    zip=$(mktemp)
    trap 'rm -f "$zip"' EXIT
    curl -fsSL -o "$zip" \
        "https://github.com/projectdiscovery/nuclei/releases/download/v$NUCLEI_VERSION/nuclei_${NUCLEI_VERSION}_linux_$arch.zip"
    echo "$sum  $zip" | sha256sum -c --quiet - || die "nuclei download does not match its checksum"
    rm -rf "$dir"
    mkdir -p "$dir"
    # python3 is already installed, so no need for unzip.
    python3 -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extract("nuclei", sys.argv[2])' "$zip" "$dir"
    chmod 755 "$dir/nuclei"
    echo "$NUCLEI_VERSION" >"$dir/VERSION"
}

# Renders the PDF report. One static binary with its own fonts, so the PDF looks the same on every distribution.
install_typst() {
    local dir=$BASE/tools/typst arch sum
    case $(uname -m) in
        x86_64) arch=x86_64 sum=$TYPST_SHA256_x86_64 ;;
        aarch64) arch=aarch64 sum=$TYPST_SHA256_aarch64 ;;
        *) die "no typst build for $(uname -m)" ;;
    esac
    if [[ -x $dir/typst && $(cat "$dir/VERSION" 2>/dev/null) == "$TYPST_VERSION" ]]; then
        say "typst $TYPST_VERSION already installed"
        return
    fi
    say "fetching typst $TYPST_VERSION"
    archive=$(mktemp)
    trap 'rm -f "${zip:-}" "$archive"' EXIT
    curl -fsSL -o "$archive" \
        "https://github.com/typst/typst/releases/download/v$TYPST_VERSION/typst-$arch-unknown-linux-musl.tar.xz"
    echo "$sum  $archive" | sha256sum -c --quiet - || die "typst download does not match its checksum"
    rm -rf "$dir"
    mkdir -p "$dir"
    tar -xJf "$archive" -C "$dir" --strip-components 1 "typst-$arch-unknown-linux-musl/typst"
    chmod 755 "$dir/typst"
    echo "$TYPST_VERSION" >"$dir/VERSION"
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
install_nuclei
install_typst

say "setting permissions"
# Only results/ and cache/ are writable by the scan user, so a compromised tool cannot change the code or the targets.
find "$BASE" \( -path "$BASE/results" -o -path "$BASE/cache" \) -prune -o -exec chown root:root {} +
chmod 755 "$BASE" "$BASE/external-scan" "$BASE/parse.py"
install -d -o "$SCAN_USER" -g "$SCAN_USER" -m 750 "$BASE/results"
# nuclei templates, downloaded again at each scan.
install -d -o "$SCAN_USER" -g "$SCAN_USER" -m 750 "$BASE/cache"
chown -R "$SCAN_USER:$SCAN_USER" "$BASE/cache"
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
