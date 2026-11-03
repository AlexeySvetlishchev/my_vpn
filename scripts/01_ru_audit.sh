#!/usr/bin/env bash
# RU VPS audit, Project Baseline v1.1; target: Ubuntu 24.04 LTS / Bash 5.
# Read-only: no installs, configuration writes, service starts or network probes.
# Run from a trusted local copy on the VPS, only with owner authorization:
#   bash -n scripts/01_ru_audit.sh       # syntax only; does not run the audit
#   bash scripts/01_ru_audit.sh --help
#   sudo bash scripts/01_ru_audit.sh    # fuller visibility; sudo is not automatic
# Optional report file (created by the invoking shell, not by this script):
#   (umask 077; sudo bash scripts/01_ru_audit.sh > ru-audit.txt)
# Metadata: IP/MAC addresses, routes, interface/service names,
# ports, disk mount paths, software versions and resource usage are sensitive.
# Review/redact the report before sharing; do not commit it to the repository.
# VPN configs, keys, process arguments, environment, logs and Docker inspect
# are never requested. Firewall output is a structured summary, not a rule dump:
# comments, log prefixes and arbitrary rule payloads might contain secrets.
# Exit: 0 = all requested probes completed (NOT a security/health verdict),
# 1 = partial report, 2 = usage/unsupported platform. No files are created.

set +x
set -u
set -o pipefail
export LC_ALL=C
export SYSTEMD_PAGER=cat SYSTEMD_COLORS=0
partial=0
reply=''

usage() {
    printf '%s\n' \
        'Usage: bash scripts/01_ru_audit.sh [--help]' \
        'Syntax check: bash -n scripts/01_ru_audit.sh' \
        'Run on Ubuntu 24.04: sudo bash scripts/01_ru_audit.sh' \
        'Root is optional; unavailable probes produce a partial report (exit 1).' \
        'Output: stdout only. No external services, VPN configuration reads or system writes.' \
        'Sensitive metadata: addresses, routes, ports, names, mount paths, versions.' \
        'Firewall summaries omit rule contents; VPN presence does not prove connectivity.'
}

case "${1-}" in
    --help|-h) usage; exit 0 ;;
    '') ;;
    *) usage; exit 2 ;;
esac
if (( $# > 1 )); then usage; exit 2; fi
if [[ ${OSTYPE-} != linux* ]]; then
    printf '%s\n' 'UNSUPPORTED: this audit requires Linux (target Ubuntu 24.04 LTS).'
    exit 2
fi

section() { printf '\n=== %s ===\n' "$1"; }
unavailable() {
    printf '[UNAVAILABLE] %s\n' "$1"
    partial=1
}

# Capture stdout only on success. Never print arbitrary stderr/partial output:
# diagnostics from third-party tools can contain configuration or credentials.
# timeout is standard on Ubuntu; if unavailable, continue without a time limit.
query() {
    local rc
    reply=''
    if ! command -v "$1" >/dev/null 2>&1; then
        unavailable "$1: utility not found"
        return 1
    fi
    if command -v timeout >/dev/null 2>&1; then
        reply=$(timeout -k 2s 15s "$@" 2>/dev/null)
        rc=$?
    else
        reply=$("$@" 2>/dev/null)
        rc=$?
    fi
    if (( rc != 0 )); then
        reply=''
        unavailable "$1: exit $rc (permissions, unsupported operation or timeout; stderr withheld)"
        return 1
    fi
}

show() {
    local label=$1
    shift
    printf '\n-- %s --\n' "$label"
    if query "$@"; then
        printf '%s\n' "${reply:-[empty result]}"
    fi
}

section 'RU VPS read-only audit'
show 'Checked at (UTC)' date -u '+%Y-%m-%dT%H:%M:%SZ'
printf 'Effective UID: %s\n' "$EUID"
printf '%s\n' 'Scope: local host/network namespace only. No connectivity or egress tests.'
printf '%s\n' 'Report contains sensitive infrastructure metadata; review before sharing.'
if (( EUID != 0 )); then
    printf '%s\n' 'NOTE: non-root execution; firewall/VPN/process visibility may be restricted.'
fi
if ! command -v timeout >/dev/null 2>&1; then
    unavailable 'timeout missing: commands have no time limit'
fi

section 'Operating system and resources'
# Parse data rather than sourcing os-release as executable shell code.
show 'OS release (selected fields)' awk -F= \
    '$1 == "PRETTY_NAME" || $1 == "ID" || $1 == "VERSION_ID" {print}' /etc/os-release
show 'Kernel and architecture (no hostname)' uname -srm
show 'CPU' lscpu
show 'RAM and swap' free -h
show 'Block devices (no serial numbers/UUIDs)' lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS
show 'Local filesystem usage (no remote filesystem queries)' df -h -l

section 'Network interfaces and routing'
show 'Interfaces, addresses and MACs' ip -brief address show
# Do not use ip -d: detailed tunnel output may include key material for some kinds.
show 'Link state and MTU' ip -brief link show
show 'IPv4 routes, all tables' ip -4 route show table all
show 'IPv6 routes, all tables' ip -6 route show table all
show 'IPv4 policy rules' ip -4 rule show
show 'IPv6 policy rules' ip -6 rule show
show 'IP forwarding (1 enabled, 0 disabled)' sysctl \
    net.ipv4.ip_forward net.ipv6.conf.all.forwarding
show 'Listening TCP and bound UDP sockets (numeric, no DNS)' ss -H -lntu
printf '%s\n' 'Socket bindings do not prove external reachability through firewall/provider filters.'

section 'Firewall (safe summary; rule contents intentionally omitted)'
# JSON parsing avoids unreliable secret redaction in arbitrary firewall comments.
if command -v python3 >/dev/null 2>&1; then
    if query nft -j list ruleset; then
        if ! printf '%s\n' "$reply" | python3 -c '
import json, sys
data = json.load(sys.stdin)["nftables"]
counts = {k: sum(k in x for x in data) for k in ("table", "chain", "rule", "set", "map")}
print("nftables object counts:", counts)
for item in data:
    if "chain" in item:
        c = item["chain"]
        # Names and arbitrary strings are deliberately excluded.
        family = c.get("family")
        hook = c.get("hook")
        policy = c.get("policy")
        if family in ("ip", "ip6", "inet", "arp", "bridge", "netdev"):
            if hook in ("ingress", "egress", "prerouting", "input", "forward", "output", "postrouting"):
                print("base chain:", family, hook, "policy:", policy if policy in ("accept", "drop") else "unspecified")
' 2>/dev/null; then
            unavailable 'nftables summary: cannot parse JSON'
        fi
    fi
else
    unavailable 'python3 missing: nftables summary skipped to avoid raw rule output'
fi

# Read only already-loaded legacy tables; never trigger module loading.
# nft-backed iptables rules are represented in the nftables summary above.
for family in ip ip6; do
    table_file="/proc/net/${family}_tables_names"
    if [[ ! -r $table_file ]]; then
        printf '%s\n' "Legacy $family tables: not exposed in this namespace."
        continue
    fi
    if ! command -v awk >/dev/null 2>&1; then
        unavailable 'awk missing: legacy firewall summary skipped'
        continue
    fi
    while IFS= read -r table; do
        case "$table" in filter|nat|mangle|raw|security) ;; *) continue ;; esac
        if [[ $family == ip ]]; then tool=iptables-legacy; else tool=ip6tables-legacy; fi
        printf '\n-- %s / %s --\n' "$tool" "$table"
        if query "$tool" -M /bin/true -t "$table" -S; then
            printf '%s\n' "$reply" | awk '
                $1 == "-P" && $2 ~ /^(INPUT|FORWARD|OUTPUT|PREROUTING|POSTROUTING)$/ && $3 ~ /^(ACCEPT|DROP)$/ {print}
                $1 == "-N" {chains++}
                $1 == "-A" {rules++}
                END {printf "User chains: %d; rules: %d\n", chains, rules}'
        fi
    done < "$table_file"
done
printf '%s\n' 'No firewall correctness/fail-closed verdict: packet matching rules are not included.'

section 'VPN and Docker presence'
for tool in docker dockerd wg wg-quick awg awg-quick wireguard-go amneziawg-go; do
    if command -v "$tool" >/dev/null 2>&1; then
        printf '%s: executable present\n' "$tool"
    else
        printf '%s: executable not found in PATH (does not prove absence)\n' "$tool"
    fi
done
show 'Loaded VPN modules (name and use count)' awk \
    '$1 ~ /^(wireguard|amneziawg|tun|ppp_generic|l2tp_core)$/ {print $1, "use_count=" $3}' /proc/modules
show 'WireGuard interface names only' wg show interfaces
show 'AmneziaWG interface names only' awg show interfaces
# Never use wg/awg dump, showconf, private-key, preshared-keys or bare show.
if command -v awk >/dev/null 2>&1; then
    printf '\n-- Known VPN/daemon processes: PID and executable name only --\n'
    if query ps -e -o pid=,comm=; then
        printf '%s\n' "$reply" | awk '
            $2 ~ /^(openvpn|charon|charon-systemd|pluto|xl2tpd|pppd|tailscaled|zerotier-one|wireguard-go|amneziawg-go|dockerd)$/ {print; n++}
            END {if (!n) print "No known VPN/daemon process names observed."}'
    fi
    printf '\n-- Loaded VPN/Docker units: UNIT LOAD ACTIVE SUB --\n'
    if query systemctl --no-pager --plain list-units --all --no-legend --type=service \
        'wg-quick@*' 'awg-quick@*' 'amnezia*' 'openvpn*' 'strongswan*' \
        'ipsec*' 'xl2tpd*' 'tailscaled*' 'zerotier*' 'docker.service'; then
        printf '%s\n' "$reply" | awk 'NF >= 4 {print $1, $2, $3, $4; n++}
            END {if (!n) print "No matching loaded units observed."}'
    fi
else
    unavailable 'awk missing: process and service summaries skipped'
fi

# Do not contact Docker: an inactive socket-activated daemon could be started
# by a read request. Do not follow DOCKER_HOST/context to a remote service.
printf '%s\n' 'Docker containers: not queried (avoids socket activation and remote Docker contexts).'
printf '%s\n' 'Container VPNs and other namespaces may be invisible; process/unit names are only evidence of presence.'
printf '%s\n' 'Installed tools/modules/interfaces do not prove a working VPN or a recent handshake.'

section 'Completion'
printf '%s\n' 'No system configuration changes requested; no data sent to external services.'
if (( partial )); then
    printf '%s\n' 'PARTIAL: some probes unavailable; see UNAVAILABLE entries. No absence/health verdict.'
    exit 1
fi
printf '%s\n' 'COMPLETE within stated scope; not a security, VPN connectivity or acceptance verdict.'
exit 0
