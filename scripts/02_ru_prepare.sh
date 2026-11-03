#!/usr/bin/env bash
# Preparation only. No VPN activation, key generation or network mutations.
set +x
set -Eeuo pipefail
export LC_ALL=C
umask 077

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
trap 'printf "ERROR: operation failed at line %s; inspect CREATED entries before retry/rollback.\n" "$LINENO" >&2' ERR
usage() {
    printf '%s\n' \
        'Usage: bash scripts/02_ru_prepare.sh [--dry-run|--apply|--help]' \
        'Default: --dry-run. Both modes require root on Ubuntu 24.04.' \
        '--apply creates only missing directories and inactive templates.' \
        'Existing objects must match expected contents, ownership and permissions.' \
        'No secrets, active .conf files, services or network changes.'
}
mode=--dry-run
(( $# <= 1 )) || { usage >&2; exit 2; }
case "${1---dry-run}" in
    --help|-h) usage; exit 0 ;;
    --dry-run|--apply) mode=${1---dry-run} ;;
    *) usage >&2; exit 2 ;;
esac
[[ ${OSTYPE-} == linux* ]] || fail 'Linux required (target Ubuntu 24.04).'
(( EUID == 0 )) || fail 'Run with sudo for complete checks; no automatic sudo escalation.'
for tool in awk uname stat cmp mkdir cat ln mktemp rm dirname timeout modinfo awg awg-quick wg wg-quick nft tc; do
    command -v "$tool" >/dev/null 2>&1 || fail "Required command missing: $tool (nothing installed automatically)."
done
[[ -r /etc/os-release ]] || fail 'Cannot read /etc/os-release.'
os=$(awk -F= '$1=="ID" {gsub(/"/, "", $2); print $2}' /etc/os-release)
version=$(awk -F= '$1=="VERSION_ID" {gsub(/"/, "", $2); print $2}' /etc/os-release)
[[ $os == ubuntu && $version == 24.04 ]] || fail 'Expected Ubuntu 24.04; review the environment.'
printf 'CHECK: Ubuntu 24.04; kernel %s\n' "$(uname -r)"
modinfo amneziawg >/dev/null 2>&1 || fail 'AmneziaWG module information unavailable for the current kernel; ensure the module is installed. This script will not load it.'
for tool in awg wg; do
    if ! interfaces=$(timeout 10s "$tool" show interfaces 2>/dev/null); then
        fail "$tool interface query failed or timed out (details withheld)."
    fi
    [[ -z $interfaces ]] || fail "$tool interfaces already exist; this preparation requires the audited pre-activation state."
done
printf '%s\n' 'CHECK: required tools present; AWG module installed (modinfo); no AWG/WG interfaces in current namespace.'

base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
sources=("$base/templates/ru/awg0.conf.template" "$base/templates/ru/wg-nl.conf.template")
directories=(/etc/amnezia /etc/amnezia/amneziawg /etc/wireguard)
targets=(/etc/amnezia/amneziawg/awg0.conf.template /etc/wireguard/wg-nl.conf.template)

# Reject symlinks (including ancestors), non-root owners and writable ancestors.
# This is a local root operation; do not run concurrently with other configuration writers.
check_ancestors() {
    local path=$1 info uid gid mode_bits
    while [[ $path != / ]]; do
        [[ ! -L $path ]] || fail "Symlink refused: $path"
        if [[ -e $path ]]; then
            [[ -d $path ]] || fail "Not a directory: $path"
            info=$(stat -c '%u %g %a' -- "$path")
            read -r uid gid mode_bits <<< "$info"
            [[ $uid == 0 && $gid == 0 ]] || fail "Expected root:root ancestor: $path"
            (( (8#$mode_bits & 0022) == 0 )) || fail "Writable by group/others: $path"
        fi
        path=$(dirname -- "$path")
    done
}
for dir in "${directories[@]}"; do
    check_ancestors "$dir"
    if [[ -e $dir ]]; then
        info=$(stat -c '%u:%g:%a' -- "$dir")
        if [[ $dir == /etc/amnezia ]]; then
            [[ $info == 0:0:755 || $info == 0:0:700 ]] || fail "Expected root:root 0755 or 0700: $dir; no automatic permission changes."
        else
            [[ $info == 0:0:700 ]] || fail "Expected root:root 0700: $dir; no automatic permission changes."
        fi
    fi
done
for i in "${!sources[@]}"; do
    src=${sources[$i]}; dst=${targets[$i]}
    [[ -f $src && ! -L $src ]] || fail "Missing or symlinked repository template: $src"
    # Repository templates must contain no populated secrets or executable hooks.
    awk '
        /^[[:space:]]*(PrivateKey|PresharedKey)[[:space:]]*=/ {bad=1}
        /^[[:space:]]*(PreUp|PostUp|PreDown|PostDown|SaveConfig)[[:space:]]*=/ {bad=1}
        END {exit bad}
    ' "$src" || fail 'Template has a secret field or forbidden hook; review trusted repository copy.'
    [[ ! -L $dst ]] || fail "Symlink refused: $dst"
    if [[ -e $dst ]]; then
        [[ -f $dst ]] || fail "Not a regular file: $dst"
        [[ $(stat -c '%u:%g:%a:%h' -- "$dst") == 0:0:600:1 ]] || fail "Expected root:root 0600, one hard link: $dst"
        cmp -s -- "$src" "$dst" || fail "Existing template differs: $dst; preserved, review manually."
    fi
done
# All preflight and conflict checks complete before any write.
for dir in "${directories[@]}"; do
    dir_mode=700
    [[ $dir != /etc/amnezia ]] || dir_mode=755
    if [[ -d $dir ]]; then
        printf 'KEEP: %s\n' "$dir"
    elif [[ $mode == --dry-run ]]; then
        printf 'WOULD CREATE: directory root:root 0%s %s\n' "$dir_mode" "$dir"
    else
        mkdir -m "$dir_mode" -- "$dir"
        printf 'CREATED: directory %s\n' "$dir"
    fi
done
temp=''
cleanup() { if [[ -n $temp ]]; then rm -f -- "$temp"; fi; }
trap cleanup EXIT
for i in "${!sources[@]}"; do
    src=${sources[$i]}; dst=${targets[$i]}
    if [[ -f $dst ]]; then
        printf 'KEEP: %s\n' "$dst"
    elif [[ $mode == --dry-run ]]; then
        printf 'WOULD CREATE: inactive template root:root 0600 %s\n' "$dst"
    else
        # Publish a complete file without overwriting an existing destination.
        temp=$(mktemp "$(dirname -- "$dst")/.ru-prepare.XXXXXXXX")
        cat -- "$src" > "$temp"
        ln -T -- "$temp" "$dst"
        rm -- "$temp"
        temp=''
        printf 'CREATED: inactive template %s\n' "$dst"
    fi
done
printf 'DONE: %s; no VPN activation or network/service changes.\n' "$mode"
