#!/usr/bin/env bash
# Offline filesystem regression; never invokes --apply or the host preflight.
set -Eeuo pipefail
export LC_ALL=C
base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$base"
scratch=$(mktemp -d "$base/tests/.ru-prepare-test.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
script="$base/scripts/02_ru_prepare.sh"
bash -n "$script"
bash "$script" --help >/dev/null
count=0

# Only stat metadata is simulated, so tests also work without root on Git Bash.
stat() {
    local format=$2 path=${@: -1} uid=0 gid=0 bits=755 links=1
    case "$path" in
        "$fixture/amnezia"|"$fixture/amnezia/amneziawg"|"$fixture/wireguard") bits=700 ;;
        *.template) bits=600 ;;
    esac
    if [[ $path == "$override" ]]; then
        uid=$test_uid; gid=$test_gid; bits=$test_bits; links=$test_links
    fi
    case "$format" in
        '%u %g %a') printf '%s %s %s\n' "$uid" "$gid" "$bits" ;;
        '%u:%g:%a') printf '%s:%s:%s\n' "$uid" "$gid" "$bits" ;;
        '%u:%g:%a:%h') printf '%s:%s:%s:%s\n' "$uid" "$gid" "$bits" "$links" ;;
        *) return 98 ;;
    esac
}
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
snapshot() {
    find "$fixture" -exec /usr/bin/stat -c '%n %F %a %u %g %s %y %z' -- {} \;
    find "$fixture" -type f -exec sha256sum -- {} \;
}
setup() {
    count=$((count + 1))
    fixture="$scratch/case-$count"
    mkdir -p "$fixture/amnezia/amneziawg" "$fixture/wireguard"
    override=''; test_uid=0; test_gid=0; test_bits=700; test_links=1
}
run_case() {
    local name=$1 expected=$2 needle=$3 body output status=0 before after
    # Keep production validation and dry-run loops, redirect only /etc paths.
    body=$(sed -n '/^sources=/,$p' "$script")
    body=${body//\/etc\//$fixture/}
    before=$(snapshot)
    output=$( (
        set -Eeuo pipefail
        mode=--dry-run
        # Any attempted mutation is a failure, including temporary files.
        mkdir() { fail 'UNEXPECTED WRITE: mkdir'; }
        mktemp() { fail 'UNEXPECTED WRITE: mktemp'; }
        ln() { fail 'UNEXPECTED WRITE: ln'; }
        rm() { fail 'UNEXPECTED WRITE: rm'; }
        chmod() { fail 'UNEXPECTED WRITE: chmod'; }
        chown() { fail 'UNEXPECTED WRITE: chown'; }
        eval "$body"
    ) 2>&1 ) || status=$?
    after=$(snapshot)
    [[ $status == "$expected" && $output == *"$needle"* && $output != *'UNEXPECTED WRITE'* && $before == "$after" ]] || {
        printf 'FAIL: %s (status %s)\n%s\n' "$name" "$status" "$output"; exit 1;
    }
    printf 'PASS: %s; fixture unchanged\n' "$name"
}

for bits in 755 700; do
    setup; override="$fixture/amnezia"; test_bits=$bits
    run_case "amnezia $bits accepted" 0 "KEEP: $fixture/amnezia"
done
setup
rmdir "$fixture/amnezia/amneziawg" "$fixture/amnezia" "$fixture/wireguard"
run_case 'missing parent planned as 0755' 0 "directory root:root 0755 $fixture/amnezia"
run_case 'missing AWG directory planned as 0700' 0 "directory root:root 0700 $fixture/amnezia/amneziawg"
run_case 'missing WG directory planned as 0700' 0 "directory root:root 0700 $fixture/wireguard"
run_case 'AWG template planned as 0600' 0 "inactive template root:root 0600 $fixture/amnezia/amneziawg/awg0.conf.template"
run_case 'WG template planned as 0600' 0 "inactive template root:root 0600 $fixture/wireguard/wg-nl.conf.template"
for path in amnezia amnezia/amneziawg wireguard; do
    for bits in 777 775 750 1700; do
        setup; override="$fixture/$path"; test_bits=$bits
        run_case "$path $bits refused" 1 'ERROR:'
    done
    for owner in uid gid; do
        setup; override="$fixture/$path"
        if [[ $owner == uid ]]; then test_uid=1000; else test_gid=1000; fi
        run_case "$path non-root $owner refused" 1 'Expected root:root ancestor:'
    done
done
for path in amnezia/amneziawg wireguard; do
    setup; override="$fixture/$path"; test_bits=755
    run_case "$path 0755 refused" 1 'Expected root:root 0700:'
done
for target in amnezia/amneziawg/awg0.conf.template wireguard/wg-nl.conf.template; do
    for condition in valid mode uid gid hardlink; do
        setup
        cp "$base/templates/ru/${target##*/}" "$fixture/$target"
        override="$fixture/$target"; test_bits=600
        case "$condition" in
            mode) test_bits=644 ;; uid) test_uid=1000 ;; gid) test_gid=1000 ;; hardlink) test_links=2 ;;
        esac
        if [[ $condition == valid ]]; then
            run_case "$target 0600 accepted" 0 "KEEP: $fixture/$target"
        else
            run_case "$target $condition refused" 1 'Expected root:root 0600, one hard link:'
        fi
    done
done
for path in amnezia amnezia/amneziawg wireguard amnezia/amneziawg/awg0.conf.template wireguard/wg-nl.conf.template; do
    setup
    # Directory symlink destinations must first be absent.
    case "$path" in
        amnezia) rmdir "$fixture/amnezia/amneziawg" "$fixture/amnezia" ;;
        amnezia/amneziawg|wireguard) rmdir "$fixture/$path" ;;
    esac
    ln -s "$base/templates/ru" "$fixture/$path" 2>/dev/null || true
    if [[ -L $fixture/$path ]]; then
        run_case "$path symlink refused" 1 'Symlink refused:'
    else
        printf 'SKIP: %s symlink (filesystem does not create symlinks)\n' "$path"
    fi
done
printf 'PASS: local regression complete (no --apply).\n'
