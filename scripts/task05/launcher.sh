#!/bin/bash
set +x
set -eu
if [[ $# != 1 ]]; then exit 2; fi
case "$1" in
    prepare|peer|up|status|start-test|result|down|cleanup) ;;
    *) exit 2 ;;
esac
exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /usr/bin/python3 -I -B /opt/vpn-task05/helper.py "$1"
