#!/bin/bash
set -eu
trap 'sudo -n systemctl stop vpn-task07-client.service' EXIT
sudo -n systemctl start vpn-task07-client.service
printf 'OWNERSHIP\n'
sudo -n /usr/local/sbin/vpn-task07 status
sudo -n /usr/bin/python3 -I -B /home/wolffrog/task07-stage/check-baseline-predicate.py
printf 'UNIT06\n'
systemctl show vpn-task06-awg.service -p ActiveState -p SubState -p MainPID -p Result --no-pager
printf 'AWG_QUERY_EXIT='; if sudo -n /opt/vpn-task06/awg show awg-transport listen-port >/dev/null 2>&1; then echo 0; else echo 1; fi
printf 'ADDR4\n'
ip -j -4 address show dev awg-client
printf 'ADDR6\n'
ip -j -6 address show dev awg-client
printf 'ROUTES4\n'
ip -j -4 route show table all dev awg-client
printf 'ROUTES6\n'
ip -j -6 route show table all dev awg-client
