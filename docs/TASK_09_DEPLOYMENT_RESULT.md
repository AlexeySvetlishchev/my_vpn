# TASK 09 — RU deployment, 2026-11-08

Owner authorized maintenance downtime, client peer changes, TASK07 restart and
Manager timer activation. This result supersedes the earlier inert-state and
zero-downtime restrictions in the handoff/Manager design documents.

## OBSERVED

- RU `/usr/local/sbin/vpn-task07` is the SQLite-backed helper, SHA-256
  `0f4416045a4bd321b0c424bd56ad645bc01babc99b60feb51a387fa3efd5f852`.
  Existing `vpnctl` and SQLite remain the sole desired peer state. Activation
  is `/etc/vpn-task09/activation.json`, root:root 0600.
- Six TASK08 RU rules now admit `10.203.253.0/24`, with a preceding DROP for
  `.0`, `.1`, `.255`. AWG per-peer `/32` remains the source authorization.
  `ru.nft`, apply pin, rollback `TASK07_NEW` pin and active owned-table ledger
  were updated together. Local TASK08 sources now match the installed target.
- `ru_set` and `force_egress` were compared with the saved baseline and are
  unchanged. Host main routes and original Test_iPhone keys/public key/profile
  were compared internally; no sensitive bytes or hashes were printed.
- TASK08 reports `rollback_ready=true`, 29 owned nft objects. Manager reports
  SQLite integrity true, no peer drift and no incomplete operations; all
  client/transport/DNS/ownership/fail-closed checks are healthy.
- TASK06 monitor returned healthy, UDP echo true, TCP echo true. Route lookup
  for `.3` to `77.88.55.242` with mark `0x701` selects RU eth0; `1.1.1.1` with
  `0x702` selects table 220 / awg-transport. The foreign fallback unreachable
  RPDB rule remains installed. No transport outage was injected this session.
- Manager created TaskNine_Probe (`10.203.253.3`) with an independent key and
  exported its profile into a protected RU directory. An actual userspace AWG
  client in an isolated network namespace established the data path: UDP DNS
  to `10.203.253.1` and HTTPS ipify returned `45.15.128.138`. Disable blocked
  actual data; enable plus client reconnection restored DNS/HTTPS. Both the
  namespace and the extra userspace process were removed afterward.
- Restarting TASK07 restored both enabled peers from SQLite without changing
  Test_iPhone. User disable/enable and device revoke also passed. The probe
  is now revoked and its test user deleted; Test_iPhone is the only live peer.
- TASK07 boot enablement and Manager reconcile timer are enabled. The new
  reconcile unit uses RuntimeDirectory 0700 with Preserve=yes, so the lock
  directory exists after boot and is not removed between CLI operations.
  Unit verification and repeated oneshot reconcile completed successfully.
- TASK06, TASK08 egress/DNS/prefix timers retain enablement. No host reboot.
- FR was only queried read-only: `amnezia-awg2 Up 4 days`. No FR or Docker
  configuration changes/restarts were necessary.

Test_iPhone retains its original live peer, IP, keys and profile. Its physical
device was not connected during the final checks (no fresh handshake), so
fresh end-to-end Test_iPhone browsing is **not** claimed. Existing physical
device RU/FR/DNS/IPv6 acceptance from TASK08 remains the earlier result.

## Backup and addressed rollback

If TASK10 is deployed, perform its addressed removal first as documented in
[TASK_10_DEPLOYMENT_RESULT.md](TASK_10_DEPLOYMENT_RESULT.md), before using the
older TASK09 baseline. TASK10 owns additional isolated routing/ledger records.

The accepted baseline is root-only at:
`/var/backups/vpn-task09/20261108T180859Z`.
It includes the installed TASK07 helper/unit/configurations, TASK08 package,
pins, ledger and owned nft snapshot with dynamic sets, Manager source/config,
SQLite online snapshot, routes and service timer states. Secret-bearing files
stay on RU. Earlier failed-attempt backups remain protected for diagnosis.

The first cutover refused before nft mutation because the adapter incorrectly
removed JSON handles included in TASK08's ownership hash. This was corrected
without changing ownership semantics. A later post-check encountered the
Manager lock held by its parent; automatic addressed rollback succeeded.
The final cutover used in-process diagnostics under the existing lock.

For this baseline, run over existing SSH (owner approval remains necessary
for any future rollback outside this stage):

```sh
sudo -n python3 -B /opt/vpn-task09-migration/task09_review/task09_maintenance.py rollback /var/backups/vpn-task09/20261108T180859Z
```

This stops client ingress and Manager/timers, reverses only the six rules and
reserved guard using fresh handles, restores saved files/ledger/SQLite/config,
disables Manager timer/activation, restores original client boot state and
starts the old client/DNS. It does not flush global nftables or touch FR.
The script refuses unknown file or nft drift. If a subsequent prefix update or
other administration changes the saved owned state, do not force this baseline
rollback: retain current dynamic sets and prepare a newly validated reverse.

Current Manager backup was created at
`/var/lib/vpn-task09/backups/vpn-task09-20261108T181334Z-266d98ef6cdd.tar`.
Integrity/hash verification and protected staged restore passed (6 files).
This plaintext 0600 archive must stay in its root-only directory. Generic live
DB restore remains unimplemented; staged restore does not replace live state.

## Issuing a real profile

```sh
sudo -n vpnctl --json user add Ivan
sudo -n vpnctl --json device add Ivan iPhone
sudo -n vpnctl --json device export Ivan iPhone
```

Export prints only the protected path, normally
`/var/lib/vpn-task09/exports/Ivan_iPhone.conf`. Deliver that file through an
explicit authorized private channel; never print it or add it to Git. Import
as AmneziaWG config in compatible AmneziaVPN. Repeated export currently refuses
to overwrite the existing output; it does not rotate the device key.

## Remaining work

- Telegram adapter is not implemented; reuse the Manager business layer.
- Speed limits are stored/reported only, **not enforced**. Aggregate per-user
  and per-device tc enforcement requires a separate network implementation and
  owner approval; no tc/nft rate-limit changes were made.
- Generic live database restore and encrypted/offsite backups remain open.
- No 15-minute test, host reboot, or new physical-client test was performed.
- Isolated suite: all 63 tests passed, including actual nft apply/reverse with
  populated dynamic sets. Deployment did not perform a commit or push; the
  subsequent local source commit was separately authorized by the owner.
