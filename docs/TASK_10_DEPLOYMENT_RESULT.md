# TASK 10 — Telegram Manager, 2026-11-09

## Final accepted state

TASK10 administrative bot and native export are complete. Owner confirmed
real-device native `.vpn`/QR import, automatic name and VPN browsing. Final new
export name: **WolfVPN**, configured once in `manager_formats.py`. Compatibility
`.conf`/QR is retained. [Final checks, users, backups and remaining limitations](TASK_10_FINALIZATION.md).

At 10:03 UTC, Test_iPhone was revoked through vpnctl and removed from AWG;
Test is disabled but retained, together with the device tombstone, because
Manager activation/startup/backup still depend on that legacy identity. Other
working peers and profiles were preserved. No physical SQL deletion or manual
AWG peer removal was used. The older initial-deployment evidence below describes
the state before this separately authorized cleanup.

## OBSERVED

Bot: [@wolffrog_homebot](https://t.me/wolffrog_homebot), private administrative
long polling on RU. Telegram getMe, webhook absence, live polling and repeated
service startup are confirmed. Direct RU-WAN access is neither required nor used.

No System_Telegram, additional AWG peer, network namespace or VPN interface was
needed. Only the approved temporary TelegramTest/Phone peer was created; it is
now revoked and its test user deleted. Test_iPhone public identity, private key
files, IP, original profile and live peer were preserved. Its physical device
was not reconnected by the agent; owner had confirmed it after TASK09 migration.

## Bot-only transport and DNS

- Root broker opens only fixed `api.telegram.org:443` TCP sockets for the exact
  authenticated bot systemd cgroup, then transfers an FD with SCM_RIGHTS over a
  Unix socket. Bot performs TLS certificate/hostname validation and HTTP itself;
  broker never receives token-bearing API URLs or profile payloads for networking.
- Bot has DynamicUser, no capabilities and `RestrictAddressFamilies=AF_UNIX`.
  It cannot open an alternate direct IPv4/IPv6 connection. Received TCP sockets
  already carry SO_MARK `0x704`, which the unprivileged bot cannot clear.
- Marked HTTPS uses RU's existing local address `10.203.253.1`, existing table 220
  and awg-transport. FR's existing client-subnet forwarding/NAT covers the source.
  No address is allocated, no FR rules/routes or Docker configuration changed.
- Only two new RPDB rules: priority 10040, fwmark `0x704` lookup 220; priority
  10041, same mark, unreachable. Terminal is installed first and removed last.
  Seven existing client/DNS RPDB rules, nftables and RU main/default routes were
  compared with baseline and remain unchanged.
- Broker resolves only the fixed Telegram hostname using A queries bound to
  `10.203.254.1`, through 9.9.9.9 / 149.112.112.112. Existing TASK08 DNS rules,
  FR NAT and terminal/DROP protections carry these queries through FR. No host
  resolver, RU DNS fallback, IPv6, public proxy or external tunnel is used.
- Ownership: root-only `/etc/vpn-task10/egress.json` records the exact two rules.
  TASK08 active ledger includes them for TASK06's existing ownership projection.
  TASK08 `recover.py` validates this marker and retains its exact original
  seven-client-rule recovery contract; TASK10 maintains its own extra rules.
  TASK06 code/manifest and Task08 client packet policies were not changed.

## Installed components

- `/opt/vpn-task10`: UI, restricted Manager broker, TLS connector, route helper,
  QR encoder wrapper, addressed rollback and public SHA-256 manifest.
- `vpn-task10-egress.service`, `vpn-task10-broker.service`,
  `vpn-task10-bot.service`; bot and egress units boot-enabled. Dependencies order
  them after TASK08/TASK07, and PartOf propagates TASK10 restarts. Root broker
  retains only CAP_NET_ADMIN and restricted filesystem access; bot has none.
- Ubuntu `qrencode` + `libqrencode4` 4.1.1 (139 KiB installed), no upgrades and
  no existing VPN, Docker or unrelated service restart.
- Root `/etc/vpn-task10/token` and `admins.json` are 0600 in directory 0700.
  Token is passed to the frontend by systemd LoadCredential. Intake/pending and
  Windows plaintext bundles were removed. No token/admin ID is in sources/Git.

## Actual checks

- 36 TASK10 tests, 27 Manager regression tests, 16 TASK08 tests passed in an
  isolated disposable Linux container. Includes real kernel RPDB no-fallback,
  request/callback authorization and replay rejection, DNS/FD routing, recovery
  fault injection, exact ownership, export cleanup and sanitized HTTP failures.
- A marked/source-bound diagnostic HTTPS request returned FR IPv4
  **45.15.128.138**. Telegram getMe and DNS succeeded through the same connector.
- Bot-only lookup loss was injected by temporarily removing only priority 10040,
  leaving terminal 10041. Route lookup and Telegram connect failed; header-only
  passive observation on RU eth0 counted **0 Telegram SYN / 0 bot DNS packets**.
  Lookup was restored in finally and bot restarted. Existing transport/users
  were not stopped. This tested lookup loss, not a full FR outage/reboot.
- Task10-only stop/start removed then recreated its rules/ledger records.
  TASK08 recovery was executed successfully with both seven and nine ledger
  records. Main routes and all pre-existing rules remained exactly unchanged.
  Root egress-service restart automatically brought broker and bot back.
- TelegramTest/Phone was created through the same Manager API used by broker,
  `.conf` and QR delivered to the allowed private chat with protect_content.
  Disable removed its actual live peer, enable restored it, revoke removed it,
  then TelegramTest was deleted. Test profile no longer grants access. Test
  attachments were deleted after their TTL; normal UI profiles are scheduled
  for deletion after about ten minutes as well.
- Scripted acceptance used the real Manager API + Telegram delivery; physical
  human button clicks remain the owner's final UI check. Root and nobody were
  actually refused by the broker socket; stranger/group/callback authorization
  was checked with synthetic Telegram updates in offline tests, not a second
  real Telegram account.
- Journal was scanned internally for the actual token and profile markers;
  none found. No raw logs, packets, keys or profiles were printed by the checks.
- Final TASK06 monitor healthy with UDP/TCP echo; Manager SQLite integrity true,
  drift empty, no pending operations, DNS/ownership/fail-closed healthy. TASK08
  rollback_ready true. FR `amnezia-awg2` remained Up 4 days, queried read-only.

## Backup and addressed removal

Original pre-egress baseline:
`/var/backups/vpn-task10/20261109T072236Z`.
`/etc/vpn-task10/installation.json` preserves its verified original recovery-source
hash and path across later updates. Protected Manager backup before acceptance:
`/var/lib/vpn-task09/backups/vpn-task09-20261109T072430Z-1ff11711326d.tar`.
These stay on RU, never in the Git workspace.

To remove only TASK10 (agent runs this only when owner requests rollback):

```sh
sudo -n python3 -I -B /opt/vpn-task10/rollback_entry.py
```

It verifies exact installed public source/unit hashes, stops/disables only the
three TASK10 units, deletes only its two rules, removes their active-ledger
records, restores the verified original TASK08 recovery helper, removes the
TASK10 public package/units and backs up credentials to a new root-only removal
directory before deleting active credentials. It does not restore a whole
firewall, old SQLite, old dynamic sets, client routes, Task06/07, FR or Docker.
No service peer exists to revoke. Runtime export directories disappear on broker
stop; non-secret audit/state data is retained protected. Full package removal
has not been executed; its rule/service removal/recreation path was tested.
The final installed rollback also supports a read-only preflight:

```sh
sudo -n python3 -I -B /opt/vpn-task10/rollback_entry.py --check
```

It returned `task10_rollback_ready=true`. Removal deliberately retains the
Manager native export extension and revoked legacy identity; it never revives
revoked profiles or rolls back the database.

Remove TASK10 first before any broader TASK09/TASK08 rollback. This avoids
leaving the additional ownership records/rules outside their owning component.

## Owner check

Owner confirmed native `.vpn`/QR import into AmneziaVPN, automatic server naming
and real client Internet access.
The newer [UI update](TASK_10_UI_UPDATE.md) is deployed: Home on all screens,
scenario cancellation, stale-action invalidation and one edited navigation
panel. Permanent profiles exist; Test_iPhone is now revoked and has no live
access, with its archived identity retained for the dependency stated above.

Open the private bot chat and send `/start`. Check users and permanent device status,
handshake age and RX/TX, back navigation and the QoS-not-applied label. Test
TelegramTest is intentionally absent, and its exported profile is revoked.
For an actual new device, use Add device then explicitly request
**📲 AmneziaVPN: профиль и QR** (WolfVPN); raw `.conf`/QR remains the compatible
alternative. Keep those files private. Old Test_iPhone is intentionally invalid.

Telegram cloud delivery is not end-to-end encrypted. Protection/deletion is
best effort; a previously downloaded valid profile must be revoked to withdraw
VPN access. QoS enforcement remains unimplemented. No 15-minute test, host
reboot was performed. The final source commit is owner-authorized; no push.
# Export-only follow-up — 2026-11-09

The standard named native AmneziaVPN export is installed. VPN/network state and
existing peers are unchanged; only bot/broker restarted. Tests and the explicit
remaining physical-import check: [TASK_10_PROFILE_NAME.md](TASK_10_PROFILE_NAME.md).
