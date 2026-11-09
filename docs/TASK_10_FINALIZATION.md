# TASK10 finalization — 2026-11-09

## Result and scope

**Complete:** administrative Telegram Manager on RU, through the existing FR
transport, native AmneziaVPN `.vpn`/QR, compatible `.conf`/QR, Home/cancellation,
authorization/replay protection and addressed TASK10 rollback. Owner confirmed
native import, automatic name and working Internet on a real device.

Final standard name: **WolfVPN**. The sole production setting is
`scripts/task09/manager_formats.py::SERVER_DISPLAY_NAME`. New CLI/native bot
exports use it; raw AWG `.conf` cannot set an Amnezia server name. Existing
imports, files, keys, Endpoint, AllowedIPs, DNS and AWG parameters are unchanged.
No new device/profile was created or reissued during finalization.

## Applied and observed

- 10:03:09 UTC: exact baseline/delivery SHA-256 checks passed. Atomically
  updated only Manager's name module, TASK10 rollback preflight and its public
  manifest. Only TASK10 bot/broker restarted; all live peers, TASK06/07/egress
  PIDs, default routes, TASK08 ledger and TASK07 helper stayed unchanged.
- Native exporter/model and QR decoder tests used the final name, with exact
  preservation of the raw AWG config and network/key fields. Real-device native
  format acceptance was confirmed by owner before shortening the name. There
  was no forced rename/reissue of already imported profiles.
- Confirmed separate permanent profiles. `pasha_phone` had a recent handshake
  and bidirectional counters; its observed RX/TX grew from 1,863,772/2,946,564
  to 2,111,344/3,410,905 bytes during this work. It is a different ID/IP/key
  identity from legacy Test_iPhone. Aleksey also has prior bidirectional traffic.
- Protected Manager backup and archive-integrity check passed before retirement.
  `vpnctl device revoke Test iPhone` removed only the legacy peer from live AWG.
  `vpnctl user disable Test` made the otherwise empty test account inactive.
  Reconcile and the actual installed TASK07 startup reader exclude its key;
  Manager activation still validates. All other device states/addresses/peers
  were preserved, drift empty and no incomplete operations.
- **Deletion limitation:** vpnctl has terminal device revoke, not physical
  device deletion. Its audited tombstone retains the reserved address/key.
  `vpnctl.activated()` calls `store.device('Test','iPhone')`; deleting Test
  would break subsequent Manager mutations. TASK07 startup and backup checks
  also require the retained legacy identity. Therefore Test and its archived
  device were deliberately NOT physically deleted. No SQL writes or direct AWG
  commands bypassed Manager. This is dependency preservation, not active access.
- **Inferred from actual server authorization:** the old key cannot authenticate
  because it is no longer an AWG peer and is not desired at startup/reconcile.
  No connection attempt with the old device/private key was performed.

## Remaining inventory (no secrets)

| User | Device | Manager state | Present in AWG | Connection evidence |
|---|---|---|---|---|
| Aleksey | phone | enabled | yes | Prior handshake and RX/TX; not connected recently at final sample |
| pasha | phone | enabled | yes | Recent handshake, growing RX/TX |
| Stas | phone | enabled | yes | No handshake or data yet; registration is not a connection |
| Test | iPhone | revoked; user disabled | no | Legacy identity tombstone only |

Earlier TaskNine_Probe and TelegramTest_Phone are already revoked tombstones
under deleted users; neither is live. Those older records were not modified.
Final inventory: three live peers, four retained user rows in user-list output,
six device records including three revoked tombstones. No System_Telegram.

## Tests and final checks

- Disposable Linux container, with isolated CAP_NET_ADMIN: **58 TASK10 +
  32 TASK09 + 16 TASK08 tests passed (106 total), no skips**. Real kernel RPDB
  lookup loss reaches the terminal unreachable; no host/VPS routing was used
  as a test sandbox. Tests include stranger/group/callback denial, replay,
  Home at every UI level, stale confirmations, raw/native export and safe
  cleanup, updater error rollback, manifest drift and read-only rollback check.
- Extra pinned-official-source Qt6 check: QR import and AWG/native model parsed
  the requested final name, unchanged fields and config. zbar scanned the PNG
  to exactly the native payload. Only synthetic fixtures; no key files committed.
- Live private Telegram rendering: one silent temporary panel, two edits,
  Home cancellation cleared input, panel deleted. No user/device operation or
  profile delivery was triggered by this renderer check. Actual export/control
  acceptance from the earlier authorized TelegramTest scenario and owner's
  native profile confirmation is retained; no new sacrificial peer was created.
- All installed manifest hashes valid. Bot connected through FR; sampled logs
  had no detected token, INI profile or native URI. Source/log checks are bounded
  evidence, not a claim that arbitrary raw diagnostics are inherently safe.
- Manager SQLite integrity/services healthy, drift absent, rollback_ready true
  for TASK08 and read-only TASK10 preflight. TASK06 UDP/TCP monitor healthy.
- RU policy lookup for 77.88.55.242 chose eth0; foreign 1.1.1.1 chose
  awg-transport/table 220 using a permanent client's source and the correct mark.
  The existing client DNS at 10.203.253.1 answered example.com successfully.
  TLS over the bot's marked/bound FR path returned IPv4 **45.15.128.138**.
- Fail-closed guards/ownership remain configured and unchanged; the earlier
  live bot-only lookup-loss observation remains valid historical evidence.
  No new real-client transport outage, DNS leak/IPv6 test or full FR failure
  was injected in finalization. No firewall/route/sysctl/FR/Docker modification.
- Boot enablement verified: bot and egress enabled; broker is intentionally
  dependency-started by bot (`Requires`, `After`, `PartOf`). Units verified by
  systemd-analyze. **Host reboot not performed**; enabled units are not proof
  of successful cold boot. No 15-minute or load test.

## Backups and addressed rollback

- Name/preflight public files: 0700
  `/var/backups/vpn-task10/export-final-20261109T100309Z`, files 0600.
- Pre-retirement protected Manager backup:
  `/var/lib/vpn-task09/backups/vpn-task09-20261109T100317Z-0a3f24948de1.tar`.
  Integrity passed. It contains secrets, remains root-only on RU and must not
  be copied to Git or used for an automatic global/live database rollback.
- Initial egress baseline: `/var/backups/vpn-task10/20261109T072236Z`, referenced
  by root installation.json. Original Task08 recovery source hash is preserved.

Read-only preflight, then full addressed bot removal **only if rollback is
requested**:

```sh
sudo -n python3 -I -B /opt/vpn-task10/rollback_entry.py --check
sudo -n python3 -I -B /opt/vpn-task10/rollback_entry.py
```

Removal verifies source/unit/marker/kernel/ledger ownership, stops/disables only
TASK10 units, removes only its mark-0x704 rules/ledger entries, restores the
verified TASK08 recovery source and moves credentials to a protected backup.
It preserves Manager, native exports, live users/peers, dynamic RU sets,
TASK06–09 client policies, FR and Docker. Revoked Test_iPhone remains revoked.
Full destructive removal was not executed; its preflight, isolated policy
removal/recreation and earlier TASK10 service recovery checks passed.

To undo **only** the final name/preflight code update:

```sh
sudo -n python3 -I -B /opt/vpn-task10-final-20261109/task10/update_name.py --rollback /var/backups/vpn-task10/export-final-20261109T100309Z
```

This restores public files and restarts only bot/broker. It never restores
SQLite/polling offsets or re-enables Test_iPhone. Revocation is intentionally
terminal in vpnctl; enabling the retained Test user cannot revive this device.

## Remaining acceptance and TASK11

- Optional owner observation of the final shortened name on the next **new**
  device; the native format/name/connection scenario has already been accepted.
- A real old-device negative connection attempt was not made; server-side
  removal and no-resurrection checks passed. Don't distribute the old profile.
- Actual reboot/recovery and physical-client fail-closed/IPv6/DNS checks during
  a transport outage remain project-level acceptance, not a reason to claim
  they were tested here. Stas_phone has not connected yet.
- TASK11 can begin: limits are already stored/displayed in Manager and bot,
  but QoS is **not enforced**. Plan per-user aggregate and per-device limits,
  upload/download and RU/FR paths, then obtain the specific network-change
  authorization. No tc/nft rate limits were installed by TASK10.
- End-of-project **📲 Скачать VPN-клиент** and a verified mirror of official
  Android/Windows/iOS distribution channels remain deferred in ROADMAP.md.
  No mirror, fork, distributions or download button created now.

One TASK10 source commit is authorized; push remains prohibited. Older unrelated
worktree changes are retained outside that commit. Temporary profiles, keys,
archives, logs, databases and runtime state are excluded.
Index review (`scripts/task10/review_index.py`) checked Python syntax, common
secret signatures, prohibited runtime extensions and all 14 manifest-pinned
public files using the actual Git-index bytes. `git diff --cached --check`
passed. This source scan complements protected delivery/log checks; it is not
a claim of universal secret detection.
