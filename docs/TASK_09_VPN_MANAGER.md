# TASK 09 — VPN Manager / `vpnctl`

Current status (2026-11-08): deployed on RU after explicit owner approval for
maintenance downtime and peer operations. SQLite-backed TASK07 startup,
activation, expanded TASK08 client rules and reconcile timer are active.
The independent probe passed real AWG/DNS/HTTPS and disable/enable tests,
restart persistence and revoke. Test_iPhone identity/profile are unchanged.
See [deployment result and addressed rollback](TASK_09_DEPLOYMENT_RESULT.md).
Preparation/gate descriptions below are historical where they describe an
inert installation or require the approval already granted for this stage.

## Scope and observed baseline

- RU `vpn-task07-client.service` is running on `awg-client`, `10.203.253.1/24`, UDP 51821, MTU 1280. Its unit is currently **disabled** for boot. `/usr/local/sbin/vpn-task07 serve` owns the interface and recreates exactly one peer, `10.203.253.2/32`, each time it starts. The live interface has exactly one peer. `awg set` supports add/remove without restarting the interface.
- The current test identity is root-owned under `/etc/vpn-task07` (directory 0700, `state.json`, `server.key`, `client.key`, `client.pub`, `Test_iPhone.conf` all 0600). TASK 09 will not regenerate or expose these files. The existing exported profile remains valid. The source helper, not SQLite, currently controls persistence of that peer.
- RU TASK 08 nft rules explicitly admit only `10.203.253.2` in ingress, DNS, return forwarding and RU NAT. FR TASK 08 already accepts `10.203.253.0/24`. Consequently a new peer can handshake but cannot have working client Internet/DNS until the exact RU TASK 08 rules are adapted. This is outside the current approval. TASK 06/08 health and ledger checks must be kept consistent.

## Architecture

One root-only Python library is the management core; `vpnctl` calls it locally. No HTTP listener, Telegram process or second AWG daemon is needed. SQLite is the desired-state store. The AWG adapter reads only peer public metadata (`peers`, `allowed-ips`, `latest-handshakes`, `transfer`) and applies one authorized peer change at a time with fixed argv for the installed `/opt/vpn-task07/awg`. It never runs `showconf`/`dump` or shell commands from database text.

`vpn-task07` remains interface lifecycle owner. At migration, its source and root-owned installed copy will be changed to populate peers from the validated root-owned Manager SQLite desired state on each service start, rather than hard-coding the sole test peer. The runtime Manager adapter handles live add/remove; both paths use the **same desired set**, without a second peer manifest that could diverge. A small systemd oneshot/timer reconciles after TASK 07 is ready and after interrupted operations. It never restarts `awg-client`. Missing or corrupt desired state fails closed and reports drift instead of silently adopting unknown peers. The initial test peer is imported as `Test_iPhone`, preserving its public identity, existing root-only client key and original profile file. An import is rejected if live public key/IP or file ownership differs.

SQLite: `/var/lib/vpn-task09/manager.sqlite3`, parent 0700, file 0600, `journal_mode=DELETE`, `synchronous=FULL`, `foreign_keys=ON`, `busy_timeout`, `BEGIN IMMEDIATE` for writes. This gives serialized writes and a read-only startup path without WAL sidecar writes from TASK 07's sandbox. Per-device private keys and profiles are **not** stored in SQLite; new secrets live under `/etc/vpn-task09/devices/<opaque-id>/` (0700/0600). SQLite stores a reference to that location, public key, IP, desired state and metadata. The legacy test key stays in `/etc/vpn-task07`. Export is a separate command that writes a new 0600 file into a root-only export directory and prints only its path. No private material appears in normal/JSON CLI output or audit events.

### Proposed SQLite schema v1

```sql
CREATE TABLE users (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, name_key TEXT NOT NULL UNIQUE,
 state TEXT NOT NULL CHECK(state IN ('enabled','disabled','deleted')),
 limit_up_bps INTEGER, limit_down_bps INTEGER,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE devices (
 id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
 name TEXT NOT NULL, name_key TEXT NOT NULL, profile_name TEXT NOT NULL UNIQUE,
 ipv4 TEXT NOT NULL UNIQUE, public_key TEXT NOT NULL UNIQUE,
 key_ref TEXT NOT NULL UNIQUE, state TEXT NOT NULL
   CHECK(state IN ('enabled','disabled','revoked')),
 origin TEXT NOT NULL CHECK(origin IN ('task07','manager')),
 limit_up_bps INTEGER, limit_down_bps INTEGER,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, revoked_at TEXT,
 UNIQUE(user_id,name_key)
);
CREATE TABLE operations (
 id TEXT PRIMARY KEY, kind TEXT NOT NULL, target_id TEXT NOT NULL,
 phase TEXT NOT NULL CHECK(phase IN ('planned','applying','done','failed')),
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, error_code TEXT
);
CREATE TABLE audit_events (
 id INTEGER PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL,
 action TEXT NOT NULL, target_type TEXT NOT NULL, target_id TEXT NOT NULL,
 result TEXT NOT NULL, operation_id TEXT
);
```

Names preserve display case and use NFKC + casefold for collision checks. To keep `User_Device.conf` safe and unambiguous, each component is 1–32 Unicode letters/digits, starts with a letter, and cannot contain `_`, slash, whitespace or control characters. Components are stored separately; profile names are never parsed back on `_`. `Test_iPhone` is reserved for adoption. New addresses are allocated from `10.203.253.3`–`.254`; `.0/.1/.2/.255` are reserved. Active and revoked public keys remain unique in SQLite; revoked addresses are not automatically recycled during TASK 09.

### CLI contract

`vpnctl [--json] user add|list|show|disable|enable|delete ...`, `device add|list|show|disable|enable|revoke|export ...`, `status`, `diagnostics`, `backup`. The user name and device name are separate positional arguments. `user delete` revokes all devices before marking the user deleted; a failed peer removal is reported as incomplete and never as success. `device revoke` is irreversible for the old key. `device disable` retains a key for re-enable. `device export` requires an explicit output action and never streams a profile to stdout. JSON has stable `ok`, `code`, `data` fields; human output avoids raw keys. Unknown names and collisions return distinct nonzero codes. A future Telegram adapter calls the same library, never replicates peer/DB logic.

`status` separates registered, desired-enabled, present-in-AWG and recently handshaken devices, with handshake age and RX/TX. It also reports TASK 07 service, TASK 06 monitor, RU DNS, read-only TASK 08 fail-closed/ledger checks and exact drift (missing/extra peer or wrong AllowedIPs). A peer is not called connected solely because it exists in SQLite. Audit records actor/action/outcome/opaque ID only. Per-user and per-device desired speed limits can be stored and reported as **not enforced** until a separate tc/nft network change is approved.

### Consistency and backup

SQLite writes are serialized; each operation is recorded before the AWG change. Applying a peer is followed by a read-back of exact public key and `/32`. On interruption, reconciliation compares desired SQLite state, validated startup snapshot and live AWG peers, then completes only Manager-owned operations. Unknown peers or a changed legacy test identity stop automatic reconciliation. Disable/revoke prioritizes removing live access; CLI cannot report success while the peer remains. A partial failure stays visible in `operations`/`diagnostics` and retries only after ownership checks.

`vpnctl backup` uses SQLite's online backup API, validates `PRAGMA integrity_check`, and packages the database with referenced root-only secret files and a SHA-256 manifest. The local archive is **unencrypted** but 0600 under a 0700 directory; it must never leave RU in this form. An off-host copy requires a separately configured authenticated-encryption recipient and a restore test before transfer. `vpnctl restore --check` validates archive hashes and SQLite integrity without replacing live state. Full live restore additionally requires key-file ownership, name/IP/key conflicts and current test identity checks **before** any replacement, with previous database/secrets retained for addressed rollback; this cutover remains unimplemented until the peer-change approval. No overwrite of the current test profile. Backup/restore of keys must not log payloads or store archives in Git/workspace.

Desired speed limits are stored for users and devices, and the more restrictive value is shown as a per-device effective ceiling. **No limit is enforced yet.** A true aggregate user cap shared by several devices, in both directions and across RU/FR paths, requires a separate tested `tc` design and network approval; the stored ceiling is not represented as that aggregate cap.

## One approval gate before live peer changes

1. Capture root-only baseline of TASK 07/08 helper, unit, manifest, test peer public metadata, current RU nft table/ledger and TASK 06 health. Verify production `amnezia-awg2` remains untouched. Stage exact helper and Manager files with hashes. Import legacy `Test_iPhone` metadata into Manager and verify its public key/IP against the live peer without displaying private material. Keep its client key and profile in place.
2. With owner approval, update only RU TASK 08 source/owned nft rules that currently hard-code `.2` to the client subnet `10.203.253.0/24`, preserving interface, destination, mark, fail-closed and NAT matches. AWG per-peer AllowedIPs must remain unique `/32` and act as the ingress source constraint. Update TASK 08 ledger and TASK 06 projection atomically. FR already permits the subnet; no FR change is proposed. Verify old client FR/RU paths before creating a new peer.
3. Install the TASK 07 lifecycle change that reads the Manager SQLite desired state, **without restarting** the running service initially. Enable its boot unit only after review. Apply one new test peer with `awg set` and verify live state, export profile and real client data path. Then perform a controlled restart of **only** TASK 07 after separately authorized cutover, confirming the original test peer and new peer return unchanged. Do not restart TASK 06, Docker, DNS or firewall services.
4. Test new-device disable/enable/revoke, user disable and restore, a forced interruption between SQLite and AWG, and backup/restore in an isolated environment before touching live data. Rollback is addressed: remove only the new Manager peer, restore exact TASK 07/08 owned files/ledger/rules from baseline, restore Manager DB snapshot, verify original test peer and RU/FR data path. Do not perform a global nft/iptables rollback or touch FR production.

The approval required for step 2 and the first live peer mutation is **not** yet given. Installing an isolated, inactive Manager package/database and running offline tests does not imply this approval. TASK 09 cannot meet its live-peer and speed-limit acceptance criteria until the corresponding scoped network/peer changes are authorized and actually tested.

## Installed inert state and verification (2026-11-08)

Only RU changed. `/opt/vpn-task09/*.py` is root:root 0644, `/usr/local/sbin/vpnctl` is root:root 0755, `/var/lib/vpn-task09/manager.sqlite3` is root:root 0600 in a root-only directory. `manager_migrate.py import-legacy` imported exactly one existing peer public identity and `10.203.253.2/32`; its read-only preflight matched the sole live peer and did not read a private key. The marker `/etc/vpn-task09/activation.json` remains absent. No TASK 09 unit was installed or enabled. Staged source hashes matched local hashes; Linux `py_compile` and `sh -n` passed.

`sudo vpnctl --json diagnostics` observed `sqlite_integrity=true`, empty peer drift and incomplete operations, and healthy TASK 07, TASK 06, DNS, TASK 08 ownership and configured fail-closed guards. `sudo vpnctl --json status` observed one registered and live old peer, zero recently handshaken peers at that instant; an old handshake is not a current connection. A local root-only archive was created with `vpnctl backup`; `restore --check` verified 5 files and SQLite integrity, and `restore --stage` extracted to a new 0700/0600 root-only staging area without replacing the live DB. The archive is **plaintext** and must stay on RU until authenticated encryption and offsite handling are implemented. No full live restore was performed.

### CLI examples and output

All commands run locally as root, for example `sudo -n vpnctl --json status`. Positional names are `vpnctl user add Ivan`, `vpnctl user show Ivan`, `vpnctl device add Ivan iPhone`, `vpnctl device export Ivan iPhone`. `user list`, `device list [USER]`, `status`, `diagnostics`, and `backup` take no target. `user disable|enable|delete USER` and `device show|disable|enable|revoke|export USER DEVICE` use the same names. `user limit USER --up-bps N --down-bps N` and `device limit USER DEVICE --up-bps N --down-bps N` store desired values only. `restore --check ARCHIVE` verifies; `restore --stage ARCHIVE` extracts into protected staging but never cuts over live state. `--json` precedes the entity and yields `{ok,code,data}` on success or `{ok,code,error}` on refusal. Exit codes: 0 success, 2 CLI/root usage, 3 controlled refusal, 4 withheld internal error. Human output is indented JSON without public or private keys. `device export` prints only the path of a newly created protected profile file and fails if the file already exists.

Before activation, all peer-changing commands and reconcile return `approval_required`. User creation/listing, desired limit storage, status, diagnostics, backup and staged restore remain usable without touching live peers. The interface is not re-created by Manager.

### Exact scoped cutover to approve

1. Save a root-only, hash-checked snapshot of the current RU TASK 07 helper/unit, TASK 08 `ru.nft`, `apply.py` pinned hashes, active ledger and nft table, TASK 06 projection, Manager DB, and the old public peer/IP. Confirm the existing client profile and RU/FR routes before any mutation.
2. Replace **six** source-address matches in RU-owned TASK 08 rules from `10.203.253.2` to `10.203.253.0/24`: prerouting anti-spoof DROP, UDP and TCP DNS INPUT accepts, forward anti-spoof DROP, established return from `awg-transport`, and RU WAN masquerade. Preserve all interface, mark, destination set, conntrack, drop and fail-closed predicates. Apply a prechecked atomic nft batch to only the RU-owned table and update its pinned source hash plus active ledger hash. Validate TASK 08 recovery and TASK 06 monitor against the new exact state. FR rules already admit the client /24, so FR needs no change. The existing peer's AWG AllowedIPs remains `10.203.253.2/32`; each new peer gets one unique `/32`.
3. Install the reviewed TASK 07 helper that reads the same SQLite desired peers, with its activation marker absent until import/ownership checks pass. Create a root-owned activation marker matching the old public fingerprint. Create one new test device via `vpnctl`; it calls live `awg set` for only that peer, without interface restart. Verify the old peer still exists with unchanged public identity and `/32`, and both peers match SQLite. Explicit export creates a 0600 profile. Test DNS, RU and FR egress, and fail-closed using a real test client; retain the prior client profile.
4. Restart **only** `vpn-task07-client.service` once to verify persistence, then enable its boot unit and Manager reconcile timer. This briefly interrupts existing TASK 07 clients, so it is part of the approval. Confirm both peers return, handshake/data pass, TASK 06 and TASK 08 monitors stay healthy, SSH remains available, and FR `amnezia-awg2` stays running. Test disable, enable, revoke and operation interruption using only the new device; the existing test peer must not be modified.
5. On failure, remove only the new Manager peer by its recorded public key, disable Manager timer and activation, restore the exact saved RU TASK 07 helper/unit and TASK 08 owned table/source/ledger hashes, and restore the protected pre-cutover Manager DB. Start only TASK 07 if it was restarted, then verify the original peer/IP, client connectivity, TASK 06/08 health and SSH. Do not apply global firewall restoration or touch Docker/FR production. A fresh backup plus `restore --check` precedes any future live DB restore; the current `--stage` command is not a live restore.

Current approval boundary: steps 2–4 and the corresponding addressed rollback need one explicit owner authorization. Rate enforcement through `tc`/nft requires a separate future network review; stored values are not enforced.
