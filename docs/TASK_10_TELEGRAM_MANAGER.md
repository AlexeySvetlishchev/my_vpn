# TASK 10 — administrative Telegram adapter

Scope: RU only. No TASK06/07 restart, live peer mutation, FR, Docker, firewall,
PBR/NAT/DNS, default-route or SSH changes are part of the installation itself.
Owner confirmed Test_iPhone browsing after TASK09 migration.

**Current 2026-11-09:** deployed and connected through FR without a new peer or
namespace. See [actual result, isolation and rollback](TASK_10_DEPLOYMENT_RESULT.md).
The original direct-access attempt and namespace proposal below are historical;
the implemented path uses broker-passed marked sockets, two bot-only rules and
an ownership-aware TASK08 recovery extension. Owner approved the real test.

Owner subsequently confirmed native `.vpn`/QR import, automatic server naming
and real client Internet access. Final standard display name is **WolfVPN**.
The latest [navigation revision](TASK_10_UI_UPDATE.md) adds Home at every level,
cancels dialog state and invalidates stale actions, and edits one navigation
panel instead of accumulating duplicate messages. Permanent names/profiles are
chosen and created by the owner. Authorized cleanup revoked Test_iPhone and
disabled Test; their archived identity remains required by Manager activation.
See [finalization and remaining limits](TASK_10_FINALIZATION.md).
Deferred final-stage client downloads/mirror are tracked in [ROADMAP.md](ROADMAP.md).

## Implementation

- Python standard library only; Telegram HTTPS long polling, no webhook/listener
  port. See the [official Bot API](https://core.telegram.org/bots/api#getupdates).
- `vpn-task10-bot.service`: systemd DynamicUser, empty capabilities, read-only
  system, private temp/devices, credentials passed by `LoadCredential`. It has
  no access to AWG keys, SQLite, or root commands. No sudo grant to the bot.
- `vpn-task10-broker.service`: root local Unix socket broker with CAP_NET_ADMIN
  only and a narrow write allowlist. Kernel SO_PEERCRED and exact systemd cgroup
  `/system.slice/vpn-task10-bot.service` authenticate each connection. Root/local
  users and other services are rejected. Socket mode 0666 is intentional: the
  DynamicUser UID changes; kernel identity and cgroup, not filesystem mode alone,
  enforce access. Runtime exports are under a separate 0700 subdirectory.
- Broker accepts only fixed user/device/status methods, numeric authorized admin
  ID and private chat ID equal to that ID, exact argument counts and Manager
  identity syntax. No shell, arbitrary CLI options, backup/restore, arbitrary
  networking, service control or file API is exposed to Telegram input. The
  separate fixed `network.telegram` operation supplies only an authenticated,
  FR-bound api.telegram.org:443 socket to the exact bot process.
- Existing `vpnctl.execute`, Store, Controller, Vault and process_lock perform
  all business operations; no second database or direct AWG configuration layer.
- Per-request random IDs are durably reserved before API execution. Bot persists
  polling offset before processing, consumes callbacks before side effects,
  expires them after 10 minutes and binds them to admin identity. Restart makes
  old buttons unusable. At-most-once favors no duplicate operations over automatic
  retry: a crash can leave an action unexecuted; refresh state before retrying.
- Limit: 20 accepted UI requests/minute/admin. Each callback repeats authorization;
  groups, supergroups, channels, bots and unauthorized user IDs receive no data.

## UI

`/start` or `/menu` opens inline navigation. Users and devices are paginated.
Text input is used only for names. Disable/delete/revoke have confirmation;
profile delivery requires separate explicit confirmation. State shows present
peers versus recent handshakes, RX/TX, service health and configured limits.
QoS is explicitly displayed as **not applied**; bot does not install rate rules.

## Credential handoff

Do not send token or admin ID to chat, tool arguments, source code or `.env`.
The Windows `scripts/task10/collect_credentials.pyw` masked form writes only:
`%LOCALAPPDATA%\vpn-ru-fr\task10\credentials.json`.
Its protected DACL grants only the current Windows SID; the file is outside Git.
The agent transfers it without displaying/reading its contents via SCP to the
owner-only `/home/wolffrog/.task10-intake/credentials.json` (directory 0700,
file 0600). Agent executes the prepared provision script with the **path only**:

```sh
sudo -n python3 -B /opt/vpn-task10-stage/task10/provision.py /home/wolffrog/.task10-intake/credentials.json
```

Provision verifies getMe and absence of an existing webhook, writes root-owned
`/etc/vpn-task10/token` and `admins.json` (directory 0700, files 0600), removes
the upload and starts only TASK10 services. It prints no token or admin ID.
After successful delivery the local plaintext bundle must be removed too. Token
rotation uses the same masked path; BotFather can revoke the previous token.

## Profiles and logs

Broker calls existing Manager export into a fresh root-only runtime directory,
returns bounded bytes over the authenticated socket and removes the temporary
directory even on error. RuntimeDirectory cleanup covers broker process failure.
Bot uploads the document from memory with `protect_content=true`; neither token,
private key, profile nor raw Telegram errors is logged. Core administrative audit
uses `telegram-admin:<numeric ID>` in the existing Manager audit table.

Telegram bots use cloud chats, **not end-to-end encrypted secret chats**.
The admin explicitly accepts this delivery channel on the export confirmation.
Protection flags reduce forwarding but cannot promise secrecy after download.
Sent profile messages are scheduled for deletion after about ten minutes;
only chat/message IDs and deadlines persist, never profile contents. Deletion
is best-effort with retries. A saved profile stays valid until its peer is revoked.

## Install, verify and rollback

Public source delivery manifest is verified on RU before installation. Baseline
of existing TASK10 files/units, if any, is retained under `/var/backups/vpn-task10`.
Until credentials arrive, code/units are installed and bot is boot-enabled but
both services remain inactive; missing credentials are an explicit condition.

```sh
sudo -n systemctl is-active vpn-task10-bot.service vpn-task10-broker.service
sudo -n systemctl show vpn-task10-bot.service -p User -p DynamicUser -p MainPID
sudo -n journalctl -u vpn-task10-bot.service -u vpn-task10-broker.service -n 30 --no-pager
sudo -n vpnctl --json diagnostics
```

Addressed service rollback (no effect on VPN sessions or Manager CLI):

```sh
sudo -n systemctl disable --now vpn-task10-bot.service
sudo -n systemctl stop vpn-task10-broker.service
```

Keep root credentials protected or revoke the token through BotFather. Do not
restore old Manager SQLite or VPN configuration merely to remove Telegram.
Already-authorized user/device changes require explicit Manager operations.

## Historical initial acceptance boundaries (superseded by final result)

Offline tests cover unauthorized users/groups/callbacks, wrong chat binding,
expired/replayed buttons and polling updates, durable broker replay guard,
request allowlist, kernel peer/cgroup checks, rate limiting, isolated real
Manager-core add/disable/enable/revoke, protected export cleanup and sanitized
HTTP errors. Windows user-only credential intake was tested with synthetic data.

Telegram connection and real UI delivery remain unconfirmed until owner supplies
the credential bundle. One proposed real test scope, requiring owner approval:
create `TelegramTest`, add `Phone`, export only that new profile to the authorized
private chat, disable/enable the new device, revoke it and delete `TelegramTest`.
Existing Test_iPhone and other users/devices are excluded from that test.

## Observed installation, 2026-11-08

- Final delivery SHA-256 matched locally and on RU; installed source files
  matched the public manifest. Units passed `systemd-analyze verify`.
- `/opt/vpn-task10` and both systemd units are installed root-owned. Bot unit
  is enabled for boot; both TASK10 services are currently inactive because
  credentials are absent. No actual Telegram API connection has been tested.
- TASK10 file baseline: `/var/backups/vpn-task10/20261108T184753Z`.
- 23 TASK10 tests and 27 Manager regression tests passed inside disposable Linux
  containers. Windows Tk initialization and user-only intake storage passed with
  synthetic credentials; no real credential was read by these tests.
- Final Manager diagnostics: SQLite integrity true, peer drift empty, no pending
  operations, client/transport/DNS/ownership/fail-closed checks all healthy.
- No real user/device was created, disabled or revoked by TASK10 preparation.
  No VPN interface/service, network rules, FR or Docker was changed.
- Owner action pending: fill only BotFather token and numeric admin ID in the
  local form, then tell the agent the bundle is ready (no secrets in chat).
  Agent handles SCP, provisioning and startup; owner runs no server commands.
- After successful connection, approve the single TelegramTest/Phone live test
  scope above. End-to-end button/profile delivery acceptance remains pending.
- No commit or push.

## HISTORICAL blocker after credential handoff (resolved via marked sockets)

The owner supplied the bundle through the masked Windows form. A local API
getMe confirmed `wolffrog_homebot` and no existing webhook, without logging the
token or admin ID. RU provisioning failed at `telegram_getme` before installing
active service credentials or starting either service. A fixed TLS-only probe
observed IPv4 TCP/TLS timeout on RU (6 seconds); IPv6 returned ENETUNREACH.
The same public endpoint was reachable from Windows (verified TLS) and FR
(HTTP 302). Thus the observed blocker is RU-to-Telegram connectivity, not an
invalid token. The exact cause of the upstream loss has not been determined.

The supplied bundle is now protected as root:root 0600 at
`/etc/vpn-task10/pending-credentials.json` inside the 0700 config directory.
The user-owned RU upload and Windows plaintext intake file were deleted after
the root copy was compared byte-for-byte. No credential needs to be resubmitted.
Do not display the pending file or include it in any source archive.

Existing host PBR routes only traffic arriving on `awg-client` (plus explicit
DNS-source rules) through table 220. Merely binding the bot to the transport
address would not supply Telegram connectivity. No PBR, default-route, firewall,
TASK06, Docker or FR changes were attempted to bypass this boundary.

### HISTORICAL proposal: isolated service-client egress (not implemented)

Requires owner approval for the additional permanent service peer and namespace:

1. Back up Manager metadata, bot units and peer inventory. Create only the new
   managed `System_Telegram` identity using vpnctl; allocate its unused /32 from
   the existing pool without changing Test_iPhone or any revoked key.
2. Use a dedicated TASK10 userspace client/helper and disposable `task10-tg`
   namespace on RU. Its outer UDP endpoint is local `127.0.0.1:51821`; its client
   packets enter existing `awg-client` and use the accepted TASK08 RU/FR path.
   Give this helper a private UAPI mount so TASK07's socket directory/lifecycle
   remains independent. No new kernel AWG or binary rebuild is proposed.
3. Place only the Telegram process in that namespace; its default route and
   resolver `10.203.253.1` are namespace-local. Root broker stays in the host
   namespace and communicates over the existing Unix socket. No global host
   routes, PBR, firewall rules or FR configuration change is proposed.
4. Verify DNS, Telegram getMe/long polling and fail-closed behavior on this
   isolated path before enabling the new dependency. Resume provisioning from
   the root-only pending bundle through the namespace, never by re-entering
   credentials or logging token-bearing requests.
5. Addressed rollback stops only TASK10 components, removes only its namespace /
   dedicated client process and revokes only the recorded System_Telegram peer.
   Restore its prior bot unit; leave Manager/TASK06–08 and Test_iPhone intact.

This is a proposal, not an applied network change. The underlying local-client
namespace data path was proven by TASK09's disposable probe; persistent TASK10
service wiring and tests remain to be implemented after this scope is accepted.
The separate TelegramTest/Phone user-facing acceptance scope still needs approval.
# Profile name update — 2026-11-09

New primary exports use native `.vpn`/QR with the standard server display name;
raw `.conf`/QR remains available for compatibility. Implementation, source
verification, deployment and rollback: [TASK_10_PROFILE_NAME.md](TASK_10_PROFILE_NAME.md).
