# TASK10 — standard name on new imports (2026-11-09)

## Scope and format decision

Final owner-approved name: **WolfVPN** for new AmneziaVPN connections. Only
RU export/UI modules were updated. No device/key/profile was created or
reissued during this update. Existing imported profiles are not renamed.

**OBSERVED (official source):** AmneziaVPN stable 5.1.0.6, upstream commit
`ac175c8a8147cfe56f98c8372ec17ea2ba00bb02`, imports raw AWG `.conf`/QR using
`extractWireGuardConfig`, which assigns `nextAvailableServerName()` regardless
of file name or comments. Adding an unsupported `Name`/`Description` INI field
cannot solve this. See the [official importer, line 650](https://github.com/amnezia-vpn/amnezia-client/blob/ac175c8a8147cfe56f98c8372ec17ea2ba00bb02/client/core/controllers/selfhosted/importController.cpp#L650).

The supported alternative is the [native `.vpn` format](https://docs.amnezia.org/documentation/supported-configuration-formats/).
Its `description` becomes the displayed server name in
[NativeServerConfig::fromJson](https://github.com/amnezia-vpn/amnezia-client/blob/ac175c8a8147cfe56f98c8372ec17ea2ba00bb02/client/core/models/selfhosted/nativeServerConfig.cpp#L100).
No SSH credentials, management access or server private key are in this client
envelope. `isThirdPartyConfig=true` retains the normal imported-client model.

## Implementation

- Single production name setting:
  `scripts/task09/manager_formats.py::SERVER_DISPLAY_NAME`.
- `vpnctl device export USER DEVICE` now defaults to named native `.vpn`.
  `--format amnezia` makes this explicit; `--format conf` retains raw AWG export.
  This intentionally changes the default output extension from `.conf` to
  `.vpn`. Both retain the `User_Device` file basename and exclusive 0600 output;
  an existing output file is never overwritten and keys are never rotated.
- Telegram device card: **📲 AmneziaVPN: профиль и QR** is the primary export.
  **📄 Совместимый .conf и QR** preserves the previous compatible export. A raw
  `.conf` import may still display `Server N`; use the native option for naming.
  Both require an explicit confirmation in the authorized private chat, retain
  Home/cancellation/replay controls and delete delivered attachments after TTL.
- The native file is `vpn://` plus URL-safe unpadded base64 of Qt-compatible
  `qCompress(JSON,8)`: four-byte big-endian length followed by a zlib stream.
  The native QR carries the same base64 **without `vpn://`**, as accepted by
  [extractConfigFromQr](https://github.com/amnezia-vpn/amnezia-client/blob/ac175c8a8147cfe56f98c8372ec17ea2ba00bb02/client/core/controllers/selfhosted/importController.cpp#L268).
  Existing raw `.conf` QR bytes/encoder are unchanged. No multi-part QR needed
  for the current profile size.
- All native structured fields come from the same raw profile; its complete
  original text is preserved in `last_config.config`. Keys, address, Endpoint,
  AllowedIPs (including IPv6 capture), MTU, keepalive and AWG2 obfuscation fields
  are unchanged. DNS metadata explicitly uses the existing resolver in both
  native slots; no secondary public fallback is introduced. Unknown INI
  directives cause a sanitized refusal instead of silent omission.
- Compression is **not encryption**. `.vpn` and its QR contain the device
  private key and follow the same protected delivery policy as `.conf`.
  Broker temporary export directories are deleted on success/failure. Neither
  attachments nor payloads are stored in bot state or logged.

## Verification

**OBSERVED, isolated Linux:** 51 TASK10 tests collected, 50 passed, one existing
privileged egress/kernel test skipped (routing was unchanged); all 31 TASK09
tests passed. Tests cover name uniformity, unchanged embedded config and every
network/key field, raw QR compatibility, native delivery and QR framing, admin
authorization, temporary-file removal and updater fault/rollback paths.

Additional opt-in `tests/task10_native_import_check.py` compiled the exact
official QR import method and official AWG/native-model `fromJson` methods from
the pinned checkout against Qt6Core. Native QR/file data decoded to identical
JSON, the native model selected the requested name, and AWG2 fields parsed
correctly. A generated PNG was scanned by zbar back to the exact native QR
payload. All keys in these tests were synthetic. Unrelated GUI/container paths
are stubbed; this is not a full GUI or physical-client connection test.
The official QR importer first tries uncompressing the base64 text, producing
an expected Qt warning, then successfully decodes/uncompresses base64.

Example isolated check (mount the pinned upstream checkout read-only):

```sh
python3 -B -m unittest discover -s tests -p 'task10*_test.py' -q
python3 -B -m unittest discover -s tests -p 'task09_*_test.py' -q
python3 -B tests/task10_native_import_check.py /upstream
```

The opt-in check needs git, g++, pkg-config, Qt6Core development files,
qrencode and zbar-tools, installed only in a disposable test container.

**OBSERVED, RU deployment 09:36:45 UTC:** staged SHA-256 verification passed.
`update_export.py` checked the exact installed baseline, saved addressed public
file backups, took the Manager lock and atomically replaced only:

- `/opt/vpn-task09/{manager_formats.py,manager_vault.py,vpnctl.py}`;
- `/opt/vpn-task10/{bot.py,broker.py,telegram_api.py,manifest.json}`.

Only TASK10 bot and broker were stopped/started. Telegram reconnected through
the existing FR connector. Existing AWG peers were byte-for-byte unchanged;
TASK06/TASK07/egress service PIDs, default routes, TASK08 active ledger and
TASK07 helper were unchanged. All Manager service diagnostics passed, drift
empty, no incomplete operations. Test_iPhone remained enabled/present; its
last handshake was 19,674 seconds old during this check, so a new physical
Test_iPhone connection was **not** claimed. Five registered devices remained.
Public manifest verification passed, and recent bot/broker logs contained no
detected profile or token. No FR, Docker, firewall, DNS or routing changes.

**OWNER-CONFIRMED:** native `.vpn`/QR imported on the real device, the automatic
name displayed correctly and VPN Internet access worked. This confirmation
preceded the final shortening of the name. The final name-only update changes
one constant, with no key, network parameter or existing profile changes; Qt
import/model and QR decoding tests were repeated using the final constant.
The exact physical app version is not known. Checking the shortened name on
the next newly created device remains an optional owner check; do not reissue
or rename existing profiles for that purpose.

At 10:03:09 UTC the name-only update was installed, with a checked rollback
preflight added to TASK10. Only bot/broker restarted; existing peers and all
network state stayed unchanged. Final verification and authorized legacy-peer
retirement are in [TASK_10_FINALIZATION.md](TASK_10_FINALIZATION.md).

## Addressed rollback

Public export-code baseline:
`/var/backups/vpn-task10/export-20261109T093645Z` (0700 directory, 0600 files).
The initial updater has pre-stop hash checks and automatic file restoration on a
detected failure. Explicit rollback checks installed update hashes, restores
only the seven public export files (removing the newly added module), restarts
only bot/broker and checks Manager health:

```sh
# First revert the final name/preflight-only update if still installed:
sudo -n python3 -I -B /opt/vpn-task10-final-20261109/task10/update_name.py --rollback /var/backups/vpn-task10/export-final-20261109T100309Z
# Optional earlier export-code rollback, only after the first step:
sudo -n python3 -I -B /opt/vpn-task10-export-20261109-named/task10/update_export.py --rollback /var/backups/vpn-task10/export-20261109T093645Z
```

Do not restore SQLite, secret files, polling offsets or any network rules for
this rollback. The staged updater remains root-owned in a 0700 directory.
Crash/power-loss recovery for this small multi-file update is not automatic;
the protected baseline is retained for addressed manual recovery over SSH.
The final TASK10 source commit is separately owner-authorized; no push.
