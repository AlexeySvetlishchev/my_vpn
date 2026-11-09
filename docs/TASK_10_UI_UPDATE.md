# TASK10 — navigation revision, 2026-11-09

Owner confirmed the deployed bot, QR import into AmneziaVPN, real client
connection and opening websites. This revision changes only Telegram UI/API
code; existing VPN/network/Manager components and peers remain intact.

## Behaviour

- Every navigation card, user/device view, name prompt, confirmation, error,
  exported `.conf` and QR has **🏠 Главное меню**.
- Home clears the pending name/input/confirmation scenario and invalidates the
  admin's earlier action buttons. Other administrators' sessions are unaffected.
  Home on an older attachment remains a harmless, authorized cancellation; it
  has no stored mutation or old target. Completed Manager operations are not
  undone by cancellation.
- Each new view invalidates previous action tokens; stale/replayed actions open
  the home menu without invoking Manager. Old buttons after restart cannot act.
  Authorization still applies to every message/callback, including Home.
- One text navigation panel is normally edited with
  [editMessageText](https://core.telegram.org/bots/api#editmessagetext). After
  typed input or profile attachments, a new panel is placed at the bottom and
  the old one is deleted best-effort. A missing/deleted panel is recreated.
  Old action tokens stay invalid even if Telegram cannot delete the old message.
- Duplicate success messages were replaced by a notice in the resulting card.
  Panel IDs persist, but action tokens and pending dialog state do not. No
  profile, private key, token or panel text is stored in the panel index.
- Home remains available even when the mutation/navigation rate limit is hit.

## Validation / deployment

- Linux disposable container: 44 TASK10 tests collected, 43 passed and one
  privileged kernel-routing test skipped (routing is unchanged); all 27 Manager
  regression tests passed. Navigation tests cover all Home locations, stale
  confirmations, name cancellation, replay/expiry, other-admin isolation,
  rate-limit escape, panel editing/recreation/restart and attachment navigation.
- Live Telegram renderer check: one silent temporary panel sent, two edits
  succeeded, scenario cleared, temporary panel removed. No Manager read/write
  operation was allowed in this renderer check.
- Root UI-only updater verified all other manifest hashes unchanged, saved an
  addressed backup, atomically replaced only `bot.py`, `telegram_api.py` and
  the public TASK10 manifest, then restarted only vpn-task10-bot.service.
- Telegram startup and getMe through the existing FR connector succeeded.
  Existing live peers were byte-for-byte unchanged; Manager diagnostics healthy,
  drift empty and no incomplete operations. Broker, TASK06 and TASK07 PIDs
  remained unchanged. No rules, routes, Task06–09 source/config, FR or Docker
  were modified by this revision.
- Backup: `/var/backups/vpn-task10/ui-20261109T085532Z` (root-only). Failed update
  automatically restores only those three files and restarts the bot. Do not
  restore polling offsets/state when reverting code; that could replay updates.

## Permanent profile, chosen by owner

Open `/start` → **➕ Создать пользователя**, enter your chosen name, then
**➕ Устройство**, enter your chosen device name. Open that device →
**📲 AmneziaVPN: профиль и QR** → confirm private delivery. This named native
export was added in the [profile-name update](TASK_10_PROFILE_NAME.md); a
compatible raw `.conf`/QR remains a separate option. Names are 1–32 letters/
digits, begin with a letter, with no spaces/underscore; the profile name is
constructed by Manager as User_Device. No names or profiles were pre-created.

The later [finalization](TASK_10_FINALIZATION.md) records owner confirmation of
the permanent native profile and the separately authorized revocation of
Test_iPhone. Other peers remain unchanged. Its archived identity and disabled
Test account are retained for Manager activation/startup/backup compatibility.

The final-stage download/mirror feature is recorded in [ROADMAP.md](ROADMAP.md).
No mirror, fork or distribution files were created. The final TASK10 commit is
separately authorized; no push.
