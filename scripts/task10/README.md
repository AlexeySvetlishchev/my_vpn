# TASK10 components and operational scope

Current behaviour, deployment and final accepted evidence:
`docs/TASK_10_TELEGRAM_MANAGER.md`, `TASK_10_DEPLOYMENT_RESULT.md`,
`TASK_10_PROFILE_NAME.md`, `TASK_10_FINALIZATION.md`.

Runtime: bot/broker entrypoints, bot.py, broker.py, egress connector/control,
telegram_api.py, qr.py, rollback_entry.py, three systemd units and manifest.json.
Native client formatting belongs to the shared TASK09 Vault/CLI, not bot logic.

Installation/credentials: install.py, provision.py, collect_credentials.pyw.
The GUI stores a protected intake outside Git; neither token nor actual admin
ID is an input to a logged shell command. check_credentials_local.py is an
optional Windows intake/API check, not an RU direct-access requirement.

Export/UI updates: update_ui.py, update_export.py and update_name.py are
baseline-pinned, sequential deployment tools for their documented versions.
Their addressed rollback refuses newer drift. Never run an older updater over
the final deployment. Publish verified staged files using SCP and simple SSH,
not inline secret-bearing shell expressions. Retain protected backups on RU.

Checks/cleanup:

- final_check.py: bounded read-only routes/DNS/egress/activation/boot check;
  requires Test_iPhone to have been retired. Does not export a real profile.
- verify_export.py: read-only installed hashes, log signatures and Manager.
- ui_smoke.py: one silent temporary private panel and two edits, then deletion;
  no Manager operations, creates no user/device/profile.
- review_index.py: local, read-only syntax/secret-signature/runtime-artifact
  scan and public manifest validation against the actual Git-index bytes.
- retire_legacy.py: **owner-authorized mutation**, only Test/iPhone revoke and
  disabling an otherwise empty Test account, through vpnctl. Makes/verifies a
  protected backup, preserves other devices and required identity tombstones.
  Revocation is terminal. Do not run for any other user/device.

Historical one-time acceptance tools (do not run as a routine health check):

- live_acceptance.py creates TelegramTest/Phone and sends its secret exports;
  the accepted scenario has already run and its user is deleted. Repeating it
  needs a separately approved test identity and a reviewed scenario.
- cleanup_acceptance.py deletes only the recorded test's expired attachments.
- verify_live.py temporarily changes **TASK10's own** lookup rule to exercise
  no-fallback. It is not read-only; do not run without that test's authorization.
- recovery_check.py stops/starts TASK10 routing/services and executes TASK08
  recovery against its historical baseline. Not part of final read-only checks.
- verify_ui.py is the historical pre-retirement Test_iPhone/UI verification.
- check_connectivity.py was an initial direct-access diagnostic; direct Telegram
  from RU is not required and must not replace the FR-only connector.

No runtime state, secret intake, archives, keys or exported profiles belong in
this directory. `.vpn`/`.conf` are sensitive regardless of compression.
