# Roadmap — remaining work

Current baseline: TASK09 and TASK10 are accepted. Telegram Manager works through
FR. Owner confirmed native `.vpn`/QR import, automatic naming and real client
Internet access. Final standard name is WolfVPN; compatibility `.conf` remains.

## Completed TASK10 acceptance

- [x] Owner created permanent profiles with personally chosen names.
- [x] Owner confirmed native import, automatic name and real VPN connectivity.
- [x] Old Test_iPhone revoked through vpnctl, removed from live AWG and excluded
  from reconcile/startup. Other peers preserved. Test account disabled.
- [ ] Decouple Manager activation/startup/backup identity from the archived
  Test_iPhone record before any physical deletion. Do not delete Test or its
  tombstone now: vpnctl activation still requires that retained identity.
- [ ] Optional: verify the final shortened name on the next new device without
  reissuing existing profiles. Host reboot acceptance remains outstanding.

## Remaining implementation / acceptance

- [ ] **TASK11:** enforced per-user/per-device QoS: design and separately approve the network
  changes; currently limits are stored/displayed but not enforced.
- [ ] Encrypted independent backups and generic live restore/conflict checks.
- [ ] Remaining transport/reboot/fail-closed client acceptance from the main SPEC.

## Final project stage — client downloads (deferred)

- [ ] Add **«📲 Скачать VPN-клиент»** to the Telegram interface.
- [ ] Offer official compatible Android, Windows and iOS clients, with current
  official source/distribution links and clear platform/version labels.
- [ ] Provide an independently reachable project mirror of official distributors;
  define the supported distribution channel for each platform at implementation.
- [ ] Verify origin and published signatures/checksums; publish SHA-256 per
  mirrored version and verify bytes before making an update available.
- [ ] Track official version updates, retain the last verified working version,
  and check both official links and mirror availability from RU without VPN.
- [ ] Preserve original package signatures; do not repackage clients or imply a
  project fork. Any fork would be a separate, explicitly approved task.

Only this roadmap entry is authorized now: no download button, mirror, fork,
hosting, distribution files or updater is being created at this stage.
