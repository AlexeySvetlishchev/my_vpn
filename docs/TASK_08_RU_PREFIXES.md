# TASK 08 — RU IPv4 prefixes, exceptions and client acceptance

Date: 2026-11-08. Scope: RU `218852` only. The FR Docker network, `amnezia-awg2`, FR firewall and both host default routes were not changed in this phase.

## OBSERVED

- The owner tested the new AmneziaVPN profile on a separate device after the RPDB/rp_filter repair: connection succeeds, sites open and ipify shows **45.15.128.138** (FR). DNS Leak Test displayed five Cloudflare resolver addresses, all identified as Paris, France. test-ipv6.com reported **No IPv6 address detected, 0/10**. These are client observations reported by the owner; they do not establish the DNS path of every application or future IPv6 behavior. The Codex Windows host is not this VPN client.
- RU's test peer and `awg-transport` are active. RU TASK 06 monitor passed fresh handshake and bidirectional TCP/UDP echo after the prefix update. FR TASK 06 monitor also passed; `docker inspect --format={{.State.Running}} amnezia-awg2` returned `true`. This container-state check is not a fresh production-client data-plane test.
- `ru_set` now contains **9,860** canonical IPv4 prefixes covering **44,452,300** addresses. `force_egress` is empty. The live sets match root-only `ru-prefix-current.json`, and the TASK 08 nft ledger hash matches the live table. `vpn-task08-rollback ru check` passed.
- Server route lookup for `77.88.8.8` with client ingress and RU mark `0x701` selected `eth0` via `137.22.146.1`. Lookups for `8.8.8.8` and `1.1.1.1` with foreign mark `0x702` selected table 220 and `awg-transport` via `10.203.254.2`. RU's host default still points to `137.22.146.1 dev eth0`; FR's still points to `45.15.128.1 dev ens3`.
- RU local DNS `10.203.253.1:53` returned A records for `example.org`; its upstream queries to `9.9.9.9`/`149.112.112.112` are source-routed through FR with an explicit unreachable fallback. Server IPv6 forwarding is 0 on both hosts. The owner's separate DNS Leak Test and test-ipv6.com results above supply the client-side check for this test session; the resolver actually selected by the application still needs separate confirmation if strict use of the exported `10.203.253.1` setting is required.
- Addressed rollback was executed once: the RU set returned to its saved original `77.88.8.8/32`, status and ledger passed, then the validated candidate was reapplied. Final status is 9,860 prefixes with matching ledger. The refresh service completed successfully, and the timer is enabled and scheduled about every 12 hours.

## Sources and classification

`scripts/task08/ru-prefix-data.py` fetches the monthly [DB-IP Lite country CSV](https://db-ip.com/db/download/ip-to-country-lite) and the daily [IPdeny aggregated RU list](https://www.ipdeny.com/ipblocks/). DB-IP Lite has reduced accuracy and coverage; its [CSV format](https://db-ip.com/db/format/ip-to-country-lite/csv.html) gives start/end addresses and country code. The classifier uses only the **intersection** of their RU IPv4 claims. Disagreements and unknown public addresses use FR. The sources describe geolocation estimates, not a complete or guaranteed set of destinations physically located in Russia. A country of resource registration is also not equivalent to physical geolocation; see the [RIPE country resource list description](https://stat-ui.stat.ripe.net/docs/data-api/api-endpoints/country-resource-list).

The selected releases during deployment had SHA-256 `e5c8459d638a272ece7f4d7cfa49dce18d91b4f403f6940ba9249bf0db3781fd` (DB-IP) and `a115697bb8cacf10c211c59848448862c05411a62b21e343e8fb3fab0cb0a645` (IPdeny). The updater records URL, SHA-256, Last-Modified and size in root-only candidate/current records. HTTPS only, exact URLs and no redirects are accepted. Downloads, age, CSV rows, number of networks and address coverage are bounded; noncanonical CIDRs, nonpublic networks and changes exceeding 10% of addresses or 20% of prefix count after the initial load are rejected. Special-use blocks and the RU/FR WAN, client and transport subnets are subtracted even if both sources label them RU. A failed download or validation leaves the last valid nft sets in place and makes the refresh service report failure.

The root-only `/etc/vpn-task08/force-egress.txt` accepts one reviewed public IPv4 CIDR per line, at most 256. It is currently empty because no service-specific exception has been approved. The existing TASK 08 prerouting rule tests `force_egress` **before** `ru_set`; this permits a service in a Russian-address block to use FR. An exception must be tied to a verified service destination, since shared/CDN IPs may affect unrelated traffic. Updating this file alone does not change live routing; a validated `prepare`/`apply` or scheduled refresh does.

## Atomic update and recovery

The RU-only `ru-prefix-update.py` owns only `ru_set` and `force_egress` in `ip vpn_task08_ru`. `prepare` stores root-only baseline, ledger and validated candidate. `apply` checks live set ownership and ledger, runs `nft -c`, pauses the TASK 06/08 periodic checks, waits for active checks to finish, then sends one nftables transaction containing flush/add operations for the two sets. It verifies the resulting sets and ledger and saves previous/current records. On a failed post-transaction check, it restores the previous two sets and ledger; if that restoration fails, RU IPv4 forwarding is disabled. No global ruleset flush occurs. The TASK 08 recovery source restores the saved current set after reboot when its own table is absent, before accepting the new ledger hash. `vpn-task08-ru-prefixes.timer` starts refresh after boot and about every 12 hours.

Installed on RU: `/opt/vpn-task08/{ru-prefix-data.py,ru-prefix-update.py,recover.py}`, `/etc/vpn-task08/force-egress.txt`, `vpn-task08-ru-prefixes.service/.timer`, root-only `/var/lib/vpn-task08/ru-prefix-{baseline,candidate,current,previous}.json` and `active-before-ru-prefixes.json`. The previous `recover.py` is backed up under root-only `/var/lib/vpn-task08/backup/recover.pre-ru-prefix.py`. No component was installed on FR for prefix refresh.

Addressed prefix rollback (keeps TASK 06/07 and the rest of TASK 08 running):

```sh
ssh vpn-ru 'sudo -n systemctl disable --now vpn-task08-ru-prefixes.timer'
ssh vpn-ru 'sudo -n /usr/bin/python3 -I -B /opt/vpn-task08/ru-prefix-update.py rollback'
ssh vpn-ru 'sudo -n /usr/bin/python3 -I -B /opt/vpn-task08/ru-prefix-update.py status'
```

This restores the previous validated set; immediately after initial deployment that is the original `/32`. For full TASK 08 rollback, use the separate, already checked `vpn-task08-rollback` procedure in [TASK_08_DEPLOYMENT_RESULT.md](TASK_08_DEPLOYMENT_RESULT.md). Never roll back Docker globally.

## RU client branch check — completed 2026-11-08

On the **separate device with this test profile**, while it is connected:

1. With the test profile connected, open `http://77.88.55.242/` once on that device. A 406 response is acceptable; the destination is an observed A record for `ya.ru` and was confirmed in the live `ru_set` as part of `77.88.52.0/22`. Its site geolocation is not evidence of egress by itself.
2. In the same short window, observe headers only on RU `awg-client` for source `10.203.253.2` to destination `77.88.55.242`, and on RU `eth0` for source `137.22.146.212` to that destination. Count matching packets on both interfaces and verify replies. This proves the client packet was classified and source-NATed out RU WAN without modifying nftables rules or production configuration.
3. Preserve the owner's already reported foreign egress, DNS Leak Test and test-ipv6.com results separately from this RU path observation. The exported profile specifies `DNS = 10.203.253.1`, but an earlier capture showed requests to `1.1.1.1`/`1.0.0.1` through FR; the leak test does not identify which setting the app actually selected.

Fail-closed was checked earlier with a brief RU TASK 06 interruption: foreign `0x702` lookup did not fall back to RU WAN and transport recovered. A real client packet during transport failure was not sent in that test.

Preparation for the RU client check on 2026-11-08: `77.88.55.242` was confirmed in live `ru_set` (`77.88.52.0/22`), and `ip route get` with client ingress/mark `0x701` chose `eth0` via `137.22.146.1`. A 180-second header-only `tcpdump` filter for this destination captured **zero** matching packets while no client request was confirmed; this is not evidence that the RU path works or fails. No firewall rule, route or service was changed for this observation. Repeat a short capture when the separate test device actually opens the URL.

After the owner reported sending an HTTP request from the test device, a further **12-second** header-only capture on RU again recorded zero matching packets. The request preceded the capture; therefore no inference about the path follows. The subsequent synchronized check resolved this timing issue: the owner signaled readiness, RU started a short capture, then the device opened the URL.

**OBSERVED in the synchronized check.** With the new VPN profile enabled on the separate device, the owner opened `http://77.88.55.242/` after the RU capture started. A 20-second header-only `tcpdump -i any` recorded **22 packets, zero kernel drops**: six client-origin packets entered `awg-client` as `10.203.253.2:49262 → 77.88.55.242:80`; six corresponding packets left RU `eth0` as `137.22.146.212:49262 → 77.88.55.242:80`, proving RU source NAT. Five replies entered `eth0` and five left `awg-client` toward `10.203.253.2`. The capture included 374-byte outbound and 813-byte inbound TCP payload lengths; it did not inspect payload content. No matching packet appeared on `awg-transport`. The destination was confirmed in the live `ru_set` (`77.88.52.0/22`), and the client-ingress route lookup with mark `0x701` selected RU `eth0`. Thus this real client flow used RU WAN and did not traverse the FR tunnel. The temporary capture file was removed; RU prefix ledger, TASK 06 monitor and TASK 08 rollback check passed afterward. No production firewall, route or service was changed for the observation.

**TASK 08 result.** Real-client FR IPv4, RU direct IPv4, DNS Leak Test and test-ipv6.com observations are recorded. The server-side fail-closed test remains valid; end-to-end fail-closed with a real client during FR failure and longer-term operation are distinct acceptance checks not performed in this short test.
