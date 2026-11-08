# TASK 07 — RU client AmneziaWG and test profile

**Scope:** one isolated client interface and one device profile on RU `218852`. The VPN Manager is out of scope. TASK 06's host-level `awg-transport` is reused and must not be reinstalled or rewritten. The FR production container `amnezia-awg2` on UDP 40905 and its Docker network are protected.

## Chosen client interface (RU stage)

| Item | Value | Basis |
|---|---|---|
| Implementation | Separate pinned userspace `amneziawg-go` and `awg`, UAPI `/run/vpn-task07/amneziawg` | Isolated client process and UAPI; later diagnosis tied TASK 06 exits to its monitor unit |
| Interface | `awg-client` | Distinct from TASK 06 `awg-transport` |
| Client network | `10.203.253.0/24` | RU live addresses/routes showed no overlap; TASK 06 uses `10.203.254.0/30` |
| Server/client address | `10.203.253.1/24` / `10.203.253.2/32` | First test peer only |
| UDP port | `51821` | RU live UDP socket check showed it free; TASK 06 uses 51983/51984 |
| MTU | `1280` | Conservative initial client value |
| Profile | `Test_iPhone.conf` | One profile with independent server and device keys |
| Initial AllowedIPs | `10.203.253.1/32` | Handshake and tunnel-address test only; no client default route or egress yet |

The RU host `net.ipv4.ip_forward` was observed as `0`; RU INPUT/FORWARD/OUTPUT iptables policies were ACCEPT, UFW inactive, and no nftables tables were listed. No global route, firewall, sysctl, NAT, or forwarding changes were made. The profile uses the AWG2-compatible obfuscation values already exercised in TASK 05/06. Separate server and test-device keys and the profile were generated on RU under root-owned `/etc/vpn-task07` (0700 directory, 0600 files). The profile was not exported or imported into a client application. It is a secret and must not enter the repository, logs, or chat.

The pinned build used `amneziawg-go` commit `b5928efb6ca19f0153958460c3d141f04abc5c2e` and tools commit `ee0f0a9aa34ff0a0da4b3433b9512781cfe02843`. Two offline builds produced identical SHA-256: `amneziawg-go` `f5868b52775eaa17a275dc1f8c451d585df70c816e283bccec9be2e9ec745e44`, `awg` `6baceec819f5e6cd716cad1640073d9a6b34ae9ef4b688a7997a50b7892acbb9`. Binaries are root-owned in `/opt/vpn-task07` on RU.

## Stage boundary and current egress blocker

The client interface can be installed and tested independently of client forwarding. The current FR snapshot has `net.ipv4.ip_forward=1`, `awg-transport` active, and production `amnezia-awg2` running with UDP 40905 published. FR iptables reports `FORWARD DROP`. Sending client Internet traffic through FR therefore requires a scoped forwarding exception on the host firewall (and a client-subnet return route/AllowedIPs extension on the existing transport); those are outside this stage and must not be applied while the owner prohibits global firewall changes. No egress success may be inferred from a client handshake.

## Files in this task package

- `scripts/task07/helper.py` — fixed command allowlist, address/port conflict checks, interface ownership ledger, key generation, profile export, status, and targeted rollback.
- `scripts/task07/build.py` and `build-go.sh` — offline pinned userspace build with an isolated UAPI directory.
- `scripts/task07/vpn-task07-client.service` — only the TASK 07 client interface lifecycle; installed but not enabled on RU.
- `tests/task07_test.py` — offline tests for profile scope, conflicts, ownership checks, and no-shell execution.

The interface helper does not invoke `awg-quick`, `wg-quick`, Docker, nftables, iptables, UFW, route/rule commands that install routes, or sysctl. The client peer is pinned to its `/32`; no default route is installed by the helper.

## RU install and smoke procedure

1. Check the local package, run `python -B -m unittest tests/task07_test.py`, and check `bash -n` only for any shell wrapper used. Verify the RU live candidate subnet, interface, and UDP port immediately before installing.
2. Transfer only `helper.py` and the unit file to a mode-0700 staging directory owned by `wolffrog`. Install root-owned copies as `/usr/local/sbin/vpn-task07` (0755) and `/etc/systemd/system/vpn-task07-client.service` (0644); run `systemctl daemon-reload`.
3. Run `sudo -n /usr/local/sbin/vpn-task07 prepare`, then start only `vpn-task07-client.service` for a scoped test. Check `vpn-task07 status`, interface address/MTU, port 51821 and unchanged default route, host routes, and TASK 06 unit. Enable autostart only after a real client test.
4. Export the profile to `/home/wolffrog/.local/share/vpn-task07/Test_iPhone.conf` (0700 directory, 0600 file), transfer it over the trusted SSH alias to a user-private temporary folder on the Windows client, import it into the already installed AmneziaVPN app, and remove both copies after import.
5. Connect briefly. Verify the expected client peer has a fresh handshake, the client can reach only `10.203.253.1` through this initial profile, then disconnect. Do not add `0.0.0.0/0`, DNS, PBR, NAT, or client egress at this point.

## PBR/NAT stage is blocked pending firewall approval

To meet the full project egress requirement, a later controlled stage needs all of the following:

1. RU IPv4 forwarding enabled and a source-policy route for `10.203.253.0/24`, with direct RU routes for classified Russian prefixes and the other IPv4 default via `10.203.254.2` over `awg-transport`.
2. A fail-closed RU forward filter: client foreign traffic is accepted only from `awg-client` to `awg-transport`; it is dropped if egress transport is unavailable and can never use `eth0`. RU destinations use narrowly matched direct-WAN forwarding and source NAT. No host default route is changed.
3. The existing transport peer's AllowedIPs/return route must cover the test client subnet. On FR, a narrowly scoped forwarding and SNAT allowance for source `10.203.253.0/24` and ingress `awg-transport` is needed. The observed FR FORWARD default is DROP. Do not alter production Docker chains or `amnezia-awg2` networking.
4. Test real client egress, DNS, direct-RU vs FR public IPv4, and a capture/counter proving foreign test packets never leave RU `eth0`; test fail-closed by stopping only the dedicated egress path and verify SSH stays available.

**Stop condition:** this next stage changes the existing FR host firewall and extends the TASK 06 transport peer's route scope. It has not been implemented or approved by this task file. No client Internet egress or DNS result is confirmed yet.

## Targeted rollback

For the isolated client-interface stage only, disconnect the test client, then on RU:

```sh
sudo -n systemctl disable --now vpn-task07-client.service
sudo -n /usr/local/sbin/vpn-task07 rollback
```

The helper deletes `awg-client` only when its name, AmneziaWG kind, ownership alias and recorded ifindex match. It removes only the TASK 07 keys/state/profile, the temporary export, and the exact TASK 07 service/helper files; it refuses unknown files or mismatched objects. It does not change TASK 06, firewall, routes, sysctl, Docker, or other services.

## Actual run and safe state (2026-11-07)

1. RU kernel AmneziaWG `awg-client` started on 51821/`10.203.253.1/24`, and TASK 06 userspace process exited during this early test. Later TASK 06 exited repeatedly with TASK 07 fully stopped, so the early correlation was not evidence of a kernel-client conflict. The first TASK 06 baseline check also rejected the new client address/route; its RU helper and manifest were updated to allow only a TASK 07 interface with matching root-owned ledger, alias, ifindex, link kind, address and kernel-generated routes. The original TASK 06 helper/manifest are retained in `/root/vpn-task06-task07-baseline-backup` on RU; FR helper was not changed.
2. A separate TASK 07 userspace service was built twice and installed. In a short diagnostic window with both interfaces, TASK 06 reported `TASK07_OWNED=True`; addresses, routes, rules and firewall hash all matched baseline; RU TASK 06 status had a fresh handshake. The expected userspace TUN link-local IPv6 address and exact kernel-generated `fe80::/64`, local link-local, and `ff00::/8` routes are the only additional allowed TASK 07 shape.
3. With TASK 07 stopped, the original TASK 06 helper still repeatedly exited and FR lost its fresh handshake. Structured diagnostics on RU showed that the child `amneziawg-go` exited cleanly with code 0 as `vpn-task06-monitor.service` completed. Directly running the same monitor command did not terminate it; the oneshot monitor unit shared `RuntimeDirectory=vpn-task06` with the transport. Removing that directive only from the monitor unit, updating its package manifest on RU and FR, and restarting the RU TASK 06 service stopped the observed restart loop. The old units/manifests are saved under `/root/vpn-task06-monitor-fix-backup` on each host.
4. After the monitor fix, the separate userspace TASK 07 interface started on RU with its root-owned ledger, alias and expected address. TASK 06 baseline remained unchanged, and RU/FR monitors both returned `healthy=true`, `tcp_echo=true`, `udp_echo=true` with a fresh handshake. Repeated systemd monitor runs did not increment the RU restart count (0 after reset) or the FR count (100 from earlier failures). The FR `amnezia-awg2` container remained `Up`, UDP 40905 published. Both default routes remained through the original WAN gateways. No Docker, global firewall, host default route, sysctl or production VPN change was made.
5. TASK 07 remains **disabled in systemd** pending a real client test; it was active for the latest short coexistence checks. The test profile has not been imported; client handshake, egress IP, DNS and leak behavior remain unobserved. Do not claim client VPN readiness from the host-only checks.

The source-controlled `scripts/task06/verify-remote.ps1` invokes fixed SSH commands directly. It replaces the one-off PowerShell here-string diagnostic that sent CRLF to `bash -s` and turned the `head -c 400` argument into `400\r`; TASK 06 source files themselves use LF. No raw shell stderr or secrets are forwarded by the helper.
