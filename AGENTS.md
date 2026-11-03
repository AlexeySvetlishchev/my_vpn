# Codex project rules — VPN RU → NL

## Authority and scope
- This repository contains the approved project baseline v1.1. Before any task, read `README.md`, `docs/SPEC.md`, `docs/DECISIONS.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/WORK_RULES.md`, and the specific task file.
- Treat approved requirements as binding. Do not redesign the architecture, substitute technologies, or broaden the task. If a requirement looks incorrect or impractical, document the concern and ask for a decision; do not implement an alternative.
- Distinguish **approved**, **to verify**, and **undecided** decisions. Use `docs/ACCEPTANCE.md` for acceptance criteria.

## Approved design essentials
- RU VPS: Ubuntu 24.04 LTS, 2 vCPU / 4 GB, initial clean installation. Client entrance: AmneziaWG. RU egress direct; other IPv4 destinations via ordinary WireGuard to NL; enforce fail-closed for NL-targeted traffic.
- NL VPS: Ubuntu 24.04 LTS, 2 vCPU / 4 GB. Existing AmneziaVPN Docker installation must remain operational during migration; remove it only in a separately approved final migration step. Target NL is a minimal WireGuard egress server.
- NL peer is addressed by a stable hostname resolved on RU through `/etc/hosts`; changing NL IP must update the running WireGuard endpoint and verify actual NL egress. Do not change client AWG configs for NL replacement.
- VPN Manager and CLI work independently of Telegram. Telegram is an optional UI and alert channel. Users have human-assigned unique names; one user can own multiple device profiles named `User_Device` (underscore, not hyphen). Per-device speed limits are set only by admins.
- Telegram registration requires one-time invitations and admin approval. Do not require Telegram ID or personal contact data in the core VPN user model. Keep any Telegram authorization bindings separate.
- Keep services lightweight; no unnecessary Docker, BGP stack, or monitoring platform.

## Safety and execution policy
- Default to **READ_ONLY** for remote machines. Do not access production over SSH without explicit authorization for that task and a configured trusted host key.
- Never execute production-changing commands without the owner's **explicit approval for the exact change**, with a backup, verification plan, and rollback strategy. In particular: no firewall flush, default-route change, SSH configuration change, network restart, Docker removal, or irreversible operations without separate approval.
- Treat `/etc/hosts`, WireGuard keys, secrets, and endpoint migration as sensitive production state. Never print or commit private keys, credentials, Telegram bot tokens, or secret configuration contents.
- Do not use unrestricted agent execution, disable approval/sandbox controls, or bypass host-key checking for convenience.
- Before editing, list the precise files to modify and expected effects. After editing, summarize changes and tests. For SSH diagnostics, report what was actually observed, not what is assumed.
- If tools, access, or evidence are missing, state **BLOCKED** and request one concrete prerequisite. Do not replace missing access with speculative research.

## Workflow
1. State the current task's scope and whether it is READ_ONLY, LOCAL_BUILD, STAGING_CHANGE, or PRODUCTION_CHANGE.
2. Read the specific approved documents needed for that scope.
3. Perform only authorized steps, minimizing commands and changes.
4. Return: observed results, files changed, tests, risks, rollback, and **one next action**.
5. Do not automatically start the next task.

Until explicitly authorized otherwise, the first local task is to validate project files and prepare an SSH connection plan **without connecting to or changing any VPS**.
