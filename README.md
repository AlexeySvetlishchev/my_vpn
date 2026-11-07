# VPN RU → FR — проект (редакция требований 2026-11-07)

**Статус:** нормативная документация проекта обновлена по baseline v1.1. На VPS развёрнут только постоянный host-level AmneziaWG RU↔FR по TASK 06; клиентский VPN, PBR/NAT/DNS и egress не включены.

## Серверы

- RU `218852` (`218852.ru`) — `137.22.146.212`, Ubuntu 24.04, 2 vCPU ~4 ГБ; AmneziaWG установлен, production клиентский VPN не запущен.
- FR `hiplet-142983` — `45.15.128.138`, Ubuntu 24.04.5, **1 vCPU / 961 МиБ**; нужный владельцу AmneziaVPN уже работает в Docker (`amnezia-awg2`, UDP 40905). **Не останавливать, не удалять и не повреждать.**
- Старая VPS NL в текущих настройках не участвует.

## Цель

Клиентский AmneziaWG → RU → российские назначения напрямую / прочие через сменяемый иностранный egress (сейчас FR — кандидат). Для иностранного трафика fail-closed. VPN Manager (SQLite, `vpnctl`) и уникальные устройства, скорость, статистика, бэкапы, необязательный Telegram. Менять зарубежный узел без перевыпуска клиентских конфигов.

Обычный WireGuard RU↔FR не используется после нестабильного испытания. Владелец принял короткий userspace AmneziaWG transport smoke и затем постоянный изолированный TASK 06 service: handshake и двусторонний UDP/TCP echo проверены, включая recovery после рестарта каждой собственной службы. 15-минутная нагрузка, host reboot, production client data plane и клиентский egress не проверены. На FR общий nftables INPUT DROP фильтрует ICMP; firewall не менялся. Production Docker `amnezia-awg2`/UDP 40905 защищён и не используется новым транспортом.

## Правила приоритета

1. Последнее явное решение владельца.
2. `docs/SPEC.md` — нормативные требования.
3. `docs/SECURITY.md` и `docs/DECISIONS.md` — ограничения и решения с пометками SUPERSEDED.
4. `docs/ARCHITECTURE.md` и `docs/ACCEPTANCE.md` — схема/проверки.
5. `docs/WORK_RULES.md`, `AGENTS.md` — порядок действий исполнителя.
6. Старые TASK и `NL_*` — исторические, не разрешение выполнять команды.

## Доступ Codex

Windows workspace `C:\Users\User\Projects\vpn-ru-nl` (рабочий Git-репозиторий владельца). SSH `vpn-ru`, `vpn-fr`, пользователь `wolffrog`, отдельные локальные SSH-ключи; read-only аудит разрешён, production changes — отдельно одобряемые этапы. Серверные секреты не переносить в Git. Никаких `NOPASSWD: ALL`.

## Файлы

`docs/SPEC.md` — ТЗ; `docs/ARCHITECTURE.md` — схема; `docs/DECISIONS.md` — журнал решений; `docs/SECURITY.md` — угрозы/доступ; `docs/ACCEPTANCE.md` — приёмка; `docs/WORK_RULES.md` и `AGENTS.md` — правила; `docs/NL_*.md` — архив, `docs/TASK_01_PREFLIGHT.md` — архив.
