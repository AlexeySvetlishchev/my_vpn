# VPN RU → FR — проект (редакция требований 2026-11-07)

**Статус (2026-11-08):** TASK 06 транспорт и TASK 07 клиентский AmneziaWG активны. TASK 08 PBR/NAT/DNS и консервативный RU IPv4 set включены. На отдельном устройстве подтверждены FR IPv4 `45.15.128.138`, RU WAN/NAT для российского адреса, пять DNS Leak Test адресов Cloudflare в Paris и отсутствие обнаруженного публичного IPv6 (`0/10` на test-ipv6.com). Серверный fail-closed проверен; клиентский тест во время отказа FR и длительная работа остаются отдельными проверками. Подробности: [развёртывание TASK 08](docs/TASK_08_DEPLOYMENT_RESULT.md), [RU prefixes](docs/TASK_08_RU_PREFIXES.md).

## Серверы

Обновление 2026-11-09: TASK09 VPN Manager внедрён; TASK10 Telegram adapter
работает на RU через FR с изоляцией только его соединений. Фактические проверки,
ограничения и откат: [TASK09](docs/TASK_09_DEPLOYMENT_RESULT.md),
[TASK10](docs/TASK_10_DEPLOYMENT_RESULT.md). QoS ещё не применяется.

TASK10 закрыт: владелец подтвердил нативный `.vpn`/QR и работу VPN; стандартное
имя новых экспортов — **WolfVPN**. Test_iPhone отозван, Test отключён и сохранён
как техническая запись. [Итоги, проверки и откат](docs/TASK_10_FINALIZATION.md).
Следующий этап — TASK11 QoS, без уже включённого ограничения скорости.

- RU `218852` (`218852.ru`) — `137.22.146.212`, Ubuntu 24.04, 2 vCPU ~4 ГБ; клиентский AmneziaWG, VPN Manager и административный Telegram работают.
- FR `hiplet-142983` — `45.15.128.138`, Ubuntu 24.04.5, **1 vCPU / 961 МиБ**; нужный владельцу AmneziaVPN уже работает в Docker (`amnezia-awg2`, UDP 40905). **Не останавливать, не удалять и не повреждать.**
- Старая VPS NL в текущих настройках не участвует.

## Цель

Клиентский AmneziaWG → RU → российские назначения напрямую / прочие через сменяемый иностранный egress (сейчас FR — кандидат). Для иностранного трафика fail-closed. VPN Manager (SQLite, `vpnctl`) и уникальные устройства, скорость, статистика, бэкапы, необязательный Telegram. Менять зарубежный узел без перевыпуска клиентских конфигов.

Обычный WireGuard RU↔FR не используется после нестабильного испытания. Постоянный userspace TASK 06 transport проверен handshake и двусторонним UDP/TCP echo, включая recovery после рестарта каждой собственной службы. Новый тестовый клиент подтвердил FR egress. 15-минутная нагрузка и host reboot не проверялись. На FR общий nftables INPUT DROP фильтрует ICMP; production Docker `amnezia-awg2`/UDP 40905 защищён и не используется новым транспортом.

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
