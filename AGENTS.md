# AGENTS.md — VPN RU → FR (2026-11-08)

## Источник истины
Прочитать `README.md`, `docs/SPEC.md`, `docs/DECISIONS.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/ACCEPTANCE.md`, `docs/WORK_RULES.md`. Устаревшие `NL_*` и `TASK_01` — **HISTORICAL**, не управляют текущей работой. Если в коде или шаблоне встречается `wg-nl`, `nl-egress.internal`, `vpnctl nl set-ip` или обычный WG как обязательный, не запускать его: требуется миграция и ревью.

## Инфраструктура
- `vpn-ru` → `218852` / `137.22.146.212`, `wolffrog`; TASK 07 `awg-client` активен, TASK 08 PBR/NAT/DNS и консервативный RU IPv4 set работают. TASK09 Manager и TASK10 административный Telegram через FR приняты. Новые нативные `.vpn`/QR экспорты получают имя WolfVPN; `.conf` сохранён. Test_iPhone отозван и отсутствует в AWG, Test отключён; их архивную запись не удалять — activation/startup/backup зависят от неё. Актуальный отчёт: `docs/TASK_10_FINALIZATION.md`. QoS ещё не применяется.
- `vpn-fr` → `hiplet-142983` / `45.15.128.138`, `wolffrog`; production Docker `amnezia-awg2`/UDP 40905 **запрещено нарушать или удалять**. FR 1 vCPU / 961 МиБ. Привилегированный аудит, TASK 05 smoke и TASK 06 transport приняты. Production-клиент проверялся до/после TASK 08 FR firewall; в текущем RU geodata этапе подтверждён только статус контейнера. 15-минутная устойчивость и host reboot не проверены.
- NL вне текущего развёртывания. Межсерверный RU↔FR userspace AmneziaWG `awg-transport` работает как отдельный systemd service. На отдельном устройстве подтверждены FR IPv4 `45.15.128.138`, RU WAN/NAT для российского назначения, пять Cloudflare DNS Leak Test адресов Paris и отсутствие обнаруженного публичного IPv6 (`0/10`). Windows с Codex не является VPN-клиентом.

## Работа Codex
- Доступ по отдельным SSH-ключам `codex_ru` и `codex_fr` проверен, алиасы настроены. SSH вход не означает root/sudo доступ и не авторизует изменения.
- READ_ONLY доступен в рамках явно установленной области. `PRODUCTION_CHANGE` — только отдельное разрешение владельца на конкретные изменения, с baseline, бэкапом, проверками и адресным rollback.
- Не менять FR Docker/AmneziaVPN, firewall/маршруты, SSH, sysctl, default routes без отдельного согласования. Не отключать sandbox, approvals или host-key checking.
- Не читать и не выводить секреты, приватные ключи, токены, Docker environment, полные VPN-конфиги; не коммитить их.
- Каждая задача: цель, затрагиваемые хосты, разрешённые команды/эффекты, проверки, rollback. Отчёт разделяет `OBSERVED` / `INFERRED` / `PROPOSED` / `BLOCKED`. Не считать один handshake успешной передачей данных; для TASK 05 успех принят по двустороннему UDP/TCP echo.
- Запрещена самостоятельная реализация старого RU→NL/WG ТЗ, автоматический демонтаж Docker после запуска проекта, изменение пользовательских клиентских конфигов при замене зарубежного узла.

## Принципы проекта
RU AmneziaWG клиенты, RU IP напрямую, остальные через зарубежный egress, fail-closed, смена egress без смены клиентских профилей. VPN Manager + обязательный `vpnctl`, SQLite, `User_Device`, индивидуальные ключи/лимиты, необязательный Telegram, лёгкие сервисы, защита IPv6/DNS утечек.
