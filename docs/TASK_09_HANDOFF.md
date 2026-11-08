# TASK 09 — handoff

Дата: 2026-11-08

## Текущее состояние

### OBSERVED — RU

- Установлены `/opt/vpn-task09/*.py` (root:root 0644), `/usr/local/sbin/vpnctl` (root:root 0755), SQLite `/var/lib/vpn-task09/manager.sqlite3` (root-only, 0600).
- Импортированы метаданные прежнего `Test_iPhone`; ключ и профиль TASK 07 не менялись. Activation marker отсутствует, Manager timer/service не устанавливались. Изменённый `scripts/task07/helper.py` только в рабочем дереве/стейдже, не в установленном TASK 07.
- Последняя проверка: `vpn-task07-client.service` active; один live peer `10.203.253.2/32`; Manager показывает peer присутствующим, drift пустой, TASK 06/08/DNS проверки healthy. Handshake не свежий на момент проверки, поэтому подключение клиента сейчас не подтверждено.
- Сделана plaintext root-only резервная копия и проверена; `restore --stage` создавал защищённую копию без замены рабочей БД. Архив остаётся на RU; не копировать его открытым.
- FR, Docker, firewall, маршруты и peers в этой сессии не менялись.

### Подготовлено локально, не применено к dataplane

- CLI, SQLite schema, AWG adapter, vault/export, audit/operation journal, backup/verify/stage, legacy import preflight, TASK 07 startup handoff, systemd reconcile unit/timer; офлайн-тесты и TASK 09 документация.
- 34 офлайн-теста прошли; Linux Python compile и shell syntax прошли. Ограничения: ограничения скорости только записываются, не применяются; live restore отсутствует; backup не зашифрован; реальный новый клиентский peer не тестировался.
- Не делались commit/push до этого сохранения. В дереве есть более старые посторонние изменения; не включать их.

## Основной блокер

В RU TASK 08 nft-правила ограничивают источники адресом `10.203.253.2`. Для egress нового клиента требуется адресно расширить **ровно шесть** принадлежащих TASK 08 правил до `10.203.253.0/24`: prerouting anti-spoof, два DNS INPUT, forward anti-spoof, established return и RU WAN masquerade. Сохранить все интерфейсные, mark, destination-set, conntrack и fail-closed условия. Обновить pinned `ru.nft` hash и active ledger согласованно. До согласования не применять.

## Продолжение

1. Прочитать `AGENTS.md`, `README.md`, актуальные `docs/SPEC.md`, `ARCHITECTURE.md`, `SECURITY.md`, `DECISIONS.md`, `ACCEPTANCE.md`, `WORK_RULES.md`, затем этот handoff и `docs/TASK_09_VPN_MANAGER.md`.
2. Проверить `git status`, текущий commit и что предыдущий локальный commit TASK 09 присутствует. Не затрагивать прочие dirty файлы.
3. Снять новый точечный baseline TASK 07/08 RU, сохранить точные копии helper/unit, `ru.nft`, `apply.py` pinned hash, active ledger, DB и старый peer public metadata. Секреты не читать/печатать.
4. Получить требуемое владельцем единое согласование перед изменением шести RU rules, activation, любым `awg set` и перезапуском `vpn-task07-client.service`.
5. После согласования атомарно применить проверенный nft batch и согласовать hash/ledger; импорт уже сохранён, сверить прежний Test_iPhone key identity/IP без вывода ключей.
6. Установить TASK 07 SQLite-backed helper, создать activation marker, добавить один тестовый peer через `vpnctl`, экспортировать файл в защищённый каталог и проверить реальным устройством. Затем контролируемо перезапустить только TASK 07 для проверки восстановления; включить boot/timer только после успешных проверок.
7. Проверить disable/enable/revoke нового peer, старый Test_iPhone, TASK 06/08, fail-closed, SSH и FR production без изменений Docker.

## Команды проверки

- `sudo -n vpnctl --json status`
- `sudo -n vpnctl --json diagnostics`
- `sudo -n /opt/vpn-task07/awg show awg-client allowed-ips` (не использовать `showconf`/`dump`)
- `sudo -n systemctl is-active vpn-task07-client.service`
- `sudo -n /usr/local/sbin/vpn-task06 monitor`
- `sudo -n /usr/local/sbin/vpn-task08-rollback ru check`
- Backup: `sudo -n vpnctl --json backup`, затем `sudo -n vpnctl --json restore --check <archive>`.

## Адресный откат после согласованного теста

1. Остановить/отключить только TASK 09 reconcile timer и удалить activation marker.
2. Удалить только новый peer по его public identity через `vpnctl device revoke USER DEVICE` и подтвердить отсутствие этого peer; сохранить `Test_iPhone`.
3. Восстановить сохранённые `ru.nft`, pinned hash/ledger и TASK 07 helper/unit. Запустить только TASK 07, если его перезапускался.
4. Проверить старый peer `10.203.253.2/32`, TASK 06/08 и SSH. Не выполнять глобальный firewall/Docker rollback и ничего на FR.

Если rollback precondition/hash отличается от сохранённого baseline — остановиться, не применять общий rollback.

## Риски/ограничения

- Перезапуск только `vpn-task07-client.service` кратковременно прервёт клиентское соединение.
- Открытая backup содержит секретные материалы и должна оставаться root-only на RU до реализации authenticated encryption.
- `tc` ограничения скорости и полное восстановление БД в live state не готовы.
- FR production AmneziaVPN в этом этапе не диагностировался повторно; его не меняли.
