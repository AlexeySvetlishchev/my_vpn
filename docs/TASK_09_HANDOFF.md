# TASK 09 — handoff

Дата: 2026-11-08

Актуально после разрешённого обслуживания: TASK09 внедрён на RU; SQLite-backed
helper активирован, шесть правил расширены, reconcile timer включён. Фактические
проверки, ограничения и адресный откат: [TASK_09_DEPLOYMENT_RESULT.md](TASK_09_DEPLOYMENT_RESULT.md).
Разделы ниже сохраняют историю подготовки и прежних ограничений; их запрет на
внедрение заменён последующим прямым разрешением владельца.

## Текущее состояние

### OBSERVED — RU

- Установлены `/opt/vpn-task09/*.py` (root:root 0644), `/usr/local/sbin/vpnctl` (root:root 0755), SQLite `/var/lib/vpn-task09/manager.sqlite3` (root-only, 0600).
- Импортированы метаданные прежнего `Test_iPhone`; ключ и профиль TASK 07 не менялись. Activation marker отсутствует, Manager timer/service не устанавливались. Изменённый `scripts/task07/helper.py` только в рабочем дереве/стейдже, не в установленном TASK 07.
- Последняя проверка: `vpn-task07-client.service` active; один live peer `10.203.253.2/32`; Manager показывает peer присутствующим, drift пустой, TASK 06/08/DNS проверки healthy. Handshake не свежий на момент проверки, поэтому подключение клиента сейчас не подтверждено.
- Сделана plaintext root-only резервная копия и проверена; `restore --stage` создавал защищённую копию без замены рабочей БД. Архив остаётся на RU; не копировать его открытым.
- Установка TASK 07 helper по фактическому пути `/usr/local/sbin/vpn-task07` была опробована и адресно отменена. Новая версия изменила hash, контролируемый TASK 08 ownership/rollback; диагностика перешла в `task08_ownership=false`. После возврата исходного helper TASK 08 `ru check` снова показал `rollback_ready=true`, Manager diagnostics — ownership healthy. Исходник сохранён root:root 0755 в `/var/lib/vpn-task09/rollback/vpn-task07.before-task09`. Сейчас установлен старый helper; live peer не менялся.
- FR, Docker, firewall, маршруты и peers в этой сессии не менялись.

### Подготовлено локально, не применено к dataplane

- CLI, SQLite schema, AWG adapter, vault/export, audit/operation journal, backup/verify/stage, legacy import preflight, TASK 07 startup handoff, systemd reconcile unit/timer; офлайн-тесты и TASK 09 документация.
- 34 офлайн-теста прошли; Linux Python compile и shell syntax прошли. Ограничения: ограничения скорости только записываются, не применяются; live restore отсутствует; backup не зашифрован; реальный новый клиентский peer не тестировался.
- Не делались commit/push до этого сохранения. В дереве есть более старые посторонние изменения; не включать их.

## Основной блокер

В RU TASK 08 nft-правила ограничивают источники адресом `10.203.253.2`. Для egress нового клиента требуется адресно расширить **ровно шесть** принадлежащих TASK 08 правил до `10.203.253.0/24`: prerouting anti-spoof, два DNS INPUT, forward anti-spoof, established return и RU WAN masquerade. Сохранить все интерфейсные, mark, destination-set, conntrack и fail-closed условия. Обновить pinned `ru.nft` hash и active ledger согласованно. До согласования не применять.

## Продолжение

1. Прочитать `AGENTS.md`, `README.md`, актуальные `docs/SPEC.md`, `ARCHITECTURE.md`, `SECURITY.md`, `DECISIONS.md`, `ACCEPTANCE.md`, `WORK_RULES.md`, затем этот handoff и `docs/TASK_09_VPN_MANAGER.md`.
2. Проверить `git status`, текущий commit и TASK 09 commit. Не затрагивать прочие dirty файлы.
3. Снять точечный baseline TASK 07/08 RU: точные копии `/usr/local/sbin/vpn-task07`, unit, `/opt/vpn-task08/ru.nft`, `apply.py` и его `NFT_HASH['ru']`, active ledger, SQLite DB, OWNED nft table/rules/handles и public metadata/IP единственного peer. Не читать/печатать секреты.
4. Подготовить согласованную пару артефактов: (a) SQLite-backed helper по фактическому пути `/usr/local/sbin/vpn-task07`; (b) TASK 08 ownership package с новым ожидаемым helper hash и согласованными `ru.nft` hash, active ledger `own_table_sha256`, pinned source hash. Не ослаблять проверки: обновить expected hash только на точное SHA-256 проверенного helper, оставить проверку owned nft objects/handles и всех TASK 08 predicates включённой.
5. До установки запустить офлайн-тесты генерации обновлённых `ru.nft`, проверки pinned hash/ledger и rollback preconditions. На RU проверить rollback readiness в исходном состоянии; затем staged-копии новых артефактов должны пройти те же ownership/hash checks без применения. Обновление должно быть атомарным для nft batch, а package/helper/ledger публиковать в порядке, при котором recovery либо видит полностью старую валидную версию, либо полностью новую; при прерванном обновлении не запускать общий recovery до ручной проверки сохранённого baseline.
6. Получить одно требуемое владельцем согласование. Сначала применить адресную версию TASK 08 и согласовать source hash + active ledger, доказать `ru check`, fail-closed lookup и сохранность исключения `10.203.253.1`; затем установить новый helper атомарно по `/usr/local/sbin/vpn-task07` и проверить `ru check`/diagnostics. Пока marker не изменён, helper при следующем старте сохраняет legacy fallback peer.
7. Отдельно после согласования cutover записать activation marker, сверить SQLite identity с прежним Test_iPhone, затем разрешённые операции с peer. Без отдельного разрешения на restart остановиться до проверки восстановления: запущенный процесс загрузил старый код и новый startup handoff начинает действовать при следующем старте.
8. После разрешённого restart проверить Test_iPhone, TASK 06/08, fail-closed, SSH и FR production; включать boot/timer только после успешных проверок. Тест нового клиента и peer lifecycle — отдельная следующая граница разрешения.

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
2. Удалить только добавленный TASK 09 peer по записанному public identity; сохранить Test_iPhone.
3. Восстановить исходный helper из `/var/lib/vpn-task09/rollback/vpn-task07.before-task09`, mode 0755; восстановить сохранённые TASK 08 `ru.nft`, `apply.py` pin и active ledger согласованно. Проверить `/usr/local/sbin/vpn-task08-rollback ru check` до любого рестарта.
4. Если служба была перезапущена, запустить только `vpn-task07-client.service`; проверить старый peer `10.203.253.2/32`, TASK 06/08 и SSH. Не выполнять глобальный firewall/Docker rollback и ничего на FR.

Если rollback precondition/hash отличается от сохранённого baseline — остановиться, не применять общий rollback.

## Риски/ограничения

- Перезапуск только `vpn-task07-client.service` кратковременно прервёт клиентское соединение.
- Открытая backup содержит секретные материалы и должна оставаться root-only на RU до реализации authenticated encryption.
- `tc` ограничения скорости и полное восстановление БД в live state не готовы.
- FR production AmneziaVPN в этом этапе не диагностировался повторно; его не меняли.

## TASK 08 → TASK 09 migration prototype (2026-11-08)

### Implemented and locally verified

- `scripts/task09_review/task09_linux_backend.py` composes durable storage with
  an nft adapter restricted to an explicitly named network namespace; no
  production/root-namespace install entry point exists.
- Storage now shares the real TASK08 updater lock
  `/var/lib/vpn-task08/ru-prefix-update.lock` (root mode), then acquires the
  separate TASK09 migration lock, both nonblocking. This corrects the earlier
  mismatch where migration had locked its own state directory instead.
- Migration validates the staged `ru.nft`, `apply.py`, `rollback.py`, and
  `vpn-task07` pins together through `task09_integrity.validate()`. It journals
  the exact TASK08 owned nft baseline snapshot, not stale handles. Post-change
  and recovery checks prove that only the six expected rule expressions and
  the reserved-address guard differ; all other owned rules, chains, sets and
  dynamic `ru_set`/`force_egress` members must match. Reverse commands use a
  fresh snapshot and current handles.
- Files use fsynced temporary files, exact modes, atomic rename and parent
  directory fsync. Journal transitions and recovery are tested at each boundary;
  a reverse failure retains the journal and calls fail-closed rather than
  deleting or guessing at changed state.
- Offline Linux test run: **63 passed, 1 skipped** (the real-nft test is skipped
  by the general suite because that image lacks `nft`). Separate isolated
  Docker network namespace run with `nftables` installed: **real kernel apply
  and reverse passed**, with the canonical owned hash restored and populated
  `ru_set` and `force_egress` data preserved. No RU/FR host was used.

### Still blocked from live RU use

- The named-network-namespace adapter was tested with a mocked command runner,
  not through a newly created named namespace. The disposable Docker container
  itself supplied the isolated kernel network namespace for the real nft test.
- No boot-time recovery unit or operational maintenance gate is implemented.
  nft and several file/ledger renames cannot be one atomic transaction; before
  live use a reviewed gate must keep client traffic fail-closed throughout the
  inconsistent window and guarantee journal recovery before TASK08/09 resume.
- The RU kernel/nft version and complete live Russian-prefix/force-egress sets
  (including their full live element counts) were not exercised. Only synthetic
  dynamic set entries were used in the isolated real-nft test.
- Therefore the migrator is **not ready for live application**. The live
  helper, Test_iPhone keys/IP/profile, nftables, and both VPS remain untouched.
