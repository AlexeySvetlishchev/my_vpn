# TASK 08 — фактическое развёртывание, 2026-11-07–08

Статус: TASK 08 клиентское разделение IPv4 проверено на отдельном устройстве: FR egress, RU egress, DNS Leak Test и отсутствие обнаруженного публичного IPv6. Короткий серверный fail-closed test прошёл; end-to-end fail-closed с реальным клиентом при отказе FR и длительная работа не проверялись.
План и границы разрешения: [TASK_08_CLIENT_EGRESS_APPROVAL_PLAN.md](TASK_08_CLIENT_EGRESS_APPROVAL_PLAN.md).

## OBSERVED

- До изменения FR firewall реальный Windows-клиент production AmneziaVPN имел поднятый адаптер, default route через него, успешный HTTPS IP echo и публичный IPv4 `45.15.128.138`. Та же проверка прошла сразу после изменения и после восстановления TASK 06. Контейнер `amnezia-awg2` оставался `Up`. Docker network, конфигурация контейнера и UDP 40905 не менялись.
- На RU создана отдельная nft table `ip vpn_task08_ru` с anti-spoof, INPUT/FORWARD/OUTPUT guard и NAT. RPDB pref 10000–10033 и table 220 направляют foreign-клиентский IPv4 через `10.203.254.2 dev awg-transport`. `net.ipv4.ip_forward=1`. Default route RU прежний.
- На FR создана собственная NAT table `ip vpn_task08_fr`, chain `ip filter vpn_task08_fr_forward` и один jump в существующей `FORWARD` после `DOCKER-USER`, перед `DOCKER-FORWARD`. Добавлен return route `10.203.253.0/24 dev awg-transport`. Docker-цепочки не редактировались; default route FR прежний.
- На RU установлен только `dnsmasq-base`; отдельный `vpn-task08-dns.service` слушает только `10.203.253.1:53` по IPv4. Upstream `9.9.9.9` и `149.112.112.112` привязаны к `awg-transport` и source `10.203.254.1`. DNS-запрос получил `rcode=0`, два answer records. Системный resolver RU не менялся.
- Тестовый root-only профиль TASK 07 обновлён: `AllowedIPs = 0.0.0.0/0, ::/0`, `DNS = 10.203.253.1`. Ключи не выводились и не копировались в репозиторий. Обновлённый helper прошёл `prepare` и `status`; handshake нового клиента отсутствует.
- В отдельном network namespace на обеих VPS проверены создание, адресное удаление и восстановление TASK 08 nft objects. Локально прошли 26 unit tests. После перезапуска только TASK 06 на RU/FR собственные TASK 08 routes восстановились; TASK 06 подтвердил handshake и двусторонний TCP/UDP echo. SSH оставался доступен.
- Foreign lookup `1.1.1.1` с `iif awg-client`, mark `0x702` выбрал table 220. Тестовый RU `77.88.8.8` с mark `0x701` выбрал RU WAN. Первоначальный немаркированный lookup получил `Network is unreachable`, однако это же безусловное правило мешало проверке обратного пути ядром. Его замена при первом реальном клиентском тесте описана ниже. При краткой остановке RU TASK 06 foreign lookup не получил RU WAN; собственные службы и TCP/UDP echo затем восстановились.
- `vpn-task08-egress.timer` включён на обоих VPS и вызывает адресную проверку/восстановление каждые 30 секунд; RU DNS имеет собственный systemd restart. Старый профиль и helper, TASK 06 helper/manifest и сетевой baseline хранятся в root-only `/var/lib/vpn-task08/backup` и `prechange.json`.
- Дополнительно RU forwarding кратко переключён в `0` и восстановлен **самой** `vpn-task08-egress.service` в `1`; сразу после этого TASK 06 TCP/UDP monitor снова прошёл. Это проверяет восстановление sysctl службой без host reboot.

## INFERRED

RPDB terminal `unreachable` для mark `0x702` и RU nft FORWARD guard препятствуют fallback foreign-трафика на RU WAN при потере transport. Это подтверждено route lookup при остановленной TASK 06, но реальный клиентский пакет в этом сценарии не отправлялся. FR production-клиент сохранил выход по фактическому внешнему IP echo после FR firewall transaction.

## Исторические ограничения первого server-side развёртывания

- На момент первого server-side развёртывания новый RU-клиентский профиль ещё не был импортирован. Последующий фактический клиентский тест описан ниже.
- На момент первого server-side развёртывания `ru_set` содержал лишь тестовый `/32`. Последующее обновление набора описано в [TASK_08_RU_PREFIXES.md](TASK_08_RU_PREFIXES.md).
- Автозапуск после host reboot подготовлен systemd units/timers, но reboot не проводился. Длительный тест не проводился по просьбе владельца. Активность конкретного peer внутри production-контейнера не проверялась, хотя внешний production-клиентский data plane подтверждён.

## Состав и адресный откат

- RU: `/opt/vpn-task08/{ru.nft,apply.py,recover.py,dnsmasq.conf}`, `/usr/local/sbin/{vpn-task08-snapshot,vpn-task08-rollback}`, `vpn-task08-egress.service`, `vpn-task08-egress.timer`, `vpn-task08-dns.service`, пакет `dnsmasq-base`, root-only `/var/lib/vpn-task08/{prechange.json,active.json,backup}`.
- FR: `/opt/vpn-task08/{fr.nft,apply.py,recover.py}`, `/usr/local/sbin/{vpn-task08-snapshot,vpn-task08-rollback}`, `vpn-task08-egress.service`, `vpn-task08-egress.timer`, root-only `/var/lib/vpn-task08/{prechange.json,active.json,backup}`.
- Адресный rollback выполняется сначала на RU: `ssh vpn-ru 'sudo -n /usr/local/sbin/vpn-task08-rollback ru run'`; затем на FR: `ssh vpn-fr 'sudo -n /usr/local/sbin/vpn-task08-rollback fr run'`. Он выключает RU forwarding, отключает собственные timers/DNS, удаляет только проверенные TASK 08 rules/routes/nft objects и восстанавливает сохранённые TASK 06 helper/manifest и тестовый TASK 07 профиль/helper. `rollback check` прошёл на обоих VPS. Live `run` не выполнялся, поскольку он отключил бы включённый тестовый dataplane. Пакет `dnsmasq-base` и неактивные файлы TASK 08 после отката остаются на RU; исходная сеть будет восстановлена.

## Первый реальный клиентский тест — адресная диагностика 2026-11-08

**OBSERVED.** AmneziaVPN на тестовом устройстве показывал подключение, сайты не открывались. На RU у TASK 07 peer был свежий handshake, его RX рос, TX почти не рос. Короткий capture на `awg-client` показал клиентские DNS и TCP/UDP пакеты. На FR `awg-transport` получал эти пакеты и отправлял ответы; RU `awg-transport` получал ответы, однако `awg-client` не отправлял их устройству. Временные счётчики в собственной RU TASK 08 nft table за 5 секунд показали 108 ответных пакетов в PREROUTING и 0 в FORWARD. Счётчики удалены; baseline TASK 06 после cleanup снова прошёл.

**INFERRED, затем проверено маршрутом.** Безусловное RPDB pref 10020 `iif awg-client unreachable` попадало в reverse-path lookup Linux для ответов из FR. При `rp_filter=2` и `src_valid_mark=0` это давало `Invalid cross-device link` до FORWARD. Проверка route get после удаления безусловного правила успешно выбрала `dev awg-client`. Это исправление находится внутри согласованного TASK 08, общие sysctl и FR firewall не менялись. Поведение `rp_filter` и `src_valid_mark` описано в [документации ядра Linux](https://docs.kernel.org/networking/ip-sysctl.html).

**Изменение.** На RU terminal rule заменён на pref 10021 `iif awg-client fwmark 0x702 unreachable`; он ловит потерю foreign table 220, но не перекрывает немаркированный reverse-path lookup ядра. Непомеченный клиентский пакет по-прежнему отбрасывается RU nft FORWARD guard. Изменены только TASK 08 `apply.py`, `recover.py`, `rollback.py`, root-owned RPDB ledger и собственно RU rule. Предыдущие копии скриптов сохранены в root-only backup. TASK 06, FR, Docker и production VPN не менялись.

**OBSERVED после изменения.** RU `awg-client` стал отправлять устройству ответные DNS, TCP и HTTPS/QUIC пакеты; TX peer вырос с единиц килобайт до мегабайт. TASK 06 monitor и rollback ownership check прошли. Повторный краткий fail-closed test остановил только RU TASK 06: lookup foreign mark `0x702` не перешёл на RU WAN; затем TASK 06, TASK 08 recovery и двусторонний TCP/UDP echo восстановились. В capture DNS-запросы клиента к `1.1.1.1`/`1.0.0.1` прошли через FR, хотя экспортированный профиль содержит `DNS = 10.203.253.1`; настройки DNS приложения на устройстве ещё нужно подтвердить.

**OBSERVED по сообщению владельца после исправления.** На отдельном тестовом устройстве новый профиль подключается, сайты открываются, ipify показывает `45.15.128.138` (FR). DNS Leak Test показал пять адресов Cloudflare, все определены как Paris, France; test-ipv6.com сообщил `No IPv6 address detected, 0/10`. Это подтверждает реальный клиентский FR egress и отсутствие обнаруженного публичного IPv6 в данном тесте. DNS-результат не доказывает, что каждое приложение использует указанный в профиле `10.203.253.1`. Windows-машина с Codex не является этим клиентом.

**RU-ветка подтверждена на клиенте.** Синхронный запрос к `77.88.55.242` вошёл на RU через `awg-client` с `10.203.253.2`, вышел через `eth0` с NAT-адресом `137.22.146.212`, ответ вернулся тем же путём; совпадений на `awg-transport` не было. 22 пакета, ноль kernel drops. Точный протокол и оставшиеся ограничения приведены в [TASK_08_RU_PREFIXES.md](TASK_08_RU_PREFIXES.md). Фактический выбранный резолвер приложения и end-to-end fail-closed при отказе FR этим тестом не определялись.
