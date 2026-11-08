# TASK 06 — постоянный межсерверный AmneziaWG RU ↔ FR

**Статус:** развёрнут и проверен 2026-11-07 по явному разрешению владельца.
Постоянный host-level туннель активен; клиентские VPN-профили, PBR, NAT, DNS и
клиентский egress не внедрялись.

## 1. Основание и границы

TASK 05 принят владельцем как успешный короткий транспортный smoke: userspace
`amneziawg-go` установил handshake; 1024-байтовый TCP и UDP echo прошёл в обе
стороны; адресный cleanup завершился на RU и FR. На FR nftables INPUT drop
отбрасывает все ICMP без привязки к интерфейсу; firewall менять не требуется.

FR `hiplet-142983` продолжает содержать защищённый production Docker
`amnezia-awg2` на UDP 40905. Не останавливать/перезапускать контейнер, не читать
его полную конфигурацию/environment, не менять Docker networking, firewall,
global routes, sysctl или системные сетевые службы. TASK 06 развернул только
отдельный host userspace AWG transport.

Один и тот же пользователь `wolffrog` сохраняется на обоих узлах. SSH-ключи
Codex `codex_ru` и `codex_fr` остаются раздельными; новые Unix-пользователи не
создаются. Право SSH или sudo не означает авторизацию для будущего включения
клиентских маршрутов/egress. TASK 06 был отдельно явно разрешён владельцем.

## 2. Фактическая конфигурация

| Параметр | План | Ограничение |
|---|---|---|
| Реализация | Отдельно закреплённые userspace `amneziawg-go` + совместимый `awg` | UAPI socket изолирован в `/run/vpn-task06/amneziawg`; kernel AWG не устанавливался |
| Интерфейс | `awg-transport` | Не использовать `awg-test`; маркировать alias и проверять ifindex/тип перед любым удалением |
| Адреса | RU `10.203.254.1/30`, FR `10.203.254.2/30` | Повторно проверить маршруты и адреса непосредственно перед созданием |
| Порт | UDP 51983 на обоих узлах | FR production UDP 40905 зарезервирован и неприкосновенен; проверить текущую занятость 51983 |
| MTU | Начальное значение 1280 | Перепроверить TCP/UDP и фрагментацию; не менять MTU production-интерфейсов |
| AllowedIPs | Только адрес второго peer `/32` | Не принимать default route, клиентские подсети, `Table=auto` или маршруты пользователей |
| Параметры обфускации | Зафиксированный TASK 05 AWG2-compatible профиль | Использовать только пару новых ключей постоянного канала; не повторять тестовые ключи |
| Подъём | `vpn-task06-awg.service`, systemd enable + автозапуск | Только интерфейс туннеля и один peer; клиентские маршруты отсутствуют |

Временные порт и подсеть TASK 05 прошли короткую проверку отсутствия конфликтов.
Перед созданием постоянного интерфейса helper повторно проверил текущие адреса,
маршруты всех таблиц, интерфейсы, слушающие сокеты и FR baseline
`docker0`/`amn0`. Если baseline изменён, 51983 занят, появился маршрут/адрес,
пересекающийся с `/30`, или endpoint RU↔FR уходит через новый интерфейс —
остановиться и пересогласовать значения.

## 3. Сборка и установка

1. Сборка выполнена дважды из `amneziawg-go` commit
   `b5928efb6ca19f0153958460c3d141f04abc5c2e` и `amneziawg-tools` commit
   `ee0f0a9aa34ff0a0da4b3433b9512781cfe02843`; оба результата совпали:
   `amneziawg-go` SHA-256 `a820140b0c6639c4f2bd980d7d2772882fe82a1eee4fcce5e5c004855835ad15`,
   `awg` SHA-256 `f9bd60ea5ede17e27936533bb0e1bbe5768abd4443d06118803a87c8b6e56821`.
   UAPI socket изолирован в `/run/vpn-task06`. Manifest проверен; секретов нет.
2. Перед установкой на обоих VPS снят baseline: SSH доступен; default route,
   все адреса/маршруты/rules, firewall hash, UDP 51983 и состояние systemd;
   на FR — безопасное состояние контейнера `amnezia-awg2`/UDP 40905 и сети
   `amn0`/`docker0`. Полные Docker inspect, Env и VPN-конфиги не читать.
3. Сгенерировать независимые ключи на RU/FR непосредственно на узлах. Хранить
   private keys только в root-owned каталоге `/etc/vpn-task06` с каталогом
   `0700`, файлами `0600`; обменять только public keys. Резервные копии ключей,
   если потребуются, зашифровать и хранить вне репозитория.
4. Установить только фиксированные `amneziawg-go`, `awg`, узкий launcher/helper,
   manifest и systemd units. Не вызывать `awg-quick`/`wg-quick`, потому что они могут
   менять маршруты или firewall. Компоненты проверяют фиксированные пути,
   хэши, роль и права до любого действия.
5. Установщик выполнил `daemon-reload`; затем только TASK 06 `awg` service и
   monitor timer были включены. Новые sudoers-права не добавлялись.

## 4. Постоянная служба, безопасное восстановление и мониторинг

- Root-owned `vpn-task06-awg.service` запускается после `network-online.target`,
  включён в `multi-user.target`, с `Restart=on-failure`, задержкой и StartLimit.
  Используется только фиксированный launcher без
  `shell=True`, `eval`, произвольных аргументов, environment secrets или
  конфигов из writable-путей.
- При запуске создать только `awg-transport`, установить alias
  `vpn-task06:<instance-id>`, сверить ifindex и тип интерфейса, назначить
  `/30`, MTU и один peer `/32`; default route и host-wide routing не трогать.
- Интерфейс `awg-transport`, адреса RU `10.203.254.1/30`, FR `10.203.254.2/30`,
  UDP 51983, MTU 1280. Peer AllowedIPs ограничены единственным remote `/32`;
  SSH endpoint остаётся через исходный WAN. Default routes, firewall, NAT,
  PBR, sysctl и Docker не меняются.
- Отдельный `vpn-task06-probe.service` слушает TCP/UDP 51984 только на
  `awg-transport`; `vpn-task06-monitor.timer` вызывает read-only проверки раз в
  минуту. Конкурирующие проверки используют сериализованный control lock;
  timeout отдельных UDP/TCP echo повторяется до трёх раз.
- После запуска RU AWG service потреблял около 15 MiB, echo probe около 12 MiB;
  FR показывал те же значения. Это короткий снимок памяти, не нагрузочная оценка.
- Stop/recovery helper останавливает только PID/cgroup своего unit. Удаляет
  интерфейс лишь при совпадении точного имени, alias, ifindex, link type и
  локального ownership ledger. При foreign/mismatched объекте — fail closed,
  сигнал оператору, без `ip link delete`.
- Мониторинг лёгкий: systemd timer проверяет свежесть handshake, рост peer
  RX/TX при TCP/UDP echo, состояние unit и наличие адресного
  connected route. Пинг не критерий здоровья из-за FR INPUT ICMP DROP.
  Мониторинг read-only: неудачный запуск отражается в systemd/journal, но не меняет firewall,
  маршруты и не перезапускает production VPN.
- Не добавлять внешние monitoring stack, Docker, PBR/NAT/DNS или клиентские
  маршруты в TASK 06.

## 5. Фактические проверки

1. `vpn-task06-awg.service` и `vpn-task06-monitor.timer` enabled/active на обоих
   узлах; probe service активен как зависимость. Автозапуск systemd настроен.
   Фактический reboot хостов не проводился.
2. Handshake был свежим на RU и FR (возраст 1–5 секунд в контрольных снимках).
   По 1024-байтовому payload TCP и UDP echo прошли в обе стороны до перезапусков,
   после перезапуска только RU unit, после перезапуска только FR unit и в финале.
3. После обоих service restart handshake и echo восстановились. Это проверяет
   recovery после остановки/restart своего процесса; отдельную потерю внешней
   связности фильтрацией пакетов не моделировали.
4. SSH-команды через оба alias продолжили выполняться. TASK 06 helper подтвердил,
   что host addresses, routes, rules и нормализованный firewall hash совпадают
   с baseline; default routes не менялись.
5. До и после тестов на FR безопасный запрос подтвердил один работающий
   `amnezia-awg2` и опубликованный UDP 40905. Docker metadata/environment и
   client data plane production VPN не читались/не проверялись. Docker, firewall,
   production VPN и общие сетевые параметры не менялись.
6. Короткий smoke/restart test успешен. 15-минутная нагрузка, полный reboot,
   production-клиентский тест и пригодность FR для клиентского egress остаются
   непроверенными; PBR/NAT/client DNS не внедрялись.

## 6. Резервирование и адресный откат

Перед установкой подтверждено отсутствие одноимённых TASK 06 unit/interface;
установщик создавал только фиксированные root-owned файлы с проверкой manifest
SHA-256. Существующие объекты не перезаписывались. Секретные конфиги не копировались.
Не копировать Docker конфиги или полные production VPN конфиги. План отката:

Владелец может адресно откатить каждый узел фиксированной командой:

```sh
ssh vpn-ru 'sudo -n /usr/local/sbin/vpn-task06 rollback'
ssh vpn-fr 'sudo -n /usr/local/sbin/vpn-task06 rollback'
```

Helper отключает только TASK 06 units/timer, удаляет interface только при
совпадении alias + ifindex + link type + ownership ledger, затем удаляет только
TASK 06 ключи/состояние/установленные хэши и выполняет `daemon-reload`. При
несовпадении либо неизвестных файлах он останавливается. После отката проверить
отсутствие интерфейса и units, SSH и исходный host baseline. Не применять общий
flush/cleanup и не менять чужие файлы.

Откат не должен редактировать `/etc/docker`, FR Docker networks, nftables/
iptables/UFW, sysctl, `/etc/hosts`, host default routes или другие сервисы.

## 6.1. TASK 07: совместимость с клиентским интерфейсом (2026-11-07)

На RU helper/manifest TASK 06 обновлены адресно: `snapshot()` исключает `awg-client` только при совпадении root-owned TASK 07 ledger, alias, ifindex, типа userspace TUN, адреса `10.203.253.1/24` и строго ограниченных connected/local IPv4 и link-local IPv6 маршрутов. Все прочие адреса, routes/rules и firewall hash сравниваются с прежним baseline. Оригинальные helper/manifest сохранены в `/root/vpn-task06-task07-baseline-backup`; FR TASK 06 helper не менялся. Скрипт `scripts/task06/verify-remote.ps1` выполняет fixed SSH-команды без CRLF-чувствительного `bash -s` диагностического here-string.

После первого краткого теста с TASK 07 служба RU TASK 06 отказала, а FR получил `handshake_age=null`. Повторные отказы происходили и с полностью остановленным TASK 07. Диагностика показала, что дочерний `amneziawg-go` завершался с кодом 0 сразу после завершения systemd `vpn-task06-monitor.service`; прямой вызов того же monitor helper не прерывал транспорт. У monitor unit был общий с транспортом `RuntimeDirectory=vpn-task06`. Эта директива удалена только из monitor unit на RU и FR; пакетный manifest обновлён с проверкой SHA-256, предыдущие unit/manifest сохранены в `/root/vpn-task06-monitor-fix-backup` на обоих узлах. Каталог runtime теперь создаёт и сохраняет только `vpn-task06-awg.service`.

После правки RU TASK 06 перезапущен собственным unit, TASK 07 userspace `awg-client` кратко запущен на RU. Повторные systemd monitor и отдельные RU/FR проверки вернули свежий handshake и `healthy=true`, `tcp_echo=true`, `udp_echo=true`; счётчики RU restart остались 0 после reset, FR — 100 от прежних отказов. Baseline RU допускает только валидный, принадлежащий TASK 07 интерфейс; остальные адреса, маршруты, правила и firewall hash совпали с сохранённым baseline. Production `amnezia-awg2` остался `Up` с UDP 40905. Хостовые default routes, Docker и общие firewall-правила не менялись. Это короткая проверка; длительная устойчивость и реальный клиентский трафик ещё не подтверждены.

Адресный откат только правки monitor unit при необходимости: на соответствующем узле остановить `vpn-task06-monitor.timer`, восстановить `/opt/vpn-task06/vpn-task06-monitor.service`, `/etc/systemd/system/vpn-task06-monitor.service` и `/opt/vpn-task06/manifest.json` из трёх одноимённых файлов `/root/vpn-task06-monitor-fix-backup` с владельцем root и режимом 0644, выполнить `systemctl daemon-reload`, затем запустить timer. Бэкап RU содержит manifest уже после TASK 07 baseline patch; откат monitor unit не должен возвращать старый RU helper. Проверить `vpn-task06 status` и `monitor` после восстановления. Production Docker и host firewall этот откат не затрагивает.

## 7. Полномочия и отзыв доступа

Сохранены `wolffrog` и раздельные Codex SSH keys; новые Unix-пользователи и
TASK 06 sudoers-файл не создавались. Использовался уже предоставленный владельцем
`sudo -n` доступ в рамках этого конкретного разрешения. Быстрый отзыв Codex:
удалить только Codex public-key entries из `authorized_keys` обоих узлов и закрыть
его активные SSH sessions; текущая услуга работает в systemd независимо от SSH.
