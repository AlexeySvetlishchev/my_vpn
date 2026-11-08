# TASK 08 — план согласования клиентского egress RU → FR

Фактическое развёртывание и оставшиеся проверки: [TASK_08_DEPLOYMENT_RESULT.md](TASK_08_DEPLOYMENT_RESULT.md).

**Статус:** исторический план одобрения; dataplane TASK 08 развёрнут. Фактический результат, RPDB/rp_filter repair и RU IPv4 set описаны в [TASK_08_DEPLOYMENT_RESULT.md](TASK_08_DEPLOYMENT_RESULT.md) и [TASK_08_RU_PREFIXES.md](TASK_08_RU_PREFIXES.md).
Это одобрение обусловлено проверкой production AmneziaVPN реальным клиентом
**до и после** изменения FR firewall. До первого подтверждения FR firewall,
forwarding, маршруты, NAT, DNS и клиентский профиль не менялись.
Базовые TASK 06/07 сохраняются.

Подготовка после одобрения: `scripts/task08/snapshot.py` установлен как
`/usr/local/sbin/vpn-task08-snapshot` на RU и FR и сохранил root-only baseline
`/var/lib/vpn-task08/prechange.json` (каталог 0700, файл 0600). SHA-256 записи:
RU `af37b5663ecf0f978e8df24f7749358ba7e0acbc5520b3ebc2288b244e9d4857`,
FR `406bfd800e5949ada5bbc969a3e121a775c4b8e94a4412f8a2b14278cf116e6c`.
Снимок не содержит VPN-ключей, Docker environment или полных VPN-конфигураций;
сырые сетевые данные не выводились в чат. После записи мониторы TASK 06 на обоих
узлах снова подтвердили свежий handshake и двусторонний TCP/UDP echo.

Production-client precheck около 16:00 UTC: на Windows-клиенте адаптер
`AmneziaVPN` имел статус Up, его интерфейс был выбран для IPv4 default route,
HTTPS-запрос к независимому IP echo успешно завершился, а внешний IPv4 совпал
с `45.15.128.138` (не с RU). Профиль/ключи приложения не открывались. Это
фактическое подтверждение клиентского выхода через FR до изменения firewall;
после изменения требуется тот же тест. Связь с конкретным контейнерным peer
по конфигурации не проверялась.

## Цель и проверенный baseline (2026-11-07)

- RU `218852`: `awg-transport` и `awg-client` активны; клиентского handshake нет.
  `10.203.254.1/30` и `10.203.253.1/24`; default via `137.22.146.1 dev eth0`;
  `net.ipv4.ip_forward=0`; таблица 220 отсутствует, RPDB содержит только
  приоритеты 0/32766/32767; nftables ruleset пуст, порт 53 не слушается.
- FR `hiplet-142983`: `awg-transport` активен; default via `45.15.128.1 dev ens3`;
  `net.ipv4.ip_forward=1`; таблица 220 отсутствует. Backend `iptables-nft`.
  В `ip filter FORWARD` policy DROP: сначала jump `DOCKER-USER`, затем
  `DOCKER-FORWARD`; `ip nat POSTROUTING` содержит Docker masquerade для
  `amn0`/`docker0`. `ip raw PREROUTING` содержит два Docker drop. Нет правил,
  принадлежащих TASK 08. Production контейнер `amnezia-awg2` остаётся Up,
  UDP 40905 опубликован. Его клиентский data plane не проверен.
- На обоих узлах `rp_filter=2` для all/default/WAN/тестового интерфейса.
  Мониторы TASK 06 подтвердили свежий handshake и двусторонний TCP/UDP echo.
  Существующий TASK 06 baseline включает хэши firewall и снимки routes/rules:
  без адресной адаптации он правильно отвергнет любые предлагаемые изменения.

## Точные сетевые объекты, требующие отдельного одобрения

| Узел | Объект | Предлагаемый эффект |
|---|---|---|
| RU | `net.ipv4.ip_forward` | 0 → 1 только после установки двух независимых fail-closed барьеров; IPv6 forwarding не менять. Переключение `ip_forward` может сбросить другие IPv4 sysctl к defaults, поэтому сохранить и сравнить их до/после. |
| RU | TASK 06 peer AllowedIPs | FR peer: `0.0.0.0/0` внутри AWG; **не** создавать host default route. Внешний UDP endpoint FR остаётся через `eth0` в main. Изменение закрепить в helper, иначе restart вернёт прежний `/32`. |
| RU | RPDB и таблица 220 | Приоритеты 10000/10010: только вход с `awg-client` и marks `0x701` (main) / `0x702` (table 220). После реального клиентского теста terminal rule сужено до pref 10021, `iif awg-client fwmark 0x702 unreachable`: безусловное правило мешало kernel reverse-path validation и отбрасывало ответы до FORWARD. Неотмеченный клиентский трафик ограничен nft FORWARD guard; 220 содержит default via `10.203.254.2 dev awg-transport`. Для DNS-bound запросов из `10.203.254.1` к двум фиксированным upstream — отдельные правила lookup 220 и terminal unreachable. Main/default хоста не менять. |
| RU | Собственная таблица `ip vpn_task08_ru` | `prerouting`: anti-spoof source только `10.203.253.2/32`, запрет non-public/management адресов, `force_egress` перед RU set, остальные публичные IPv4 по умолчанию mark `0x702`. `forward`: независимо от PBR пропускать клиент→`eth0` только `daddr∈ru_set`, `daddr∉force_egress`, mark `0x701`; клиент→`awg-transport` только mark `0x702`; остальные пути DROP. Обратные пакеты допускать только по ожидаемому conntrack/интерфейсам. `postrouting` NAT только `iif awg-client`, `oif eth0`, source клиентской сети и RU mark. `input` разрешает локальный DNS на `10.203.253.1:53` только с client peer, остальное от `awg-client` закрывает. `output` запрещает DNS-upstream и source `10.203.254.1` через `eth0`. |
| FR | TASK 06 peer AllowedIPs и маршрут | RU peer: `10.203.254.1/32,10.203.253.0/24`; точный обратный маршрут `10.203.253.0/24 dev awg-transport`. Закрепить в helper/recovery, не трогать host default. |
| FR | `ip filter FORWARD` | **Один** jump в собственную `vpn_task08_fr` chain между существующими jump в `DOCKER-USER` и `DOCKER-FORWARD`. Chain принимает только `iif awg-transport → oif ens3`, source `10.203.253.0/24` к публичным IPv4, и обратные `ct established,related` к этой сети. Для RU DNS source `10.203.254.1` допускается только UDP/TCP 53 к фиксированным upstream и ответы. Всё остальное RETURN в прежний Docker/FORWARD путь. Handles и порядок проверить перед nft transaction и записать для отката. `DOCKER-*`, `amn0`, `docker0` не редактировать. |
| FR | Собственная таблица `ip vpn_task08_fr` | NAT `postrouting` priority 90, masquerade только указанных клиентских flows на `ens3` и RU DNS к фиксированным upstream. Приоритет раньше Docker NAT 100, но match не пересекается с Docker подсетями. Таблица/цепочки принадлежат только TASK 08. |
| RU | DNS | Установить только `dnsmasq-base` (без запуска общесистемного dnsmasq), отдельный `vpn-task08-dns.service`: listen `10.203.253.1:53`, `bind-dynamic`, `no-resolv`, фиксированные `9.9.9.9`/`149.112.112.112` с `@awg-transport@10.203.254.1`. Нет fallback на `/etc/resolv.conf`; при недоступном FR DNS перестаёт отвечать, не переключается на RU WAN. Пакет и исходящие интерфейсы проверить до открытия клиентского трафика. |
| Client | Тестовый профиль | После server-side fail-closed тестов обновить только отдельный тестовый профиль: IPv4 `AllowedIPs=0.0.0.0/0`, DNS `10.203.253.1`. Пользовательские профили не менять. Отсутствие IPv6-утечки требует отдельной проверки реального клиентского стека; host IPv6 FR не отключать. |

Набор `ru_set` — консервативный allowlist: всё неопределённое идёт через FR.
Источник country-resource-list RIPE NCC сообщает страну регистрации ресурса,
а не физическую геолокацию; одной этой выборки недостаточно для обещания
«только российские назначения через RU». До выбора и проверки источника
геоданных прямой RU-трафик ограничивается явно проверенными test prefixes.
При дальнейшей автоматизации обновление примерно каждые 12 часов: HTTPS
загрузка, типизированный CIDR parsing, исключение IANA special-use и
пересечений с management/Docker/tunnel сетями, контроль разумного диапазона
количества/объёма, атомарная nft transaction, сохранение предыдущей валидной
версии при ошибке. `force_egress` всегда имеет приоритет над RU set.

## Порядок развёртывания после одобрения

1. Создать root-only backups и хэши точных TASK 06 helper/manifest,
   systemd units, `ip rule/route`, всех IPv4 sysctl, nft JSON/handles и
   Docker-safe структурного baseline. Проверить SSH и доступность консоли
   провайдера; production VPN client data plane до изменения — если доступен
   тестовый клиент владельца. Не читать контейнерные секреты.
2. Локально проверить генератор правил/списков, синтаксис nft в check mode,
   конфликт подсетей/marks/priority и сценарии rollback. Изменить TASK 06
   baseline только для точных TASK 08-owned объектов, а не переснимать весь
   firewall как «новую норму». Установить обновления с manifest SHA-256.
3. Сначала установить RU firewall guard и terminal unreachable RPDB,
   затем FR scoped FORWARD/NAT/return route и TASK 06 AllowedIPs; проверить
   транспорт и прежний Docker путь. Только потом включить RU forwarding,
   отдельный DNS и тестовый профиль. Каждая стадия под lock; если check
   не проходит — остановить до следующей стадии и откатить созданные объекты.
4. Проверить server-side route lookups для RU/foreign/force-foreign,
   egress counters и захват на RU WAN/AWG без payload. Короткий test fail-closed:
   остановить только FR TASK 08 egress path или RU TASK 06 service, доказать
   отсутствие foreign packet на RU WAN, восстановить собственный сервис,
   повторить TCP/UDP echo. Не останавливать production контейнер.
5. Лишь после реального подключения тестового клиента проверять его handshake,
   внешний RU/FR IPv4, DNS путь, TCP/UDP/MTU и отсутствие IPv4/IPv6 утечек.
   Отдельно проверить production AmneziaVPN клиентом до/после FR firewall
   изменения. Контейнер `Up` и UDP publication сами по себе не доказывают
   его data plane.

## Восстановление, мониторинг и адресный откат

- `vpn-task08-egress.service` на каждом хосте восстанавливает только свои
  route/rule/nft объекты после TASK 06 restart/reboot. RU fail-closed guard
  устанавливается **до** включения forwarding. Остановка/ошибка не удаляет
  guard до отключения клиентского интерфейса или возврата forwarding=0.
- Отдельный read-only timer проверяет ownership и точные хэши/handles правил,
  sysctl, DNS interface/upstream, маршруты endpoint и client subnet, свежесть
  TASK 06 и рост TCP/UDP echo. При дрейфе не делает fallback в RU WAN;
  аварийное восстановление только своих объектов после проверки владельца.
- Откат: отсоединить тестового клиента, остановить TASK 08 DNS и egress units,
  поставить RU forwarding обратно в сохранённое 0, удалить только свои RPDB
  pref 10000–10032, table 220 и `vpn_task08_*` таблицы/зафиксированный FR jump
  по проверенному handle, восстановить прежние TASK 06 AllowedIPs/helper/manifest
  и root-only sysctl snapshot. TASK 06/07 оставаться в исходном состоянии;
  перепроверить handshake/echo, default routes, SSH, Docker container/port и
  production client data plane. При несовпадении владельца объекта — остановка,
  без глобального `flush`/перезапуска Docker.

## Влияние и открытые условия

Предлагаемый FR jump находится **после** `DOCKER-USER`, но **до**
`DOCKER-FORWARD`; для нецелевых пакетов возвращает прежнюю обработку.
Production `amn0`/`docker0`, Docker daemon/networks и UDP 40905 не меняются.
Остаётся риск ошибки firewall transaction, конкурирующего обновления Docker
chain и нагрузки FR 1 vCPU/961 МиБ. Нужны атомарность, точные matches,
проверка порядка после применения и доступная консоль восстановления.

Требуемое разрешение владельца: точечные RU `ip_forward`, RPDB/table 220,
собственный nft/NAT/DNS service и изменение тестового профиля; точечные FR
FORWARD jump, собственный nft NAT, маршрут клиентской сети и расширение
TASK 06 AllowedIPs. Отдельно нужен способ проверить production VPN с реального
клиента до/после изменения FR firewall; без него состояние data plane останется
неподтверждённым, и его нельзя объявлять сохранённым на основании `docker ps`.
