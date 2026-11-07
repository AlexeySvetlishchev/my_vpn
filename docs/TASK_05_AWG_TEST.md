# TASK 05 — изолированный userspace AmneziaWG RU ↔ FR

**Статус:** короткий транспортный smoke выполнен и принят владельцем 2026-11-07.
Подтверждены свежий handshake, двусторонний UDP/TCP echo и адресный cleanup.
Тест не утверждает 15-минутную устойчивость, production client data plane или
готовность клиентского egress.

## Утверждённые границы

| Узел | Адрес | Интерфейс | Адрес туннеля |
|---|---|---|---|
| RU `218852` | `137.22.146.212` | `awg-test` | `10.203.254.1/30` |
| FR `hiplet-142983` | `45.15.128.138` | `awg-test` | `10.203.254.2/30` |

UDP `51983`, MTU `1280`; transport — закреплённый userspace `amneziawg-go`.
Тест создаёт только link и его connected route; default route, клиентские
маршруты, NAT, PBR, firewall и sysctl не меняет. Автозапуска нет. Он не
устанавливает kernel AWG и не меняет FR Docker networking. Production
`amnezia-awg2` / UDP `40905` остаётся неприкосновенным.

Обычный WireGuard не возвращается как кандидат: он уже проявил нестабильность
по сообщению владельца. Результат TASK 05 проверяет только userspace AWG
двухсерверный канал. Docker metadata не читались при FR prepare; защита
состояла в проверке host-сетевого baseline и отсутствии команд изменения
Docker/production. Это не подтверждает состояние контейнера или production
data plane.

## Файлы и подготовка локального пакета

- `scripts/task05/helper.py` — фиксированные root-операции, ledger владения,
  baseline-сравнение, двухсторонний TCP/UDP echo-тест.
- `scripts/task05/launcher.sh` — принимает ровно один фиксированный verb.
- `scripts/task05/bootstrap.py` — одноразовый root bootstrap; не включён в
  sudoers и не запускает туннель.
- `scripts/task05/controller.py` — владелец запускает его от обычного
  пользователя; SSH-команды и роли зашиты в скрипт, произвольный remote command
  не принимается.
- `scripts/task05/smoke.py` — короткий smoke orchestration: handshake,
  по четыре ping-запроса в каждом направлении, двусторонние счётчики и cleanup;
  не вызывает `start-test`.
- `scripts/task05/build.lock.json`, `scripts/task05/binary-lock.json` — commit,
  builder и SHA-256.
- `scripts/06_privileged_readonly_audit.sh` — отдельный диагностический helper;
  его исправление остаётся в репозитории, но он не входит в TASK 05 bundle и
  bootstrap его не устанавливает.

Две сборки уже дали совпадающие хэши; повторная компиляция не нужна. Передача
пакета владельцем:

```powershell
python -B scripts/task05/package.py
Get-FileHash artifacts/task05/bundle/manifest.json -Algorithm SHA256
```

Ожидаемый SHA-256 manifest: `d0fbbb7e82adb785360ac5a38e9170baa8afc8215bb6de74f8cc1463a5cf6732`.
Пакет содержит только бинарники, исходники helper/bootstrap/launcher и
manifest; приватных ключей, production-конфигов и диагностического helper в нём нет. Перед
передачей сверить этот hash с выведенным значением. Артефакты сборки и пакет
игнорируются Git.

## Одноразовое администрирование и ограниченные sudo-права

Проверенный bundle уже доставлен по SSH/SCP на оба хоста в
`/home/wolffrog/task05-upload/bundle`. Владелец выполняет одну команду на
соответствующем сервере. Она копирует фиксированный список файлов в root-owned
каталог, закрепляет SHA manifest до проверки файлов и проверяет SHA bootstrap
перед его исполнением:

```bash
sudo /bin/bash -c 'set -eu; d=/home/wolffrog/task05-upload/bundle; r=/root/vpn-task05-bundle; /usr/bin/install -d -o root -g root -m 0700 "$r"; /usr/bin/install -o root -g root -m 0600 "$d/manifest.json" "$r/manifest.json"; /bin/echo "d0fbbb7e82adb785360ac5a38e9170baa8afc8215bb6de74f8cc1463a5cf6732  $r/manifest.json" | /usr/bin/sha256sum -c -; for f in amneziawg-go awg helper.py launcher.sh bootstrap.py; do /usr/bin/install -o root -g root -m 0600 "$d/$f" "$r/$f"; done; /bin/echo "2c4acbea9140d236a176f40b6ceccffa5c62c24dc2833520ef9a65582830c36e  $r/bootstrap.py" | /usr/bin/sha256sum -c -; /usr/bin/python3 -I -B "$r/bootstrap.py" ru'
```

Для FR использовать ту же команду с последним аргументом `fr` вместо `ru`.

Это отдельная административная операция установки. Она проверяет owner/mode,
символические ссылки и SHA файлов; устанавливает фиксированные файлы в
`/opt/vpn-task05` и `/usr/local/sbin/vpn-task05`; валидирует sudoers через
`visudo`; устанавливает `/etc/sudoers.d/vpn-task05`. Она не изменяет сеть и не
запускает сервис. Уже существующие целевые файлы, отличающиеся от ожидаемых,
bootstrap не перезаписывает. Не применять `chmod -R`, `chown -R` или замену
неизвестных файлов для обхода отказа.

### Исправление manifest после неудачного обновления FR

> Историческая операция: она исправляла только manifest старого helper. Не
> использовать приведённую ниже команду для текущего состояния; актуальная
> helper+manifest установка и хэши приведены в разделе FR helper update ниже.

В текущем smoke helper сообщил `startup / validate_installation / invalid_data`.
Причина найдена локально: предыдущий генератор manifest записал после JSON
буквальные символы `\n`, поэтому JSON parser увидел лишние данные. Сам новый
helper установлен с ожидаемым хэшем; обновить нужно только root-owned
`/opt/vpn-task05/manifest.json`. Исправленный manifest валиден, SHA-256
`0e0fdd9a280bdcbc8cd60a9bc40ed849bf68ec39610801e3f368de5dabde41b3`, доставлен в
`/home/wolffrog/task05-upload/helper-update/manifest.json`. Проверка JSON на FR
успешна. Генератор `scripts/task05/make_helper_update.py` теперь формирует
настоящий завершающий newline и валидирует сериализованный JSON до передачи.

Одна команда владельца на FR атомарно обновляет только manifest; она сверяет
текущий и staged hashes, ожидает отсутствия runtime state, берёт helper lock,
и оставляет sudoers, helper, binaries, Docker и сеть неизменными:

```bash
sudo /bin/bash -c 'set -eu; umask 077; d=/home/wolffrog/task05-upload/helper-update; b=/opt/vpn-task05; exec 9>>/run/vpn-task05.lock; /usr/bin/flock -n 9; test ! -e /run/vpn-task05; test ! -L /run/vpn-task05; test "$(/usr/bin/stat -c %u:%g:%a "$b/manifest.json")" = 0:0:644; /bin/echo "0e0fdd9a280bdcbc8cd60a9bc40ed849bf68ec39610801e3f368de5dabde41b3  $d/manifest.json" | /usr/bin/sha256sum -c -; /usr/bin/python3 -m json.tool "$d/manifest.json" >/dev/null; /bin/echo "6f0082cd7680a2a71fbb20dc2c6d923831b3c0d8485b36dbfd3b24a41df90184  $b/helper.py" | /usr/bin/sha256sum -c -; m=$(/usr/bin/sha256sum "$b/manifest.json" | /usr/bin/cut -d " " -f 1); case "$m" in bc0e7b3602e86969548bd55464050791511ff473aa9f395c8e51b93cf63d0a70|0e0fdd9a280bdcbc8cd60a9bc40ed849bf68ec39610801e3f368de5dabde41b3) ;; *) echo "BLOCKED: unexpected installed manifest hash" >&2; exit 1;; esac; t="$b/manifest.json.task05-new"; test ! -L "$t"; trap "/usr/bin/rm -f -- \"$t\"" EXIT; /usr/bin/install -o root -g root -m 0644 "$d/manifest.json" "$t"; /bin/echo "0e0fdd9a280bdcbc8cd60a9bc40ed849bf68ec39610801e3f368de5dabde41b3  $t" | /usr/bin/sha256sum -c -; /usr/bin/mv -fT "$t" "$b/manifest.json"; trap - EXIT; echo "TASK05 manifest repaired; sudoers and network state unchanged"'
```


Устанавливаемая sudoers-запись для существующего `wolffrog` содержит только
восемь точных команд и не разрешает shell/interpreter/путь/аргументы:

```sudoers
wolffrog ALL=(root) NOSETENV: NOPASSWD: /usr/local/sbin/vpn-task05 prepare, /usr/local/sbin/vpn-task05 peer, /usr/local/sbin/vpn-task05 up, /usr/local/sbin/vpn-task05 status, /usr/local/sbin/vpn-task05 start-test, /usr/local/sbin/vpn-task05 result, /usr/local/sbin/vpn-task05 down, /usr/local/sbin/vpn-task05 cleanup
```

В sudoers каждый путь задан с точной строкой аргументов; launcher дополнительно
проверяет единственный verb и передаёт чистое окружение. `peer` принимает из
stdin одну строку публичного ключа, проверяет canonical base64 длиной 32 байта
и сохраняет только его. Никакие внешние данные не становятся командой,
интерфейсом, путём, портом или конфигом. Исключения subprocess и сырой вывод не
печатаются.

## Запуск теста после отдельного одобрения

Короткий smoke test (для отдельного одобрения испытания) запускается локально:

```powershell
python -B scripts/task05/smoke.py
```

Он проверяет handshake, четыре ping-запроса в каждом направлении, счётчики и
cleanup. ICMP не является обязательным критерием передачи: на FR обнаружен
общий nftables INPUT DROP для ICMP. Двусторонний полезный UDP/TCP payload для
принятого короткого smoke проверял отдельный `diagnose_asymmetry.py`;
900-секундный runner ниже не запускался.

Проверить, что владельцем завершена установка на обеих VPS, bundle hash
совпадает, SSH host keys остаются проверенными, и FR production VPN здоров по
обычной проверке владельца. Это не делает проверку production-клиента частью
root helper. Запуск ровно одного утверждённого этапа с рабочей машины:

```powershell
python -B scripts/task05/controller.py --run
```

Controller выполняет следующую последовательность только через эти sudo-команды:

```bash
sudo -n /usr/local/sbin/vpn-task05 prepare
sudo -n /usr/local/sbin/vpn-task05 peer       # публичный ключ передаётся stdin
sudo -n /usr/local/sbin/vpn-task05 up
sudo -n /usr/local/sbin/vpn-task05 status
sudo -n /usr/local/sbin/vpn-task05 start-test
sudo -n /usr/local/sbin/vpn-task05 result
sudo -n /usr/local/sbin/vpn-task05 down
sudo -n /usr/local/sbin/vpn-task05 cleanup
```

Порядок: подготовить отдельный приватный ключ на каждом узле; обменяться лишь
публичными ключами; поднять FR, затем RU; стартовать два независимых тестера;
опросить оба узла; всегда выполнить адресный `down` и `cleanup`. Контроллер
использует SSH `BatchMode`, проверку host key и отдельные настроенные ключи
`codex_ru`/`codex_fr`, не создаёт учётных записей и не использует root SSH.

Тестер работает до 900 секунд (плюс ограниченный прогрев и остановка), отправляет
по 1024 байта TCP и UDP в каждом направлении через привязку сокетов к `awg-test`,
проверяет echo payload, свежий после активации handshake, рост RX/TX counters,
минимум 120 циклов и передачу до и после двухминутного application-idle окна.
Keepalive AWG остаётся включённым. На FR при старте и проверках сравниваются
адреса, маршруты, правила и nftables с runtime baseline, а ключевые адреса и
маршруты прежнего аудита должны сохраниться. Docker API/container metadata не
читаются; изменение baseline прерывает тест без восстановления глобальной сети.
Production client health остаётся `UNCONFIRMED`: отдельно нужны результаты
проверки клиента владельцем.

Пропуск UDP 51983 или блокирующие host/provider ACL дают отказ теста. Этот пакет
не меняет firewall для обхода отказа. Любое требование общего firewall, Docker,
маршрутизации, sysctl или production VPN означает STOP и отдельное согласование.
FR — 1 vCPU / 961 MiB: процессы ограничены одним CPU worker, 50% transient
CPUQuota и MemoryMax 192 MiB на unit; реальная производительность остаётся
неподтверждённой.

## Проверка результата и откат

PASS принимается только если обе стороны закончили 900 секунд, имеют реальные
успешные bidirectional TCP/UDP echo, свежие handshake, ненулевой RX/TX delta,
не менее 120 образцов, ноль ошибок, проверки baseline и cleanup прошли. Сырой
handshake или только счётчики не являются успехом. Сохранить JSON-отчёт вне Git;
не добавлять ключи или полный runtime ledger.

Адресный откат выполняется штатным controller автоматически при успехе или
ошибке: остановить только `vpn-task05-test.service` и
`vpn-task05-awg.service`, удалить только `awg-test`, затем очистить только
`/run/vpn-task05` после проверки ownership nonce, ifindex, описаний transient
units и неизменности baseline. Никакие прежние маршруты не восстанавливаются
из backup, потому что они не менялись. При несовпадении владельца/nonce,
неизвестном объекте или изменившемся baseline откат откажется удалять объект;
сохранить доказательства без секретов и остановиться для ручного решения.
Ключи находятся только в root-only `/run` и удаляются при cleanup; это tmpfs
runtime state, не долговременное безопасное стирание носителя.

Быстрый отзыв полномочий: сначала вызвать ограниченный `down`, затем root
удаляет `/etc/sudoers.d/vpn-task05` и проверяет `visudo -c`; чтобы отозвать
SSH Codex, удалить только соответствующие публичные ключи из
`authorized_keys` владельца, завершив уже открытые сессии. Удаление установленных
публичных файлов можно сделать отдельной уборкой после фиксации отчёта.

## Локальная проверка

Из корня проекта:

```powershell
python -B tests/task05_test.py
python -B tests/06_privileged_readonly_audit_test.py
```

Оба набора — offline unit tests с mocks/synthetic inputs: они не подключаются по
SSH, не вызывают sudo или системные сетевые команды и не стартуют AWG. Отдельно
проверены Python AST всех `scripts/task05/*.py`; Bash scripts из bundle прошли
`bash -n` на обеих Linux VPS. Историческая первая попытка FR prepare была
заблокирована чтением Docker metadata; зависимость удалили, сохранив проверки
host-сетевого baseline и конфликтов. Финальный результат принят владельцем и
описан ниже.



## FR helper update: remove Docker metadata from TASK 05 prepare

The pinned previous privileged audit recorded these FR network invariants: `docker0` has `172.17.0.1/16` with route `172.17.0.0/16`; `amn0` has `172.29.172.1/24` with route `172.29.172.0/24`; production UDP `40905` is reserved. The TASK 05 subnet is checked against every live IPv4 route and address, and FR prepare fails closed if either audited network invariant is absent or changed. It also checks that the test UDP port `51983` is free. Each subsequent helper operation compares live non-test addresses, all route/rule tables, and the nftables ruleset to the captured baseline. Docker API/container metadata is not read. This preserves checks for host-network drift without making Docker daemon metadata a prerequisite. Production container health is therefore explicitly **not checked** by this test.

The smoke report marks `production_fr.container_state` as `NOT_CHECKED`, `docker_metadata_read` as `false`, and client data plane as `UNCONFIRMED`. Do not interpret an unchanged host network baseline as proof that `amnezia-awg2` is running or carrying traffic.

Updated helper package hashes:

- `helper.py`: `8203083d0497a0c9cb81f3272b269475396e8c3cb9dff2c84528a419f586add0`
- `manifest.json`: `0a8b62d5bf1965f3d1454825ad210de83ea9142514147e43ccc310d6688abe25`

The two files were staged and this helper-only update was executed on FR. Staged and installed hashes passed. The command is retained here for reproducibility; it refuses active runtime state, takes the existing helper lock, validates the manifest/helper digest, requires the known prior installed pair, and replaces only `helper.py` and `manifest.json`. It does not change sudoers, binaries, Docker, firewall, routes, sysctl, or production VPN:

```bash
sudo /bin/bash -c 'set -eu; umask 077; d=/home/wolffrog/task05-upload/helper-update; b=/opt/vpn-task05; exec 9>>/run/vpn-task05.lock; /usr/bin/flock -n 9; test ! -e /run/vpn-task05; test ! -L /run/vpn-task05; /bin/echo "0a8b62d5bf1965f3d1454825ad210de83ea9142514147e43ccc310d6688abe25  $d/manifest.json" | /usr/bin/sha256sum -c -; /usr/bin/python3 -m json.tool "$d/manifest.json" >/dev/null; /bin/echo "8203083d0497a0c9cb81f3272b269475396e8c3cb9dff2c84528a419f586add0  $d/helper.py" | /usr/bin/sha256sum -c -; m=$(/usr/bin/sha256sum "$b/manifest.json" | /usr/bin/cut -d " " -f 1); h=$(/usr/bin/sha256sum "$b/helper.py" | /usr/bin/cut -d " " -f 1); if test "$m" != 0e0fdd9a280bdcbc8cd60a9bc40ed849bf68ec39610801e3f368de5dabde41b3 || test "$h" != 6f0082cd7680a2a71fbb20dc2c6d923831b3c0d8485b36dbfd3b24a41df90184; then echo "BLOCKED: unexpected installed TASK 05 helper state" >&2; exit 1; fi; ht="$b/helper.py.task05-new"; mt="$b/manifest.json.task05-new"; test ! -e "$ht"; test ! -L "$ht"; test ! -e "$mt"; test ! -L "$mt"; trap "/usr/bin/rm -f -- \"$ht\" \"$mt\"" EXIT; /usr/bin/install -o root -g root -m 0644 "$d/helper.py" "$ht"; /usr/bin/install -o root -g root -m 0644 "$d/manifest.json" "$mt"; /bin/echo "8203083d0497a0c9cb81f3272b269475396e8c3cb9dff2c84528a419f586add0  $ht" | /usr/bin/sha256sum -c -; /bin/echo "0a8b62d5bf1965f3d1454825ad210de83ea9142514147e43ccc310d6688abe25  $mt" | /usr/bin/sha256sum -c -; /usr/bin/mv -fT "$ht" "$b/helper.py"; /usr/bin/mv -fT "$mt" "$b/manifest.json"; trap - EXIT; echo "TASK05 FR helper updated; sudoers and network state unchanged"'
```

## Короткая диагностика асимметрии ICMP (2026-11-07)

Повторный тест показал, что FR nftables имеет одно правило `INPUT` на hook `input` с verdict `drop` для всех типов ICMP без условия по входному интерфейсу. Следовательно, правило распространяется и на `awg-test`. За время короткого прогона его счётчик вырос с 394 до 398 пакетов (+4; +336 байт), совпав с четырьмя echo-request RU→FR без ответов. В `iptables -S INPUT` отдельного ICMP echo-request DROP не было.

Одновременный захват `tcpdump` на `awg-test` обеих VPS зафиксировал по 4 echo-request в каждом направлении, но ответы только на FR→RU (4/4); на RU→FR ответов не было. Это локализует асимметрию в обработке входящего ICMP на FR, а не в handshake или транспортном канале.

Независимо от ICMP прошёл короткий тест полезной нагрузки: 1024-байтовый UDP echo и TCP echo прошли в обоих направлениях через сокеты, привязанные к `awg-test`; на обоих peers выросли RX и TX. Поэтому для TASK 05 транспорт подтверждён тестовым UDP/TCP трафиком, хотя ICMP echo-request на FR фильтруется.

Firewall не менялся. Рекомендуемая проверка — считать тестовый UDP/TCP echo критерием двусторонней передачи, а ping оставить диагностическим. Узкое разрешение ICMP для `awg-test` с точными peer-адресами возможно только после отдельного согласования изменения firewall. Штатный cleanup завершился на RU и FR; тестовые интерфейсы, процессы и runtime state отсутствуют.
