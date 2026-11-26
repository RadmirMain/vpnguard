# 🛡️ VPNGuard 3.0 (macOS)
### Система предотвращения утечек IP/DNS и «моргания» VPN на базе XNU PF, sing-box TUN и выделенного Xray-core с нативным SwiftUI-приложением

**VPNGuard 3.0** — системная защита от микроразрывов («моргания») VPN, утечек реального IPv4/IPv6 и незашифрованных DNS-запросов для macOS (`arm64`, macOS 14+).

Система реализует герметичный контур **Fail-Closed**: весь трафик, не проходящий через `utun99` или авторизованный узел `<ip>:<port>` в sub-anchor `vpnguard/egress`, сбрасывается ядром macOS (`Packet Filter`).

> Спецификация для разработчиков и ИИ-агентов: [AGENTS.md](AGENTS.md) • [ARCHITECTURE.md](ARCHITECTURE.md)

---

## 📌 В чём проблема («Моргание VPN»)?

1. **Микроразрывы туннеля**: при реконнекте, выходе из сна или смене сети (`Wi-Fi ↔ USB-модем`) туннель кратковременно падает.
2. **Мгновенный fallback**: сетевой стек macOS переводит маршрут по умолчанию на физический интерфейс (`en0`/`en5`).
3. **Утечка IPv6 и DNS**: `mDNSResponder` отправляет запросы на локальный DNS роутера (RFC1918), а браузеры и Swift-приложения при наличии IPv6 обходят IPv4-туннель по Happy Eyeballs.
4. **Итог**: компрометация сессий, сброс OAuth и блокировка аккаунтов AI-сервисов.

---

## 🏛️ Архитектура Triple-GID Jail & TUN

```
┌────────────────────────────────────────────────────────────────────────┐
│ macOS Приложения (Dock, Spotlight, LaunchServices)                     │
│ Claude.app, Cursor.app, Codex.app, Chrome, Terminal, CLI               │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ (Шлюз по умолчанию: utun99)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ ЗОНА 3: Headless sing-box TUN Daemon (GID 890: vpnguard-tun, root)     │
│ • Интерфейс: utun99 (172.19.0.1/30, стек gVisor, auto_route)           │
│ • Hijack-DNS: DNS -> DoH 1.1.1.1 (через xray-upstream)                 │
│ • Прямой РФ-DNS: DoT (tls://77.88.8.8:853)                             │
│ • Split-Tunneling: rules.json (process_path_regex и process_path)      │
│ • Clash API: 127.0.0.1:9090 (секрет api_secret, 0640 root:admin)       │
└──────────────────┬─────────────────────────────────┬───────────────────┘
                   │ .ru / Госуслуги / LAN           │ Зарубежный / AI трафик
                   ▼                                 ▼
         [Прямой выход direct]          [Локальный сокет: 127.0.0.1:18088]
                   │                                 │
                   │                                 ▼
                   │   ┌─────────────────────────────────────────────────────────────┐
                   │   │ ЗОНА 2: Headless Xray-core (GID 889: _vpnguard_proxy)       │
                   │   │ • Вход: SOCKS5 (18088) и HTTP (18089) строго lo0 (127.0.0.1)│
                   │   │ • Протоколы: VLESS Reality (Vision), TLS (TCP/xhttp/WS/gRPC)│
                   │   │ • Выход: ТОЛЬКО sub-anchor vpnguard/egress (<ip>:<port>)    │
                   │   └───────────────────────┬─────────────────────────────────────┘
                   │                           │
                   ▼                           ▼
┌────────────────────────────────────────────────────────────────────────┐
│ ЯДРО macOS XNU PF (/etc/pf.anchors/vpnguard + vpnguard/egress)        │
│ • pass quick on lo0 all / pass quick on utun99 all                     │
│ • anchor "egress" (GID 889 -> { <ip> } port <port> proto {tcp, udp})   │
│ • pass out quick inet proto {tcp, udp} all group 890 (ТОЛЬКО IPv4)     │
│ • block return out quick proto {tcp, udp} to <lan_networks> port 53    │
│ • link-local IPv6 (fe80::/10) строго ipv6-icmp + mDNSv6 UDP 5353       │
│ • block return out quick inet6 all + block return out quick all        │
└────────────────────────────────────────────────────────────────────────┘
```

**ЗОНА 1 (GID 888: `vpnguard`)**: setuid-песочница `vpnguard-exec` (`04750 root:admin`) для явного запуска изолированных CLI-сессий (`vpnguard run`, `vpnguard shell`) и изолированного OAuth-браузера `vpnguard-browser` с профилем в `/var/db/vpnguard/browser-profile` (`0770 root:vpnguard`). Обычный пользователь исключён из группы `888`.

---

## 🖥️ Нативное macOS-приложение `VPNGuard.app`

Приложение на SwiftUI (macOS 14+, MVVM) устанавливается в `/Applications/VPNGuard.app` и работает как в основном окне, так и в Menu Bar:

1. **Menu Bar (`MenuBarExtra`)**:
   - Мастер-переключатель защиты (включая жёлтый статус *«PF Kill-Switch активен — туннель восстанавливается»* с возможностью отключения) и живой статус туннеля (*«utun99 · N мс»* + счётчик `«Утечек остановлено»`).
   - **Авторизация Wi-Fi (Captive Portal)** на 5 / 15 мин с обратным отсчётом `TimelineView`, сохранением блокировки `GID 888/889/890` (`/etc/pf.anchors/vpnguard-captive`), защищённым `pause_token`, детектом сна и досрочным автовозвратом по `captive.apple.com` (плюс сброс при `willSleep`).
   - Быстрый запуск **«Открыть защищённый браузер»** (прямой запуск `vpnguard-browser` в песочнице `GID 888` без `sudo`, лог в `~/Library/Logs/VPNGuard/browser-launch.log`).
   - Быстрая смена активного сервера и открытие окна обновлений прямо по клику на баннер.
2. **«Обзор» (Dashboard)**:
   - Статус демонов `vpnguard-xray`, `vpnguard-singbox`, `vpnguard-netwatch`, `PF Kill-Switch` (счётчик заблокированных пакетов), выходного IP и краткая сводка аудита.
   - Параллельный холодный старт (`refreshStatus --fast` + конкурентная загрузка правил/серверов) и гибридный мониторинг: нативный `utun99`-зонд каждые 2.5с, локальный `--fast` опрос каждые 45с, health-check прокси каждые 25с через переиспользуемую `URLSession` и `NWPathMonitor` для обновления UI (системный `dns-sync` / `sync-pf` при смене сети и пробуждении выполняет headless-демон `vpnguard-netwatch`).
3. **«Приложения» (Apps)**:
   - Правила маршрутизации по `.app`-бандлу (`process_path_regex`) и CLI-бинарникам (`process_path`) с режимами `Туннель` / `Напрямую` / `Блок` и кешированием иконок (`AppIconCache`).
4. **«Сайты и домены» (Websites)**:
   - Пользовательские домены с валидацией хостов, учётом специфичности поддоменов и системными пресетами (*AI-сервисы через туннель*, *Сервисы РФ напрямую*, *Блокировка QUIC UDP:443*).
5. **«Монитор трафика» (Traffic Monitor)**:
   - Потоковый WebSocket к Clash API (`ws://127.0.0.1:9090/connections` и `/traffic`) с автозакрытием сокетов при уходе со вкладки.
   - Кешированная группировка потоков (не пересчитывается на 1-секундных тиках скорости), пауза при наведении (`onHover`), параллельное закрытие групп соединений, **Live Runtime Inspector** по клику на строку (цепочка `Процесс/Хост → Правило → DNS → Выход` с сохранением снимка для завершённых соединений) и **правила в 1 клик**.
6. **«Сервер» (Server Config & Upstream)**:
   - Единый список карточек серверов с пингом и кнопкой **«+ Добавить сервер»** (модальное окно импорта `vless://` с живым предпросмотром `VlessPreviewParser` и JSON-конфига).
   - **Пинг серверов** в обход `utun99` (`GID 890` + `IP_BOUND_IF`), и **Auto-Failover** (3 пробы → прямой UDP DNS ре-синк `vpnguard/egress` → переключение на быстрейший сервер → 5-минутный cooldown цикла с активным Kill-Switch).
   - Транзакционное переключение: при выключенном VPN обновляет конфиги без запуска демонов; при активном проверяет `18088/18089` + `utun99` и полностью откатывает конфиги, `vpnguard/egress` и демоны на `.bak` при сбое.
7. **«Диагностика и логи» (Diagnostics)**:
   - Две под-вкладки: **«Аудит утечек»** (14-точечный чек-лист `vpnguard test --json` со статусами `PASS` / `DEGRADED` / `UNKNOWN` / `FAIL` и живой проверкой `Darwin.getgroups` на отсутствие `GID 888` в сессии) и **«Системные логи»** (последние 150 строк `sing-box`, `Xray`, `PF / Boot` через быстрый бинарный `seek` с безопасной ротацией на `8 MiB`, состояние `PF Rules` / `scutil --dns` / `utun99`, асинхронный рендер с подсветкой всех совпадений, маскированием секретов и экспортом отчёта в Markdown).
8. **Встроенное обновление (`Обновление…`)**:
   - **GitHub Releases**: тихая проверка `api.github.com/repos/RadmirMain/vpnguard/releases/latest` (с `ETag` / `If-None-Match` и `403` redirect-фолбэком), скачивание `VPNGuard-macos-arm64.zip`, проверка подписи **Ed25519** + **SHA-256**, атомарный staging в `/Applications` и перезапуск (`~/Library/Logs/VPNGuard/github-update-relaunch.log`). При изменении встроенного `backend.sha256` предлагает обновить системные демоны через Touch ID (`install.sh --backend-only`).
   - **Режим разработчика (`update.sh`)**: локальная пересборка из репозитория (при наличии `update.sh`) с проверкой `frontend.sha256` и `backend.sha256`.

---

## 🚀 Быстрый старт и обновление

### 1. Требования
* macOS 14.0 (Sonoma) или новее (Apple Silicon `arm64`).
* Homebrew (`brew install xray sing-box`).

### 2. Первичная установка

#### Вариант А: Готовый релиз из GitHub Releases (без Xcode и Git)
1. Скачайте `VPNGuard-macos-arm64.zip` на странице **Releases**, распакуйте и перенесите `VPNGuard.app` в `/Applications`.
2. Поскольку сборка подписана ad-hoc (без платного сертификата Apple Developer ID), при первом запуске после скачивания через браузер снимите атрибут карантина Gatekeeper:
   ```bash
   xattr -cr /Applications/VPNGuard.app
   ```
3. Откройте `VPNGuard.app` — приложение предложит установить системные компоненты через Touch ID (`install.sh --backend-only`; `install.sh` при необходимости подтянет `xray` и `sing-box` через Homebrew). Последующие обновления из GitHub Releases проверяются криптографической подписью **Ed25519** и **SHA-256** и устанавливаются автоматически.

#### Вариант Б: Сборка из исходников
```bash
git clone https://github.com/RadmirMain/vpnguard.git VPNGuard
cd VPNGuard

# Установка системных демонов, PF, CLI и hardened sudoers (при отсутствии xray/sing-box установит их через brew)
sudo ./install.sh

# Сборка и установка /Applications/VPNGuard.app
./app/VPNGuardApp/build_app.sh
```

> **После самой первой установки**: выйдите из сеанса macOS или перезагрузите Mac, чтобы активные сессии сбросили кэшированную группу `888(vpnguard)`. Если в `xray.json` остался шаблон `REPLACE_WITH_UUID`, установщик оставит защиту выключенной (`desired_state=off`) до настройки сервера.

### 3. Последующие обновления (в 1 клик или из терминала)
- **Из приложения**: нажмите **«Обновление…»** в боковой панели (скачивает готовый релиз с GitHub или собирает из локального репозитория).
- **Из терминала**:
  ```bash
  ./update.sh --relaunch
  ```

---

## 💻 Управление через CLI (`vpnguard`)

| Команда | Описание |
|---|---|
| `vpnguard status [--json] [--fast]` | Статус безопасности (`pf_active`, `utun_active`, `cores_alive`, `netwatch_active`, `captive_pause_active`), демонов, `utun99`, Clash API и `pauseUntil`. |
| `sudo vpnguard on` | Подготовка конфигов, запись `desired_state=on`, армирование PF, сброс старых PF-состояний (`pfctl -k`), ротация логов, запуск Xray/sing-box, синхронизация DNS `1.1.1.1`. |
| `sudo vpnguard off` | Сброс PF (до снятия токена `-X`), остановка `sing-box`, запись `desired_state=off`, восстановление исходного DNS. |
| `sudo vpnguard pause <300\|900>` | Режим авторизации Wi-Fi (Captive Portal): сохраняет PF-блокировку `GID 888/889/890`, восстанавливает DHCP DNS, следит за `captive.apple.com` и сном с `pause_token`. |
| `sudo vpnguard resume-if-expired` | Немедленный возврат защиты, если время `pause_until` уже истекло. |
| `sudo vpnguard dns-sync` | Идемпотентная синхронизация DNS (`1.1.1.1`) на активных физических `en*`-интерфейсах (`flush_dns_cache` только при изменениях). |
| `sudo vpnguard test [--json]` | 14-точечный активный аудит утечек (`PASS`/`DEGRADED`/`UNKNOWN`/`FAIL`: PF, GID 888/889/890, DNS, IPv6, `utun99`, `netwatch`, сессия `getgroups()`). |
| `vpnguard explain <target> [--json]` | Static Policy разбор маршрутизации (PF/GID + `rules.json` + перекрытые правила) для домена, URL или приложения. |
| `sudo vpnguard logs --json` | Последние 150 строк логов (быстрый `seek` с конца) + `pfctl`/`scutil --dns`/`ifconfig utun99` с маскированием секретов. |
| `sudo vpnguard rules get` | Вывод текущего `rules.json`. |
| `sudo vpnguard rules apply [--stdin \| <path>]` | Валидация и атомарное применение `rules.json` с откатом на `.bak`. |
| `sudo vpnguard server list [--json]` | Список настроенных upstream-профилей. |
| `sudo vpnguard server ping --json` | Прямой замер TCP RTT до всех серверов через `GID 890` + `IP_BOUND_IF` в обход `utun99`. |
| `sudo vpnguard server sync-pf` | Прямой UDP DNS ре-синк релея (`GID 890`) и обновление `vpnguard/egress` (+ `sing-box.json` при смене IP). |
| `sudo vpnguard server import-vless [--stdin \| <path>]` | Импорт `vless://` или Xray JSON в `servers.json`. |
| `sudo vpnguard server activate [--stdin \| <id>]` | Транзакционное переключение активного сервера с проверкой `18088/18089/utun99` (или offline без запуска демонов) и откатом при сбое. |
| `sudo vpnguard server delete [--stdin \| <id>]` | Удаление неактивного профиля сервера. |
| `sudo vpnguard server update [--stdin \| <path>]` | Обновление из сырого Xray JSON с синхронизацией в `servers.json`. |
| `vpnguard run <команда...>` | Запуск команды в изолированной песочнице `GID 888` (`vpnguard-exec`; раздельные профили для Cursor и VS Code). |
| `vpnguard shell` | Интерактивная защищённая оболочка `GID 888`. |
| `vpnguard watch` | Консольный мониторинг состояния локального прокси. |

---

## 🧪 Тестирование и удаление

```bash
# 1. Оффлайн Python unit-тесты (без живого прокси и root)
python3 -m unittest tests/test_pf_syntax.py tests/test_singbox_config.py tests/test_vless_parser.py tests/test_logs_and_routing.py tests/test_pause_resume.py tests/test_server_ping.py -v

# Полный набор Python-тестов на настроенном хосте (49 тестов, включая test_launcher.py и test_proxy.py)
python3 -m unittest discover -s tests -v

# 2. Swift unit-тесты (16 тестов) и Release-сборка (VPNGuardApp + vpnguard-netwatch)
swift test --package-path app/VPNGuardApp
swift build --package-path app/VPNGuardApp -c release --arch arm64

# 3. Живой 14-точечный аудит безопасности
vpnguard test

# 4. Полное удаление (останавливает приложение/watcher, выгружает LaunchDaemons/Agent и сохраняет бэкап servers.json в ~/.vpnguard-backup/)
sudo ./uninstall.sh
```
