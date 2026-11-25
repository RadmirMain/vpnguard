# 🏛️ VPNGuard 3.0: Полная архитектура, спецификация и руководство для ИИ-агентов

> **Статус документа**: Актуальная техническая спецификация и системный чертёж архитектуры VPNGuard 3.0.  
> **Целевая аудитория**: Системные инженеры, разработчики безопасности и ИИ-агенты.

---

## 1. Концепция и модель угроз

### 1.1. Проблема «моргания» VPN (VPN Blinking & Silent Leaks)
При использовании обычных GUI-клиентов на macOS во время реконнекта, засыпания или смены Wi-Fi ↔ модема возникают короткие провалы маршрута (flaps):
1. **Сброс дефолтного маршрута**: Сетевая подсистема macOS (`configd`, `networkd`) немедленно отправляет пакеты на физический интерфейс (`en0`, `en5`).
2. **Утечки DNS через `mDNSResponder`**: Нативные приложения macOS резолвят домены через Mach IPC к `_mdnsresponder`. Если DHCP выдал локальный DNS роутера (`192.168.1.1`, `172.20.10.1`), а `auto_route` исключил RFC1918, DNS-запросы уходят на роутер в обход `utun99`.
3. **Утечка IPv6 (Happy Eyeballs, RFC 8305)**: При наличии нативного IPv6 на интерфейсе и IPv4-only туннеле браузеры и `URLSession` предпочитают IPv6 мимо туннеля.
4. **Прямые протоколы и QUIC**: UDP 443 (HTTP/3) и не-TCP/UDP протоколы без явного фильтра обходят прокси.

### 1.2. Принцип Fail-Closed
В VPNGuard 3.0 реализован принцип **аппаратного отказа с блокировкой**:
- Любой исходящий пакет, не направленный в `lo0`, `utun99`, разрешённый локальный контур или динамический `vpnguard/egress` (`<ip>:<port>` для GID 889), сбрасывается ядром XNU PF (`block return out quick`).
- Внешний IPv6 и обычные DNS-запросы (порт 53) к `<lan_networks>` режутся на уровне PF.

---

## 2. Архитектура Triple-GID и топология сетевых зон

```
┌────────────────────────────────────────────────────────────────────────┐
│ macOS Приложения (LaunchServices, Dock, Spotlight, CLI)                 │
│ Claude.app, Cursor.app, Codex.app, Chrome, zsh, Git, etc.              │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ (Шлюз по умолчанию: utun99)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ ЗОНА 3: Headless sing-box TUN Daemon (GID 890: vpnguard-tun, root)     │
│ • Интерфейс: utun99 (172.19.0.1/30, стек gVisor, auto_route: true)     │
│ • Hijack-DNS: перехват DNS -> DoH 1.1.1.1 (detour: xray-upstream)      │
│ • Прямой РФ-DNS: DoT (type: tls, server: 77.88.8.8, без detour)        │
│ • Динамический Split-Tunneling: rules.json (process_path_regex)        │
│ • Встроенный Clash API: 127.0.0.1:9090 (secret из api_secret 0640)     │
│ • Отслеживание процессов: route.find_process: true                     │
└──────────────────┬─────────────────────────────────┬───────────────────┘
                   │ .ru / Госуслуги / LAN (IPv4)    │ Зарубежный / AI трафик
                   ▼                                 ▼
           [Выход direct]               [Локальный сокет: 127.0.0.1:18088]
                   │                                 │
                   │                                 ▼
                   │   ┌─────────────────────────────────────────────────────────────┐
                   │   │ ЗОНА 2: Headless Xray-core (GID 889: _vpnguard_proxy)       │
                   │   │ • Вход: SOCKS5 (18088) и HTTP (18089) строго lo0 (127.0.0.1)│
                   │   │ • Протоколы: VLESS Reality (Vision), TLS (TCP/xhttp/WS/gRPC)│
                   │   │ • Выход: ТОЛЬКО sub-anchor vpnguard/egress (<ip>:<port>)    │
                   │   │ • Правила: proxy и block (freedom/direct исключены)         │
                   │   └───────────────────────┬─────────────────────────────────────┘
                   │                           │
                   ▼                           ▼
┌────────────────────────────────────────────────────────────────────────┐
│ ЯДРО macOS XNU PF (/etc/pf.anchors/vpnguard + vpnguard/egress)        │
│ • GID 888 (vpnguard-exec): только lo0 + block return out quick all     │
│ • GID 889 (_vpnguard_proxy): lo0:18088/18089 + anchor "egress" + drop  │
│ • GID 890 (sing-box): pass out quick inet proto {tcp, udp} group 890   │
│ • lo0 & utun99: pass quick all                                         │
│ • <lan_networks> port 53: block return out quick proto {tcp, udp}      │
│ • LAN IPv4 + DHCP + mDNS + link-local IPv6 (строго ipv6-icmp + 5353)   │
│ • Kill-Switch: block return out quick inet6 all + block return out all │
└────────────────────────────────────────────────────────────────────────┘
```

Дополнительно в системе действует **ЗОНА 1 (GID 888: `vpnguard`)**:
- Обычный пользователь **исключён** из группы `vpnguard` в DirectoryService.
- В GID 888 процесс может войти **только** через `vpnguard-exec` (`04750 root:admin`), который очищает supplementary groups (`setgroups(1, &888)`), сбрасывает `IFS`, `BASH_ENV`, `ENV`, `CDPATH` (сохраняя пользовательский `PATH`), задаёт `BROWSER=/usr/local/bin/vpnguard-browser` и прокси-переменные.
- Профиль `vpnguard-browser` изолирован в `/var/db/vpnguard/browser-profile` (`0770 root:vpnguard`) и проверяет через `ps -o gid=`, что Chromium не запущен с этим профилем вне GID 888.

---

## 3. Спецификация пакетного фильтра macOS XNU PF

### 3.1. Структура основного анкора `/etc/pf.anchors/vpnguard`
```pf
table <lan_networks> const { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }

# GID 888 (Sandbox Client Jail)
pass quick on lo0 proto { tcp, udp } from { 127.0.0.0/8, ::1 } to { 127.0.0.0/8, ::1 } group 888 flags any keep state (if-bound)
block return out quick all group 888

# GID 889 (vpnguard-proxy / Xray Daemon)
pass quick on lo0 proto tcp from 127.0.0.1 port { 18088, 18089 } to 127.0.0.1 group 889 flags any keep state (if-bound)
block drop out quick on lo0 all group 889
anchor "egress"
block drop out quick all group 889

# GID 890 (vpnguard-tun / sing-box Daemon — строго IPv4)
pass out quick inet proto { tcp, udp } from any to any group 890 keep state (if-bound)

# Loopback и TUN
pass quick on lo0 all flags any keep state
pass quick on utun99 all flags any keep state

# Блокировка утечек обычного DNS на LAN-роутеры (RFC1918) для всех кроме GID 890
block return out quick proto { tcp, udp } from any to <lan_networks> port 53

# Локальные сети и link-local IPv6 (строго NDP/ICMPv6 и Bonjour mDNSv6)
pass quick inet proto udp from any port 67:68 to any port 67:68 no state
pass quick inet proto udp from any to 224.0.0.0/4 no state
pass quick inet proto udp from any to <lan_networks> no state
pass quick inet proto udp from <lan_networks> to any no state
pass quick inet proto tcp from any to <lan_networks> no state
pass quick inet proto tcp from <lan_networks> to any no state
pass quick inet proto icmp from any to <lan_networks> no state
pass quick inet proto icmp from <lan_networks> to any no state
pass quick on !utun99 inet6 proto ipv6-icmp from fe80::/10 to fe80::/10 no state
pass quick on !utun99 inet6 proto ipv6-icmp from fe80::/10 to ff02::/16 no state
pass quick on !utun99 inet6 proto udp from fe80::/10 to ff02::fb port 5353 no state

# Глобальный Fail-Closed Kill-Switch
block return out quick inet6 all
block return out quick all
```

### 3.2. Динамический sub-anchor `vpnguard/egress` (`/usr/local/etc/vpnguard/pf.egress.conf`)
В XNU PF таблицы не хранят порты, а таблицы родительского анкора не разделяются sub-anchor'ом. Поэтому для поддержки любых портов (443, 8443, 2053 и т.д.) и протокола `h3` (`xhttp` ALPN `["h2", "h3"]`) активный узел записывается напрямую в `/usr/local/etc/vpnguard/pf.egress.conf` (`0644 root:wheel`):
```pf
pass out quick proto { tcp, udp } from any to { <ip1>, <ip2> } port <port> group 889 keep state (if-bound)
```
Файл загружается через `pfctl -a vpnguard/egress -f /usr/local/etc/vpnguard/pf.egress.conf` при переключении серверов и на холодном старте в `vpnguard-pf-boot.sh` (без модификации файлов исходного кода в репозитории).

### 3.3. Позиция в `/etc/pf.conf` и DNS-синхронизация
- Скрипт [vpnguard-pf-boot.sh](file:///Users/radmirizikaev/Desktop/Business/%D0%9A%D0%BE%D0%B4%D0%B8%D0%BD%D0%B3/%D0%90%D0%BD%D1%82%D0%B8%20%D0%B2%D0%BF%D0%BD%20%D0%BC%D0%BE%D1%80%D0%B3%D0%B0%D0%BD%D0%B8%D0%B5/src/pf/vpnguard-pf-boot.sh) выставляет `PATH`, проверяет, что `anchor "vpnguard"` находится **перед** фильтрующим `anchor "com.apple/*"` (и после `scrub-anchor`/`nat-anchor`/`rdr-anchor`/`dummynet-anchor`), активирует PF с reference token (`pfctl -E`) и загружает `vpnguard` + `vpnguard/egress`.
- При `vpnguard off` сбрасываются оба анкора (`vpnguard/egress` и `vpnguard`), освобождается токен (`pfctl -X`) и восстанавливается системный DNS из `/usr/local/etc/vpnguard/dns_backup.json`.
- При `vpnguard on` и `vpnguard dns-sync` физические `en*`-сервисы из `networksetup -listnetworkserviceorder` получают `1.1.1.1` (исходные настройки сохраняются в `dns_backup.json` без перезаписи уже сохранённых сервисов), после чего сбрасывается кэш `mDNSResponder`.

---

## 4. Движок прозрачной маршрутизации и DNS (`sing-box` 1.14.4+)

### 4.1. Конфигурация DNS
- `dns-remote`: `type: "https"`, `server: "1.1.1.1"`, `path: "/dns-query"`, `detour: "xray-upstream"`.
- `dns-direct`: `type: "tls"`, `server: "77.88.8.8"` (**без `detour`** — в `sing-box 1.14+` указание `"detour": "direct"` вызывает `FATAL`, тогда как при `auto_detect_interface: true` без `detour` трафик идёт напрямую через `en0` под GID 890).
- Приоритет DNS-правил: `user_proxy_domains` → `user_direct_domains` → `ruDirect` → `aiServicesProxy` → `AAAA reject`.

### 4.2. Иерархия правил маршрутизации `build_singbox_config()`
1. `sniff` → `hijack-dns` (порт 53 / протокол `dns`).
2. `reject` QUIC (UDP 443 при `blockQuic`).
3. `ip_is_private` → `direct`.
4. Приложения (`process_path_regex`).
5. Пользовательские домены (`domain_suffix`).
6. Пресеты (`aiServicesProxy`, `ruDirect`).
7. Блокировка прочего `udp` (`action: "reject"`).
8. `final`: **`"xray-upstream"`** (контролируется жёсткими программными `ValueError`-инвариантами внутри `build_singbox_config()`, предотвращающими случайный Fail-Open).

---

## 5. Безопасность Clash API, `sudoers` и `--stdin`

### 5.1. Clash API (`127.0.0.1:9090`)
- В `sing-box 1.14.4` нет опции `external_controller_unix` (это опция mihomo), а `socks` outbound не поддерживает Unix-сокеты. Поэтому Clash API слушает `127.0.0.1:9090`, а Xray — `127.0.0.1:18088` / `18089`.
- **Разделение прав**:
  - `/usr/local/etc/vpnguard/sing-box.json` имеет права **`0600 root:wheel`** (непривилегированные процессы не могут прочитать токен из конфига).
  - `/usr/local/etc/vpnguard/api_secret` имеет права **`0640 root:admin`** (читается `root` и приложением `VPNGuard.app` под учёткой администратора без лишних вызовов `sudo`).
- Не-секретные метаданные активного профиля (`activeServerId`, `activeServerName`, `relayIp`, `relayPort`) дублируются в `/usr/local/etc/vpnguard/active_server.json` (`0644 root:wheel`), чтобы `vpnguard status --json` без `sudo` не возвращал `null`.

### 5.2. Модель `sudoers` с нулевым количеством wildcard (`*`)
В `/etc/sudoers.d/vpnguard` запрещены любые `*`, `pfctl -F all`, `launchctl` и `vpnguard-pf-boot.sh`. Все мутирующие команды принимают данные исключительно через `--stdin` (с ограничением размера 1 МБ в `read_stdin_bounded()`):
- `rules apply --stdin`
- `server import-vless --stdin`
- `server activate --stdin`
- `server delete --stdin`
- `server update --stdin`
- Точные команды без аргументов: `on`, `off`, `dns-sync`, `status`, `status --json`, `status --json --fast`, `rules get`, `server list`, `server list --json`, `test`, `test --json`, а также read-only `pfctl` запросы для статуса.

---

## 6. Профили серверов и транзакционный откат (`.bak`)

- Хранилище `/usr/local/etc/vpnguard/servers.json` (`0600 root:wheel`). При пустом хранилище мигрирует текущий `xray.json` через `parse_xray_server_json(primary_cfg, default_name="Основной сервер")`.
- `cmd_server_update` синхронизируется с `servers.json` и затем вызывает `activate_server()`.
- `activate_server()` и `cmd_rules_apply()`:
  1. Валидируют конфиги (`xray run -test` и `sing-box check`).
  2. Сохраняют `.bak` копии (`xray.json.bak`, `sing-box.json.bak`, `rules.json.bak`, предыдущий `pf.egress.conf`).
  3. Применяют конфигурацию атомарно (`os.replace`) и обновляют `vpnguard/egress`.
  4. Перезапускают демоны и мониторят `pgrep` / `utun99` / порты `18088, 18089`. При сбое автоматически восстанавливают `.bak`.
  5. При успехе вызывают `flush_dns_cache()` (`dscacheutil -flushcache` + `killall -HUP mDNSResponder`).

---

## 7. Нативное macOS-приложение `VPNGuardApp`

```
app/VPNGuardApp/
├── Package.swift
├── build_app.sh
├── Resources/
│   ├── AppIcon.icns
│   └── Info.plist
├── Sources/VPNGuardApp/
│   ├── App/
│   │   ├── AppDelegate.swift        # signal(SIGPIPE, SIG_IGN), background MenuBar policy
│   │   └── VPNGuardApp.swift
│   ├── Models/
│   │   ├── AuditModels.swift
│   │   ├── RulesModels.swift
│   │   ├── ServerModels.swift       # VlessPreviewParser (с проверкой порта 1–65535)
│   │   ├── StatusModels.swift
│   │   └── TrafficModels.swift      # Статический ISO8601DateFormatter
│   ├── Services/
│   │   ├── AppDiscoveryService.swift
│   │   ├── CLIExecutor.swift        # stdinData + конкурентный Pipe + timeout + SIGPIPE ignore
│   │   ├── TrafficMonitorService.swift # WebSocket /connections & /traffic + автореконнект
│   │   └── VPNGuardService.swift    # --stdin вызовы, getifaddrs utun99, чтение api_secret
│   ├── ViewModels/
│   │   └── VPNGuardViewModel.swift  # Гибридный поллинг, NWPathMonitor, единый LaunchAgent
│   └── Views/
│       ├── Apps/ (AppPickerSheet.swift, AppsManagementView.swift)
│       ├── Common/ (GlassCard.swift, ToastView.swift)
│       ├── Dashboard/DashboardView.swift
│       ├── MenuBar/MenuBarExtraView.swift
│       ├── Server/ServerConfigView.swift
│       ├── Traffic/TrafficMonitorView.swift # LazyVStack + freeze-on-hover
│       ├── Websites/WebsitesManagementView.swift
│       └── MainContainerView.swift
└── Tests/VPNGuardAppTests/
    └── VPNGuardAppTests.swift
```

---

## 8. Инварианты для ИИ-агентов и карта системных путей

### 8.1. Незыблемые инварианты
1. **Только `127.0.0.1` для локальных сокетов**: `127.0.0.1:9090`, `127.0.0.1:18088`, `127.0.0.1:18089`.
2. **Fail-Closed `route.final == "xray-upstream"`**: в `sing-box.json` запрещён catch-all `direct`; в `xray.json` запрещены `freedom`/`direct`.
3. **Защита `SIGPIPE` и `Pipe` deadlock в Swift**: не убирать `signal(SIGPIPE, SIG_IGN)` и читать `stdout`/`stderr` до `waitUntilExit()`.
4. **Без `SMAppService` и `osascript` Login Items** при ad-hoc подписи (`codesign -s -`), иначе после пересборки меняющийся CDHash ломает автозапуск; используется только `~/Library/LaunchAgents/com.vpnguard.app.plist`.
5. **AMFI Code Signing на ARM64**: после копирования Mach-O бинарников в `/usr/local/libexec/` выполнять `xattr -c` и `codesign --force -s -`.
6. **Нулевые `*` в `sudoers`** и запрет записи runtime-данных в `PROJECT_ROOT`.

### 8.2. Карта системных путей
| Компонент / Файл | Системный путь | Владелец и права | Назначение |
|---|---|---|---|
| Исполняемый CLI | `/usr/local/bin/vpnguard` | `root:wheel 755` | Главный CLI вход |
| C Setuid Helper | `/usr/local/bin/vpnguard-exec` | `root:admin 4750` | Setuid песочница GID 888 |
| Браузерный wrapper | `/usr/local/bin/vpnguard-browser` | `root:wheel 755` | Изолированный Chromium |
| Профиль браузера | `/var/db/vpnguard/browser-profile` | `root:vpnguard 770` | Изолированный `--user-data-dir` |
| sing-box бинарник | `/usr/local/libexec/vpnguard-singbox` | `root:wheel 755` | TUN daemon Mach-O |
| Xray бинарник | `/usr/local/libexec/vpnguard-xray` | `root:wheel 755` | Proxy daemon Mach-O |
| PF Bootstrap | `/usr/local/libexec/vpnguard-pf-boot.sh` | `root:wheel 755` | Инициализация фаервола |
| Правила анкора PF | `/etc/pf.anchors/vpnguard` | `root:wheel 644` | Основной анкор PF |
| Динамический egress PF | `/usr/local/etc/vpnguard/pf.egress.conf` | `root:wheel 644` | Sub-anchor `vpnguard/egress` |
| Sudoers правила | `/etc/sudoers.d/vpnguard` | `root:wheel 440` | Точные правила без `*` |
| Секрет Clash API | `/usr/local/etc/vpnguard/api_secret` | `root:admin 640` | 32-hex секретный токен |
| Конфиг sing-box | `/usr/local/etc/vpnguard/sing-box.json` | `root:wheel 600` | Конфигурация TUN |
| Конфиг Xray | `/usr/local/etc/vpnguard/xray.json` | `root:vpnguard-proxy 640` | Upstream релей |
| Профили серверов | `/usr/local/etc/vpnguard/servers.json` | `root:wheel 600` | Хранилище серверов VLESS |
| Метаданные сервера | `/usr/local/etc/vpnguard/active_server.json` | `root:wheel 644` | Не-секретное имя/ID/хост |
| Бэкап системного DNS | `/usr/local/etc/vpnguard/dns_backup.json` | `root:wheel 644` | Исходные DNS до `vpnguard on` |
| Динамические правила | `/usr/local/etc/vpnguard/rules.json` | `root:wheel 644` | Правила приложений/доменов |
| macOS Приложение | `/Applications/VPNGuard.app` | `admin:staff 755` | Нативное SwiftUI GUI |

### 8.3. Чеклист верификации после изменений
```bash
python3 -m py_compile src/vpnguard.py
bash -n install.sh uninstall.sh src/pf/vpnguard-pf-boot.sh src/browser/vpnguard-browser app/VPNGuardApp/build_app.sh
/usr/local/libexec/vpnguard-singbox check -c src/singbox/sing-box.json
pfctl -n -v -f src/pf/vpnguard.pf.conf
python3 -m unittest discover -s tests -v          # 18 тестов
(cd app/VPNGuardApp && swift test && swift build -c release --arch arm64)  # 4 Swift-теста + сборка
sudo -n /usr/local/bin/vpnguard test --json      # 12/12 живых проверок после install.sh
```
