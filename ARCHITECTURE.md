# 🏛️ VPNGuard 3.0: Полная архитектура и техническая спецификация

> **Статус документа**: Актуальная системная спецификация VPNGuard 3.0.  
> **Операционная инструкция для ИИ-агентов**: [AGENTS.md](AGENTS.md).

---

## 1. Концепция и модель угроз

### 1.1. Проблема «моргания» VPN (VPN Blinking & Silent Leaks)
При использовании обычных GUI-клиентов на macOS во время реконнекта, засыпания или смены `Wi-Fi ↔ модем` возникают короткие провалы маршрута:
1. **Сброс дефолтного маршрута**: `configd`/`networkd` немедленно отправляет пакеты на физический интерфейс (`en0`, `en5`).
2. **Утечки DNS через `mDNSResponder`**: нативные приложения резолвят домены через Mach IPC к `_mdnsresponder`. Если DHCP выдал локальный DNS роутера (RFC1918), а `auto_route` исключил частные сети, DNS-запросы уходят на роутер в обход `utun99`.
3. **Утечка IPv6 (Happy Eyeballs, RFC 8305)**: при наличии IPv6 на интерфейсе браузеры и `URLSession` предпочитают IPv6 мимо IPv4-туннеля.
4. **QUIC и прямой UDP**: UDP `443` (HTTP/3) и не-TCP/UDP протоколы обходят HTTP/SOCKS-прокси.

### 1.2. Принцип Fail-Closed
- Любой исходящий пакет, не направленный в `lo0`, `utun99`, разрешённую локальную сеть или динамический sub-anchor `vpnguard/egress` (`<ip>:<port>` для `GID 889`), сбрасывается ядром XNU PF (`block return out quick`).
- Внешний IPv6 и plain DNS (порт `53`) к `<lan_networks>` блокируются на уровне PF.

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
│ • Split-Tunneling: rules.json (process_path_regex и process_path)      │
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
│ • GID 890 (sing-box & bypass workers): pass out quick inet group 890   │
│ • lo0 & utun99: pass quick all                                         │
│ • <lan_networks> port 53: block return out quick proto {tcp, udp}      │
│ • LAN IPv4 + DHCP + mDNS + link-local IPv6 (строго ipv6-icmp + 5353)   │
│ • Kill-Switch: block return out quick inet6 all + block return out all │
└────────────────────────────────────────────────────────────────────────┘
```

### Зона 1: `GID 888` (`vpnguard`)
- Обычный пользователь **исключён** из группы `vpnguard` в DirectoryService.
- В `GID 888` процесс попадает только через `vpnguard-exec` (`04750 root:admin`), который проверяет 3-точечный статус PF и порты `18088/18089`, сбрасывает привилегии, очищает supplementary groups (`setgroups(1, &888)`), выставляет прокси-переменные, `TZ`, `LANG`, `BROWSER=/usr/local/bin/vpnguard-browser` и запрещает запуск от `real_uid == 0`.
- Изолированный профиль Chromium расположен в `/var/db/vpnguard/browser-profile` (`0770 root:vpnguard`).

---

## 3. Спецификация пакетного фильтра XNU PF

### 3.1. Основной анкор `/etc/pf.anchors/vpnguard`
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

# GID 890 (vpnguard-tun / sing-box Daemon & bypass probes — строго IPv4)
pass out quick inet proto { tcp, udp } from any to any group 890 keep state (if-bound)

# Loopback и TUN
pass quick on lo0 all flags any keep state
pass quick on utun99 all flags any keep state

# Блокировка утечек обычного DNS на LAN-роутеры (RFC1918)
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
```pf
pass out quick proto { tcp, udp } from any to { <ip1>, <ip2> } port <port> group 889 keep state (if-bound)
```
Загружается через `pfctl -a vpnguard/egress -f /usr/local/etc/vpnguard/pf.egress.conf` при старте в [vpnguard-pf-boot.sh](src/pf/vpnguard-pf-boot.sh), при переключении серверов и при `vpnguard server sync-pf`. При выключении (`off`/`flush`/`stop`) анкоры `vpnguard/egress` и `vpnguard` сбрасываются строго **до** снятия PF-токена `pfctl -X` и удаления `/var/run/vpnguard/pf.token`; при включении существующий токен переиспользуется только при `Status: Enabled` в `pfctl -s info`.

### 3.3. Обходные проверки через `GID 890 + IP_BOUND_IF = 25`
При включённом `utun99` обычный трафик уходит в туннель до проверки PF. Чтобы измерить реальный пинг серверов (`server ping --json`) или напрямую отрезолвить домен релея (`server sync-pf`, `activate_server`, `_cmd_on_locked`), `_run_in_gid890_worker()` форкает дочерний процесс, сбрасывает права в последовательности `os.setgroups([890])` → `os.setgid(890)` → `os.setuid(nobody)`, привязывает TCP/UDP-сокеты к физическому интерфейсу (из `netstat -rn -f inet`, исключая `utun*`/`lo*`/`awdl*`) через `setsockopt(IPPROTO_IP, 25, ...)` и ограничивает ожидание результата через `select.select()` с `SIGKILL` + `waitpid()` по таймауту.
- `server ping --json` берёт кэшированные `resolvedIps` из `servers.json` и параллельно замеряет TCP RTT.
- `server sync-pf` отправляет прямой RFC 1035 UDP A-запрос на `1.1.1.1:53` / `8.8.8.8:53`, обновляет `pf.egress.conf`, а при смене IP релея обновляет `servers.json`, `active_server.json`, `route_exclude_address` в `sing-box.json` и перезапускает `sing-box`.
- `activate_server()` резолвит домен напрямую через `resolve_ipv4_direct_via_gid890()`, при выключенном VPN лишь сохраняет конфиги без `launchctl kickstart`, а при включённом VPN проверяет слушатели `18088`/`18089` и `utun99` (`get_utun_status()`), выполняя полный откат конфигов, `vpnguard/egress` и перезапуск демонов (`_rollback_activation()`) при сбое или исключении.

---

## 4. Маршрутизация и DNS (`sing-box` 1.14.4+)

### 4.1. Конфигурация DNS
- `dns-remote`: `type: "https"`, `server: "1.1.1.1"`, `path: "/dns-query"`, `detour: "xray-upstream"`.
- `dns-direct`: `type: "tls"`, `server: "77.88.8.8"` (**без `detour`** — в `sing-box 1.14+` `"detour": "direct"` вызывает `FATAL`).
- Пользовательские правила доменов (`dns.rules` и `route.rules`) сортируются по убыванию специфичности (числу меток домена) с группировкой только смежных однотипных правил (`example.com -> proxy` не перебивает `local.example.com -> direct`), а пользовательские `.ru` прокси-домены идут строго перед `ruDirect`.
- `sync_system_dns()` синхронизирует только активные `en*`-сервисы (`_get_active_en_interfaces()`), а `restore_system_dns()` проходит по всем сервисам из `dns_backup.json` и списку аппаратных сервисов; `flush_dns_cache()` вызывается только при фактическом изменении DNS.

### 4.2. Иерархия правил `build_singbox_config()`
1. `sniff` → `hijack-dns` (порт `53` / протокол `dns`).
2. `reject` QUIC (`UDP 443` при `blockQuic`).
3. `ip_is_private` → `direct`.
4. Приложения: `.app`-бандлы через `process_path_regex` (`^/Path/App\.app/.*`), CLI-бинарники через точный `process_path`.
5. Пользовательские домены (`domain_suffix`, упорядоченные по специфичности).
6. Пресеты (`aiServicesProxy`, `ruDirect`).
7. Блокировка прочего `udp` (`action: "reject"`).
8. `final`: **`"xray-upstream"`** (контролируется программными `ValueError`-инвариантами).

---

## 5. Безопасность Clash API, `sudoers`, логов и паузы Wi-Fi

### 5.1. Clash API и разделение прав
- `/usr/local/etc/vpnguard/sing-box.json`: **`0600 root:wheel`**.
- `/usr/local/etc/vpnguard/api_secret`: **`0640 root:admin`** (читается GUI без `sudo`).
- `/usr/local/etc/vpnguard/active_server.json`: **`0644 root:wheel`** (не-секретные метаданные).
- `/var/db/vpnguard/desired_state`: **`0644 root:wheel`** (`on` / `off`, синхронизируется с `launchctl enable/disable` для `com.vpnguard.pf` и `com.vpnguard.singbox`, предотвращая ложное включение при загрузке macOS).

### 5.2. Модель `sudoers` (ноль `*`) и блокировка состояния
`/etc/sudoers.d/vpnguard` разрешает исключительно точные команды:
- `--stdin` (с ограничением `MAX_STDIN_BYTES = 1 MiB` в `read_stdin_bounded()`): `rules apply --stdin`, `server import-vless --stdin`, `server activate --stdin`, `server delete --stdin`, `server update --stdin`.
- Точные команды без пользовательских аргументов: `on`, `off`, `pause 300`, `pause 900`, `resume-if-expired`, `dns-sync`, `status`, `status --json`, `status --json --fast`, `rules get`, `server list`, `server list --json`, `server ping --json`, `server sync-pf`, `test`, `test --json`, `logs --json`, а также read-only `pfctl`.
- Мутирующие команды (`on`, `off`, `pause`, `resume-if-expired`, `rules apply`, `server activate`, `server update`) и фаза возврата в `pause-watcher` сериализуются через re-entrant неблокирующий `acquire_state_lock()` (`fcntl.flock`, `/var/run/vpnguard/state.lock`, таймаут 15с).

### 5.3. Санитизация и ротация диагностических логов (`vpnguard logs --json`)
Логи в `/var/log/vpnguard*.log` недоступны непривилегированному GUI напрямую (`640 root:wheel` / `_vpnguard_proxy`).
- `get_pf_status()` объединяет чтение правил и счётчика блокировок в один вызов `pfctl -a vpnguard -s rules -v` через `_run_pfctl()`.
- `_tail_file_lines()` читает последние 150 строк бинарным `seek` с конца файла блоками по `8192` Б с единым декодированием UTF-8.
- Xray пишет логи через `launchd` (`StandardOutPath`/`StandardErrorPath`) без дублирующего файлового `error`-вывода; `rotate_log_if_needed()` ротирует логи > `8 MiB` в `.1` строго до `bootstrap`/`kickstart`.
- Команда `vpnguard logs --json` прогоняет хвост логов и состояние `pfctl`/`scutil --dns`/`ifconfig utun99` через `redact_sensitive_text()` (маскирует `vless://`, `trojan://`, `ss://`, `vmess://`, UUID, ключи Reality, `Bearer`-токены, JSON-поля `password`/`psk`/`privateKey`/`token`/`auth`, query-параметры, `api_secret` и адреса/SNI серверов).

### 5.4. Fail-Safe пауза для Captive Portal (`vpnguard pause`) и Headless Watcher (`vpnguard-netwatch`)
- **Captive Portal 2.0 (`vpnguard pause`)**: останавливает `sing-box` и `xray`, переводит якорь `vpnguard` на `/etc/pf.anchors/vpnguard-captive` (сохраняя `pfctl -E` токен и блокировку `GID 888/889/890`), восстанавливает DHCP DNS, записывает `pause_until` и случайный `pause_token` в `/var/run/vpnguard/` (`0644 root:wheel`), запуская ровно один `pause-watcher`.
- `pause-watcher` проверяет дедлайн, детектирует сон через `(dt_wall - dt_mono) > 10.0` и опрашивает `captive.apple.com` через `http.client.HTTPConnection` (без прокси и редиректов, таймаут `2.5 с`, двойной `Success`). Перед возвратом `cmd_on()` проверяет совпадение `pause_token` под `acquire_state_lock()`. При включении защиты `_cmd_on_locked()` сбрасывает старые состояния PF (`pfctl -k`) по физическим IPv4/IPv6 адресам строго до запуска `xray`/`sing-box`.
- **Headless-демон `vpnguard-netwatch` (`com.vpnguard.netwatch`)**: бинарник на Swift (`Sources/VPNGuardNetWatch/main.swift`) с `SCDynamicStore` (`State:/Network/Global/IPv4`, `State:/Network/Global/DNS`) и `IORegisterForSystemPower` (немедленный `IOAllowPowerChange` на сон, синхронизация через `2.5 с` после пробуждения). Выполняет `dns-sync` и `server sync-pf` последовательно (single-flight, таймаут `15 с` с `proc.terminate()`) только при `desired_state == on` и отсутствии активной captive-паузы, с `5 с` cooldown для DNS-событий.

---

## 6. Сборка, самообновление и структура `VPNGuardApp`

### 6.1. Релизный пайплайн GitHub Releases и локальное обновление (`update.sh`)
- **Единый источник версии**: файл `VERSION` (сейчас `3.0.1`) в корне репозитория считывается в `build_app.sh`, `update.sh` и `.github/workflows/release.yml`, записываясь в `CFBundleShortVersionString` до подписи бандла.
- **GitHub Releases (`.github/workflows/release.yml` + `GitHubReleaseUpdater.swift`)**:
  - При пуше тега `v*` CI (`macos-15`) устанавливает `sing-box` и `xray` через Homebrew, прогоняет Swift и оффлайн Python-тесты, собирает `VPNGuard.app`, упаковывает системный бэкенд (`src/`, `bin/` за вычетом 30 МБ `vpnguard-xray` и `bin/vpnguard-exec`, предсобранный `libexec/vpnguard-exec`, `install.sh`, `backend.sha256`) в `Contents/Resources/backend/`, пакует бандл через `ditto`, считает `.sha256` и подписывает архив приватным ключом **Ed25519** (`RELEASE_SIGNING_PRIVATE_KEY` → `.sig`).
  - Приложение опрашивает `releases/latest` с `ETag` / `If-None-Match` (при `403` — `HEAD` redirect-фолбэк), проверяет Ed25519-подпись по вшитому публичному ключу, `SHA-256` и `codesign`, подготавливает staging на разделе `/Applications` и перезапускается через `nohup` (с логом в `~/Library/Logs/VPNGuard/github-update-relaunch.log`) без `open -n` и с таймаутом ожидания PID `10с`.
  - После запуска новой версии приложение сверяет встроенный `backend.sha256` с `/usr/local/etc/vpnguard/backend.sha256` и при расхождении предлагает обновить системный слой через Touch ID (`install.sh --backend-only`).
- **Локальное двухэтапное обновление (`update.sh`)**:
  - `update.sh --check` выполняет `git fetch` с таймаутом `5с` (`GIT_TERMINAL_PROMPT=0`) и сравнивает `backend.sha256` и `frontend.sha256`.
  - Сборка `.app` идёт от обычного пользователя в `/tmp`, `frontend.sha256`, `Resources/backend/` (без `vpnguard-xray` и `bin/vpnguard-exec`) и `xattr -cr` выполняются **до** `codesign --force --deep --sign -`.
  - Elevation через Touch ID (`osascript`) вызывается только при изменении бэкенда (`install.sh --backend-only`), при этом `install.sh` и `uninstall.sh` определяют `TARGET_USER` через `stat -f '%Su' /dev/console`.

### 6.2. Структура `app/VPNGuardApp`
```
app/VPNGuardApp/
├── Package.swift
├── build_app.sh
├── Resources/
│   ├── AppIcon.icns
│   └── Info.plist
├── Sources/
│   ├── VPNGuardNetWatch/
│   │   └── main.swift               # Headless LaunchDaemon: SCDynamicStore + IOKit sleep/wake -> dns-sync & sync-pf
│   └── VPNGuardApp/
│       ├── App/
│       │   ├── AppDelegate.swift        # signal(SIGPIPE, SIG_IGN), background MenuBar policy
│       │   └── VPNGuardApp.swift        # MenuBarExtra (условный TimelineView паузы) & Control Center window
│       ├── Models/
│       │   ├── AuditModels.swift        # AuditStatus (.pass/.degraded/.unknown/.fail), AuditReport
│       │   ├── DiagnosticsModels.swift  # DiagnosticsLogsSnapshot
│       │   ├── RulesModels.swift
│       │   ├── ServerModels.swift       # VlessPreviewParser, ServerPingResult, UpdateCheckResult
│       │   ├── StatusModels.swift       # ProtectionState (+ .tunnelRecovering), SystemStatus (+ pauseUntil)
│       │   └── TrafficModels.swift      # ClashConnection (+ ruleDisplay/dnsDisplay/chainsDisplay), ByteFormatter
│       ├── Services/
│       │   ├── AppDiscoveryService.swift
│       │   ├── CLIExecutor.swift        # stdinData + конкурентный Pipe + немедленный возврат при timeout
│       │   ├── GitHubReleaseUpdater.swift # Ed25519 + SHA-256 + ETag + backend.sha256 sync + nohup relaunch
│       │   ├── TrafficMonitorService.swift # WebSocket /connections & /traffic + connectionsVersion
│       │   └── VPNGuardService.swift    # CLI wrapper, direct browser launcher, reusable URLSession 204 probe, update.sh
│       ├── ViewModels/
│       │   └── VPNGuardViewModel.swift  # Параллельный старт, stateEpoch, UI NWPathMonitor, willSleep/didWake, failover
│       └── Views/
│           ├── Apps/ (AppPickerSheet.swift, AppsManagementView.swift — стабильный Binding по id + AppIconCache)
│           ├── Common/ (DesignTokens.swift [VGPrimitives, VGTokens, VGComponentTokens], DesignSystem.swift [VGCard, VGLoadingStateView, VGErrorBanner, VGIconButtonStyle, VGSurfaceButtonStyle, AppIconCache, VGFormatters], ToastView.swift)
│           ├── Dashboard/DashboardView.swift
│           ├── Diagnostics/DiagnosticsView.swift # 4-статусный аудит + Darwin.getgroups GID 888 + логи + ViewThatFits
│           ├── MenuBar/MenuBarExtraView.swift    # Captive Portal (TimelineView), Tunnel Health, Browser Launcher
│           ├── Server/ServerConfigView.swift     # Единый список серверов (коды стран, без эмодзи), AddServerSheet, GID 890 Ping, Auto-Failover
│           ├── Traffic/TrafficMonitorView.swift  # Кешированная группировка, Live Runtime Inspector (keyboard/VoiceOver), 1-click rules
│           ├── Websites/WebsitesManagementView.swift # Стабильный Binding по id + адаптивный LazyVGrid пресетов
│           └── MainContainerView.swift           # Нативный List(selection:) Sidebar + AppUpdateSheetView + ReduceMotion
└── Tests/VPNGuardAppTests/
    └── VPNGuardAppTests.swift                # 16 unit-тестов (AuditStatus, Explain chain, tunnelRecovering, Ed25519)
```

---

## 7. Карта системных путей

| Компонент / Файл | Системный путь | Владелец и права | Назначение |
|---|---|---|---|
| Исполняемый CLI | `/usr/local/bin/vpnguard` | `root:wheel 755` | Главный CLI вход |
| Код CLI (установленный) | `/usr/local/share/vpnguard/src/vpnguard.py` | `root:wheel 755` | Привилегированная копия CLI |
| C Setuid Helper | `/usr/local/bin/vpnguard-exec` | `root:admin 4750` | Setuid песочница GID `888` |
| Браузерный wrapper | `/usr/local/bin/vpnguard-browser` | `root:wheel 755` | Изолированный Chromium |
| Профиль браузера | `/var/db/vpnguard/browser-profile` | `root:vpnguard 770` | Изолированный `--user-data-dir` |
| Желаемое состояние VPN | `/var/db/vpnguard/desired_state` | `root:wheel 644` | Персистентный флаг `on`/`off` для загрузки macOS |
| `sing-box` бинарник | `/usr/local/libexec/vpnguard-singbox` | `root:wheel 755` | TUN daemon Mach-O |
| `Xray` бинарник | `/usr/local/libexec/vpnguard-xray` | `root:wheel 755` | Proxy daemon Mach-O |
| PF Bootstrap | `/usr/local/libexec/vpnguard-pf-boot.sh` | `root:wheel 755` | Инициализация, captive-профиль и снятие фаервола |
| Headless NetWatch | `/usr/local/libexec/vpnguard-netwatch` | `root:wheel 755` | Swift-демон `SCDynamicStore` + `IOKit` sleep/wake |
| Правила анкора PF | `/etc/pf.anchors/vpnguard` | `root:wheel 644` | Основной анкор PF |
| Captive-профиль PF | `/etc/pf.anchors/vpnguard-captive` | `root:wheel 644` | Временный анкор PF для Wi-Fi авторизации (блокирует GID 888/889/890) |
| Динамический egress PF | `/usr/local/etc/vpnguard/pf.egress.conf` | `root:wheel 644` | Sub-anchor `vpnguard/egress` |
| Sudoers правила | `/etc/sudoers.d/vpnguard` | `root:wheel 440` | Точные правила без `*` |
| Секрет Clash API | `/usr/local/etc/vpnguard/api_secret` | `root:admin 640` | 32-hex секретный токен |
| Конфиг `sing-box` | `/usr/local/etc/vpnguard/sing-box.json` | `root:wheel 600` | Конфигурация TUN |
| Конфиг `Xray` | `/usr/local/etc/vpnguard/xray.json` | `root:vpnguard-proxy 640` | Upstream релей |
| Профили серверов | `/usr/local/etc/vpnguard/servers.json` | `root:wheel 600` | Хранилище серверов VLESS |
| Метаданные сервера | `/usr/local/etc/vpnguard/active_server.json` | `root:wheel 644` | Не-секретное имя/ID/хост |
| Бэкап системного DNS | `/usr/local/etc/vpnguard/dns_backup.json` | `root:wheel 644` | Исходные DNS до `vpnguard on` |
| Динамические правила | `/usr/local/etc/vpnguard/rules.json` | `root:wheel 644` | Правила приложений/доменов |
| Хеш бэкенда | `/usr/local/etc/vpnguard/backend.sha256` | `root:wheel 644` | Эталон для `update.sh` |
| Блокировка мутаций | `/var/run/vpnguard/state.lock` | `root:wheel 644` | Межпроцессный `flock` состояния CLI |
| Токен reference-count PF | `/var/run/vpnguard/pf.token` | `root:wheel 600` | Токен `pfctl -E` для корректного `-X` |
| Таймер паузы Wi-Fi | `/var/run/vpnguard/pause_until` | `root:wheel 644` | Unix-timestamp окончания паузы |
| Токен паузы Wi-Fi | `/var/run/vpnguard/pause_token` | `root:wheel 644` | Защита `pause-watcher` от гонок с `vpnguard off/on` |
| PID watcher'а паузы | `/var/run/vpnguard/pause_watcher.pid` | `root:wheel 644` | Защита от дублей watcher |
| Системные логи сервисов | `/var/log/vpnguard*.log(.1)` | `root:wheel 640` / `_vpnguard_proxy` | Логи PF, sing-box, Xray (ротация 8 MiB -> `.1`) |
| Пользовательские логи GUI | `~/Library/Logs/VPNGuard/*.log` | `user:staff` | Логи запуска браузера и relaunch-обновлений |
| macOS Приложение | `/Applications/VPNGuard.app` | `user:admin 755` | Нативное SwiftUI GUI + `frontend.sha256` |
| LaunchAgent GUI | `~/Library/LaunchAgents/com.vpnguard.app.plist` | `user:staff` | Единый автозапуск приложения |
