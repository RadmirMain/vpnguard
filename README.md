# 🛡️ VPNGuard 3.0 (macOS)
### Аппаратная система предотвращения утечек IP/DNS и «моргания» VPN на базе XNU PF, sing-box TUN и выделенного Xray-core с нативным SwiftUI-приложением

**VPNGuard 3.0** — комплексная система системной защиты от микроразрывов («моргания») VPN, скрытых утечек реального IP-адреса, утечек IPv6 и незашифрованных DNS-запросов для разработчиков из РФ, использующих **Claude Code**, **Cursor**, **Codex**, **ChatGPT**, **Git**, веб-авторизацию OAuth и системные браузеры.

Архитектура системы реализует герметичный контур безопасности по принципу **Fail-Closed**: при падении, рестарте или смене сети трафик, не идущий через туннель `utun99` или авторизованный узел `<ip>:<port>` в sub-anchor `vpnguard/egress`, мгновенно сбрасывается ядром macOS (`Packet Filter`).

---

## 📌 В чём проблема («Моргание VPN»)?

1. **Микроразрывы туннеля**: При переподключении VPN или смене сети (Wi-Fi ↔ iPhone USB) туннель кратковременно падает.
2. **Мгновенный fallback**: Сетевой стек macOS немедленно переключает маршрут по умолчанию на физический интерфейс (`en0`).
3. **Утечка IP, IPv6 и DNS**: Системный демон `mDNSResponder` отправляет запросы на локальный DNS роутера (RFC1918), а браузеры и Swift-приложения при наличии нативного IPv6 уходят в обход IPv4-туннеля по Happy Eyeballs.
4. **Результат**: Блокировка аккаунтов Anthropic / OpenAI, компрометация сессий и сброс рабочего окружения.

**VPNGuard 3.0** устраняет эти векторы на уровне ядра XNU PF, прозрачного TUN-интерфейса `sing-box` и принудительной синхронизации DNS.

---

## 🏛️ Архитектура Triple-GID Jail & TUN

```
┌────────────────────────────────────────────────────────────────────────┐
│ macOS Приложения (Dock, Spotlight, LaunchServices)                     │
│ Claude.app, Cursor.app, Codex.app, Chrome, Terminal, etc.              │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼ (Шлюз по умолчанию / utun99)
┌────────────────────────────────────────────────────────────────────────┐
│ ЗОНА 3: Headless sing-box TUN Daemon (GID 890: vpnguard-tun, root)     │
│ • Сетевой интерфейс: utun99 (172.19.0.1/30, стек gVisor, auto_route)   │
│ • Hijack-DNS: перехват DNS -> DoH 1.1.1.1 (через xray-upstream)        │
│ • Прямой РФ-DNS: шифрованный DoT (tls://77.88.8.8:853)                 │
│ • Динамический Split-Tunneling: rules.json (process_path_regex)        │
│ • Защищённый Clash API: 127.0.0.1:9090 (секрет api_secret, 640 admin)  │
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

Дополнительно в системе работает **ЗОНА 1 (GID 888: `vpnguard`)** — setuid-песочница `vpnguard-exec` (`04750 root:admin`) для явного запуска изолированных CLI-сессий (`vpnguard run`, `vpnguard shell`) и изолированного OAuth-браузера `vpnguard-browser` с профилем в `/var/db/vpnguard/browser-profile` (`0770 root:vpnguard`). Обычный пользователь **не состоит** в группе `888`.

---

## 🖥️ Нативное macOS-приложение `VPNGuard.app`

Приложение написано на SwiftUI (macOS 14+, MVVM) и располагается в `/Applications/VPNGuard.app`, работая как в основном окне, так и в MenuBar:

1. **«Обзор» (Dashboard)**:
   - Мастер-переключатель защиты (Fail-Closed Kill-Switch ON/OFF) + кнопка ручного обновления внешнего IP.
   - Гибридный мониторинг без спама в `ipinfo.io`: нативная проверка `utun99` через `getifaddrs` каждые 2.5с, локальный `--fast` опрос счётчиков PF каждые 45с и автоматическая реакция на смену сети через `NWPathMonitor` (`vpnguard dns-sync`).
   - Запуск 12-точечного аудита утечек (`vpnguard test --json`).
2. **«Приложения» (Apps)**:
   - Управление правилами маршрутизации приложений по `bundlePath` (`Туннель` / `Напрямую` / `Блок`).
   - Выбор установленных программ через `AppPickerSheet`.
3. **«Сайты и домены» (Websites)**:
   - Пользовательские домены и пресеты (*AI-сервисы через туннель*, *Сервисы РФ напрямую*, *Блокировка QUIC UDP:443*).
4. **«Монитор трафика» (Traffic Monitor)**:
   - Потоковое подключение к `sing-box` Clash API по WebSocket (`ws://127.0.0.1:9090/connections` и `/traffic`) с автопереподключением и автоматическим закрытием сокетов при уходе со вкладки или закрытии окна.
   - Живые счётчики скорости (↓/↑), `LazyVStack`, поиск, фильтрация, пауза обновления списка при наведении курсора (`onHover`) и принудительный разрыв сессий.
5. **«Сервер» (Server Config & Upstream)**:
   - Быстрый импорт `vless://` и JSON-конфигов через `--stdin` с живым предпросмотром (`VlessPreviewParser`, проверка порта `1–65535`).
   - Транзакционное переключение серверов с валидацией `xray run -test` + `sing-box check`, обновлением `vpnguard/egress` на любой порт и автоматическим откатом на `.bak` при сбое.
   - Расширенный режим (Raw JSON) с синхронизацией в `servers.json`.

Автозапуск приложения при входе управляется единым механизмом — `~/Library/LaunchAgents/com.vpnguard.app.plist`.

---

## 🚀 Быстрый старт

### 1. Требования
* macOS 14.0 (Sonoma) или новее (Apple Silicon `arm64`).
* Homebrew (`brew install xray sing-box`).

### 2. Установка и сборка
```bash
cd "/Users/radmirizikaev/Desktop/Business/Кодинг/Анти впн моргание"

# (Опционально) Установите ядра, если ещё не установлены
brew install xray sing-box

# Установите системные демоны, PF, CLI и sudoers
sudo ./install.sh

# Соберите и установите /Applications/VPNGuard.app
./app/VPNGuardApp/build_app.sh
```

Инсталлятор в автоматическом режиме:
- Создаст системные группы `vpnguard` (888), `vpnguard-proxy` (889), `vpnguard-tun` (890) и системного пользователя `_vpnguard_proxy` (UID 489); исключит `TARGET_USER` из группы `888`.
- Установит и подпишет ad-hoc подписью `/usr/local/libexec/vpnguard-xray` и `/usr/local/libexec/vpnguard-singbox`.
- Создаст `/var/db/vpnguard/browser-profile` (`0770 root:vpnguard`).
- Сгенерирует `/usr/local/etc/vpnguard/api_secret` (`0640 root:admin`) и `/usr/local/etc/vpnguard/sing-box.json` (`0600 root:wheel`).
- Настроит `/etc/pf.anchors/vpnguard`, `/usr/local/etc/vpnguard/pf.egress.conf` и `/etc/sudoers.d/vpnguard` (строго без wildcard `*`).
- Активирует `LaunchDaemons` (`com.vpnguard.pf`, `com.vpnguard.xray`, `com.vpnguard.singbox`) и синхронизирует DNS.

> **Важно после первой установки**: выйдите из сеанса macOS или перезагрузите Mac, чтобы активный терминал и графическая сессия сбросили кэшированную группу `888(vpnguard)`.

---

## 💻 Управление через CLI (`vpnguard`)

| Команда | Описание |
|---|---|
| `vpnguard status [--fast]` | Полный статус безопасности, состояние демонов, `utun99` и Clash API (`--fast` без внешнего `curl`). |
| `vpnguard status --json [--fast]` | Машиночитаемый JSON-статус для GUI. |
| `sudo vpnguard on` | Запуск Xray/sing-box, армирование PF, сохранение `dns_backup.json` и установка DNS `1.1.1.1`. |
| `sudo vpnguard off` | Сброс PF (включая `vpnguard/egress`), остановка `sing-box`, восстановление исходного DNS из `dns_backup.json`. |
| `sudo vpnguard dns-sync` | Идемпотентная синхронизация DNS (`1.1.1.1`) на активных `en*`-интерфейсах при смене сети. |
| `sudo vpnguard test [--json]` | Запуск 12-точечного аудита утечек (включая сквозную проверку `utun99` и блокировку LAN:53). |
| `sudo vpnguard rules get` | Просмотр текущих правил маршрутизации `rules.json`. |
| `sudo vpnguard rules apply [--stdin \| <path>]` | Атомарная валидация и применение `rules.json` с откатом на `.bak` и сбросом кэша `mDNSResponder`. |
| `sudo vpnguard server list [--json]` | Список настроенных upstream-серверов. |
| `sudo vpnguard server import-vless [--stdin \| <path>]` | Импорт `vless://` или Xray JSON в `servers.json`. |
| `sudo vpnguard server activate [--stdin \| <id>]` | Переключение активного сервера с обновлением `vpnguard/egress` (любой порт) и откатом на `.bak`. |
| `sudo vpnguard server delete [--stdin \| <id>]` | Удаление неактивного профиля сервера. |
| `sudo vpnguard server update [--stdin \| <path>]` | Обновление из сырого Xray JSON с синхронизацией в `servers.json`. |
| `sudo vpnguard server sync-pf` | Перегенерация `/usr/local/etc/vpnguard/pf.egress.conf` и загрузка в `vpnguard/egress`. |
| `vpnguard run <команда...>` | Запуск команды внутри изолированного GID 888 sandbox-контура (`vpnguard-exec`). |
| `vpnguard shell` | Интерактивная защищённая оболочка внутри GID 888. |
| `vpnguard watch` | Непрерывный мониторинг состояния прокси и уведомления при обрывах. |

---

## 🧪 Тестирование и аудит

```bash
# 1. Python unit-тесты (18 тестов)
python3 -m unittest discover -s tests -v

# 2. Swift unit-тесты (4 теста) и Release-сборка
cd app/VPNGuardApp && swift test && swift build -c release --arch arm64

# 3. Живой 12-точечный аудит безопасности
sudo vpnguard test
```

### Просмотр логов и удаление
```bash
sudo tail -f /var/log/vpnguard-singbox.log /var/log/vpnguard-xray.log /var/log/vpnguard.log

# Полное удаление (с бэкапом servers.json в ~/.vpnguard-backup/)
sudo ./uninstall.sh
```
