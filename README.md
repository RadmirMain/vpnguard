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
   - Мастер-переключатель защиты и живой статус туннеля (*«Связь через туннель: ОК · N мс»*).
   - **Пауза на 5 мин / 15 мин (вход в Wi-Fi)** с обратным отсчётом прямо в строке меню и fail-safe автовозвратом (на системном уровне через `/var/run/vpnguard/pause_until`, работает даже при закрытом GUI или после сна Mac).
   - Быстрый запуск **«Открыть защищённый браузер (GID 888)»** (прямой запуск `vpnguard-browser` без `sudo`).
   - Быстрая смена активного сервера и переход к аудиту утечек.
2. **«Обзор» (Dashboard)**:
   - Статус демонов `vpnguard-xray`, `vpnguard-singbox`, `PF Kill-Switch` (счётчик заблокированных пакетов), выходного IP и краткая сводка аудита.
   - Гибридный мониторинг: нативный `utun99`-зонд каждые 2.5с, локальный `--fast` опрос каждые 45с, реальный health-check прокси каждые 25с и `NWPathMonitor` (`debounce` 2.5с + пауза 6с после пробуждения Mac) с автосинхронизацией DNS и `vpnguard/egress`.
3. **«Приложения» (Apps)**:
   - Правила маршрутизации по `.app`-бандлу (`process_path_regex`) и CLI-бинарникам (`process_path`) с режимами `Туннель` / `Напрямую` / `Блок`.
4. **«Сайты и домены» (Websites)**:
   - Пользовательские домены и системные пресеты (*AI-сервисы через туннель*, *Сервисы РФ напрямую*, *Блокировка QUIC UDP:443*).
5. **«Монитор трафика» (Traffic Monitor)**:
   - Потоковый WebSocket к Clash API (`ws://127.0.0.1:9090/connections` и `/traffic`) с автозакрытием сокетов при уходе со вкладки.
   - Группировка потоков по приложению и домену, пауза при наведении (`onHover`), поиск, фильтр и **правила в 1 клик** (inline-кнопки `Direct` / `VPN` и контекстное меню для домена, корневого домена и приложения).
6. **«Сервер» (Server Config & Upstream)**:
   - Быстрый импорт `vless://` и JSON через `--stdin` с живым предпросмотром (`VlessPreviewParser`).
   - **Пинг серверов** в обход `utun99` (`GID 890` + `IP_BOUND_IF`), сортировка по скорости и **Auto-Failover** (3 пробы → прямой UDP DNS ре-синк `vpnguard/egress` → переключение на быстрейший сервер → 5-минутный cooldown цикла с активным Kill-Switch).
   - Транзакционное переключение с валидацией `xray run -test` + `sing-box check` и откатом на `.bak`.
7. **«Диагностика и логи» (Diagnostics)**:
   - 12-точечный аудит утечек (`vpnguard test --json`) с наглядным чек-листом.
   - Просмотр последних 150 строк логов (`sing-box`, `Xray`, `PF / Boot`) и состояния `PF Rules` / `scutil --dns` / `utun99` через `vpnguard logs --json` с автоматическим маскированием UUID, ключей, секретов и адресов серверов, автообновлением (5с) и экспортом отчёта в Markdown.
8. **Встроенное обновление (`Обновить VPNGuard...`)**:
   - Проверка актуальности (`update.sh --check` с таймаутом `git fetch` 5с и сравнением `backend.sha256` и `frontend.sha256`).
   - Сборка `VPNGuard.app` от пользователя в `/tmp` с атомарной самозаменой и запросом Touch ID (`osascript`) только при изменении файлов бэкенда.

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
3. Откройте `VPNGuard.app` — приложение предложит установить системные компоненты через Touch ID (`install.sh --backend-only`). Последующие обновления из GitHub Releases проверяются криптографической подписью **Ed25519** и **SHA-256** и устанавливаются автоматически.

#### Вариант Б: Сборка из исходников
```bash
git clone https://github.com/RadmirMain/vpnguard.git VPNGuard
cd VPNGuard

# Установка ядер (если ещё не установлены)
brew install xray sing-box

# Установка системных демонов, PF, CLI и hardened sudoers
sudo ./install.sh

# Сборка и установка /Applications/VPNGuard.app
./app/VPNGuardApp/build_app.sh
```

> **После самой первой установки**: выйдите из сеанса macOS или перезагрузите Mac, чтобы активные сессии сбросили кэшированную группу `888(vpnguard)`.

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
| `vpnguard status [--json] [--fast]` | Статус безопасности, демонов, `utun99`, Clash API и `pauseUntil`. |
| `sudo vpnguard on` | Запуск Xray/sing-box, армирование PF, установка DNS `1.1.1.1`, очистка таймера паузы. |
| `sudo vpnguard off` | Сброс PF, остановка `sing-box`, восстановление исходного DNS. |
| `sudo vpnguard pause <300\|900>` | Временный прямой доступ для входа в Wi-Fi с fail-safe автовозвратом по wall-clock таймеру. |
| `sudo vpnguard resume-if-expired` | Немедленный возврат защиты, если время `pause_until` уже истекло. |
| `sudo vpnguard dns-sync` | Идемпотентная синхронизация DNS (`1.1.1.1`) на физических `en*`-интерфейсах. |
| `sudo vpnguard test [--json]` | 12-точечный активный аудит утечек (IP, DNS, IPv6, `utun99`, LPE). |
| `sudo vpnguard logs --json` | Последние 150 строк логов + `pfctl`/`scutil --dns`/`ifconfig utun99` с маскированием секретов. |
| `sudo vpnguard rules get` | Вывод текущего `rules.json`. |
| `sudo vpnguard rules apply [--stdin \| <path>]` | Валидация и атомарное применение `rules.json` с откатом на `.bak`. |
| `sudo vpnguard server list [--json]` | Список настроенных upstream-профилей. |
| `sudo vpnguard server ping --json` | Прямой замер TCP RTT до всех серверов через `GID 890` + `IP_BOUND_IF` в обход `utun99`. |
| `sudo vpnguard server sync-pf` | Прямой UDP DNS ре-синк релея (`GID 890`) и обновление `vpnguard/egress` (+ `sing-box.json` при смене IP). |
| `sudo vpnguard server import-vless [--stdin \| <path>]` | Импорт `vless://` или Xray JSON в `servers.json`. |
| `sudo vpnguard server activate [--stdin \| <id>]` | Транзакционное переключение активного сервера с обновлением `vpnguard/egress`. |
| `sudo vpnguard server delete [--stdin \| <id>]` | Удаление неактивного профиля сервера. |
| `sudo vpnguard server update [--stdin \| <path>]` | Обновление из сырого Xray JSON с синхронизацией в `servers.json`. |
| `vpnguard run <команда...>` | Запуск команды в изолированной песочнице `GID 888` (`vpnguard-exec`). |
| `vpnguard shell` | Интерактивная защищённая оболочка `GID 888`. |
| `vpnguard watch` | Консольный мониторинг состояния локального прокси. |

---

## 🧪 Тестирование и удаление

```bash
# 1. Python unit-тесты (31 тест)
python3 -m unittest discover -s tests -v

# 2. Swift unit-тесты (8 тестов) и Release-сборка
swift test --package-path app/VPNGuardApp
swift build --package-path app/VPNGuardApp -c release --arch arm64

# 3. Живой 12-точечный аудит безопасности
sudo vpnguard test

# 4. Полное удаление (с бэкапом servers.json в ~/.vpnguard-backup/)
sudo ./uninstall.sh
```
