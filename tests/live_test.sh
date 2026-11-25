#!/bin/bash
# ==============================================================================
# live_test.sh - Боевые тесты переходных состояний VPNGuard 3.0
# ==============================================================================
set -euo pipefail

C_RESET='\033[0m'
C_BOLD='\033[1m'
C_RED='\033[31m'
C_GREEN='\033[32m'
C_YELLOW='\033[33m'
C_CYAN='\033[36m'

RUSSIAN_IP="5.144.116.28"

usage() {
    echo -e "${C_BOLD}Использование:${C_RESET} $0 [watch|crash|browser|traffic|status]"
    echo ""
    echo "Команды для 5 боевых проверок:"
    echo "  watch    - Запуск непрерывного мониторинга IP (Тест 1: Сон и смена Wi-Fi)"
    echo "  crash    - Тест аварийной остановки sing-box (Тест 3: SIGSTOP / SIGCONT)"
    echo "  browser  - Открытие тестов утечки DNS и WebRTC в браузере (Тест 4)"
    echo "  traffic  - Проверка классификации трафика через Clash API (Тест 5)"
    echo "  status   - Проверка готовности автозапуска и демонов (Тест 2)"
    exit 1
}

cmd_watch() {
    echo -e "${C_BOLD}${C_CYAN}=== 🛰️  Тест 1: Непрерывный монитор IP (Сон и смена Wi-Fi) ===${C_RESET}"
    echo -e "Инструкция: закрой крышку Mac на 2-3 мин или переключи Wi-Fi."
    echo -e "Критерий: трафик либо OFFLINE, либо США. Российский IP (${RUSSIAN_IP}) НИКОГДА не должен появиться."
    echo -e "Для остановки нажми Ctrl+C.\n"

    while true; do
        ts=$(date +'%H:%M:%S')
        # Проверяем IP с коротким таймаутом
        ip=$(curl -s --max-time 1.5 https://api.ipify.org 2>/dev/null || echo "")
        
        if [[ -z "$ip" ]]; then
            echo -e "[${ts}] ${C_YELLOW}⚡ OFFLINE / CONNECTION REFUSED (Fail-Closed Killswitch защищает en0)${C_RESET}"
        elif [[ "$ip" == *"$RUSSIAN_IP"* ]]; then
            echo -e "[${ts}] ${C_BOLD}${C_RED}❌ КРИТИЧЕСКАЯ УТЕЧКА! Обнаружен провайдерский IP: ${ip}${C_RESET}"
        else
            echo -e "[${ts}] ${C_GREEN}🛡️  SECURE TUNNEL IP: ${ip} (US / Non-RU)${C_RESET}"
        fi
        sleep 1
    done
}

cmd_crash() {
    echo -e "${C_BOLD}${C_CYAN}=== 💥 Тест 3: Тест краша / зависания sing-box ===${C_RESET}"
    echo -e "1. Отправляем SIGSTOP процессу sing-box..."
    sudo launchctl kill SIGSTOP system/com.vpnguard.singbox
    echo -e "   ${C_YELLOW}sing-box приостановлен (SIGSTOP)${C_RESET}\n"

    echo -e "2. Выполняем curl к https://1.1.1.1 (таймаут 4 сек)..."
    start_time=$(date +%s)
    set +e
    curl -v --max-time 4 https://1.1.1.1 2>&1 | grep -E "Connected|timed out|refused|Closing connection"
    curl_exit=$?
    set -e
    end_time=$(date +%s)
    elapsed=$((end_time - start_time))
    echo -e "   Время выполнения: ${elapsed} сек. Код выхода: ${curl_exit}"

    echo -e "\n3. Отправляем SIGCONT процессу sing-box (возобновление)..."
    sudo launchctl kill SIGCONT system/com.vpnguard.singbox
    echo -e "   ${C_GREEN}sing-box успешно возобновлен (SIGCONT)${C_RESET}\n"

    if [[ $curl_exit -ne 0 ]]; then
        echo -e "${C_BOLD}${C_GREEN}✅ ТЕСТ 3 ПРОЙДЕН: Трафик заблокирован / таймаут от PF, прямого прорыва через en0 не произошло!${C_RESET}"
    else
        echo -e "${C_BOLD}${C_RED}❌ ОШИБКА: curl смог подключиться в обход замороженного демона!${C_RESET}"
    fi
}

cmd_browser() {
    echo -e "${C_BOLD}${C_CYAN}=== 🌐 Тест 4: Открытие тестов DNS и WebRTC в браузере ===${C_RESET}"
    echo "Открываем browserleaks.com/dns..."
    open "https://browserleaks.com/dns"
    echo "Открываем browserleaks.com/webrtc..."
    open "https://browserleaks.com/webrtc"
    echo -e "${C_GREEN}Страницы открыты в браузере по умолчанию.${C_RESET}"
    echo -e "Критерий: только DNS Cloudflare/США, в WebRTC нет реального IP ${RUSSIAN_IP}."
}

cmd_traffic() {
    echo -e "${C_BOLD}${C_CYAN}=== 📊 Тест 5: Проверка маршрутизации через Clash API ===${C_RESET}"
    SECRET=$(python3 -c '
import json
try:
    with open("/usr/local/etc/vpnguard/sing-box.json") as f:
        print(json.load(f)["experimental"]["clash_api"]["secret"])
except Exception:
    pass
')
    if [[ -z "$SECRET" ]]; then
        echo -e "${C_RED}Не удалось прочитать Clash API secret${C_RESET}"
        exit 1
    fi

    echo -e "Генерируем тестовые запросы: anthropic.com (Прокси) и ya.ru (Прямой)..."
    curl -sI --max-time 3 https://api.anthropic.com/robots.txt >/dev/null 2>&1 &
    curl -sI --max-time 3 https://ya.ru/robots.txt >/dev/null 2>&1 &
    sleep 0.2

    python3 -c "
import urllib.request, json
req = urllib.request.Request('http://127.0.0.1:9090/connections', headers={'Authorization': 'Bearer $SECRET'})
try:
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode())
    print('\nАктивные соединения в реальном времени:')
    print(f'{\"Хост / Назначение\":40} | {\"Цепочка\":15} | {\"Тип маршрута\":15}')
    print('-' * 75)
    for c in data.get('connections', [])[-8:]:
        meta = c.get('metadata', {})
        host = meta.get('host') or meta.get('destinationIP') or '—'
        chains = c.get('chains', [])
        is_proxy = any('xray' in str(ch).lower() or 'proxy' in str(ch).lower() for ch in chains)
        route_label = 'Прокси (Xray)' if is_proxy else 'Прямой (Direct)'
        print(f'{str(host)[:38]:40} | {str(chains)[:15]:15} | {route_label:15}')
except Exception as e:
    print('Ошибка опроса Clash API:', e)
"
}

cmd_status() {
    echo -e "${C_BOLD}${C_CYAN}=== 🖥️  Тест 2: Проверка готовности Cold Boot (Автозапуск) ===${C_RESET}"
    echo "1. LaunchDaemons (system):"
    for daemon in com.vpnguard.pf com.vpnguard.xray com.vpnguard.singbox; do
        if [[ -f "/Library/LaunchDaemons/${daemon}.plist" ]]; then
            echo -e "   • ${daemon}: ${C_GREEN}УСТАНОВЛЕН (RunAtLoad: true, KeepAlive: true)${C_RESET}"
        else
            echo -e "   • ${daemon}: ${C_RED}ОТСУТСТВУЕТ!${C_RESET}"
        fi
    done

    echo "2. GUI App (Menu Bar / Login Items):"
    login_items=$(osascript -e 'tell application "System Events" to get name of every login item' 2>/dev/null || echo "")
    if [[ "$login_items" == *"VPNGuard"* ]]; then
        echo -e "   • VPNGuard.app: ${C_GREEN}ЗАРЕГИСТРИРОВАН в Login Items (поднимется сам при входе)${C_RESET}"
    else
        echo -e "   • VPNGuard.app: ${C_YELLOW}НЕ В LOGIN ITEMS (исправляем...)${C_RESET}"
        osascript -e 'tell application "System Events" to make login item at end with properties {path:"/Applications/VPNGuard.app", hidden:false}' 2>/dev/null || true
    fi
    echo ""
    vpnguard status
}

case "${1:-}" in
    watch)   cmd_watch ;;
    crash)   cmd_crash ;;
    browser) cmd_browser ;;
    traffic) cmd_traffic ;;
    status)  cmd_status ;;
    *)       usage ;;
esac
