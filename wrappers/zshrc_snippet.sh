# ==============================================================================
# VPNGuard Shell Integration Snippet
# Add to your ~/.zshrc or ~/.bashrc:
#   source "${HOME}/Developer/vpnguard/wrappers/zshrc_snippet.sh"
# ==============================================================================

if command -v vpnguard &>/dev/null; then
    # Automatic protection for sensitive AI / cloud developer tools
    alias claude='vpnguard run claude'
    alias codex='vpnguard run codex'
    alias vpn-shell='vpnguard shell'
    alias vpn-status='vpnguard status'
    alias vpn-test='vpnguard test'
    alias vpn-watch='vpnguard watch'
fi
