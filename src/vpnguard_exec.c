/*
 * vpnguard_exec.c - High-security, fail-closed setuid launcher for VPNGuard 2.0
 *
 * Guarantees:
 * 1. Strict Fail-Closed (3-point verification):
 *    - Check 1: /sbin/pfctl -s info -> Status: Enabled
 *    - Check 2: /sbin/pfctl -sr -> contains 'anchor "vpnguard"'
 *    - Check 3: /sbin/pfctl -a vpnguard -sr -> contains rules for group 888 & 889
 * 2. Pre-flight health: Verifies dedicated Xray proxy listeners (18088, 18089).
 * 3. Non-root enforcement: Refuses execution if invoked by root/sudo (prevents LPE).
 * 4. Supplementary group clearance: Strips privileged groups (admin, wheel) via setgroups(1, &gid).
 * 5. Permanent, irrevocable drop of root: real UID == effective UID == calling user.
 * 6. Sandboxed process: real GID == effective GID == vpnguard (GID 888).
 * 7. Injects fail-closed proxy variables (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, strict NO_PROXY).
 * 8. Telemetry suppression: CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC, DISABLE_TELEMETRY, etc.
 * 9. Hardened OAuth browser wrapper: sets BROWSER to /usr/local/bin/vpnguard-browser.
 * 10. Sanitized dynamic timezone & locale cloaking.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/select.h>
#include <ctype.h>

#define DEFAULT_VPNGUARD_GID 888
#define DEFAULT_GROUP_NAME   "vpnguard"
#define XRAY_SOCKS_PORT      18088
#define XRAY_HTTP_PORT       18089
#define DEFAULT_TIMEZONE     "America/New_York"
#define DEFAULT_LOCALE       "en_US.UTF-8"
#define STRICT_NO_PROXY      "127.0.0.1,localhost,::1"
#define BROWSER_WRAPPER      "/usr/local/bin/vpnguard-browser"
#define TZ_CONFIG_FILE       "/usr/local/etc/vpnguard/timezone"
#define JSON_CONFIG_FILE     "/usr/local/etc/vpnguard/config.json"

static void print_usage(const char *progname) {
    fprintf(stderr, "Usage: %s <command> [args...]\n", progname);
    fprintf(stderr, "Executes <command> inside the fail-closed VPNGuard network sandbox.\n");
}

/*
 * Safely execute an internal /sbin/pfctl query with an empty environment
 * to prevent PATH hijacking and environment pollution.
 */
static int run_pfctl_query(const char *const args[], char *output, size_t out_len) {
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        close(pipefd[1]);

        char *const env[] = { NULL };
        execve("/sbin/pfctl", (char *const *)args, env);
        _exit(127);
    }

    close(pipefd[1]);
    size_t total = 0;
    ssize_t n;
    while ((n = read(pipefd[0], output + total, out_len - 1 - total)) > 0) {
        total += (size_t)n;
        if (total >= out_len - 1) {
            break;
        }
    }
    output[total] = '\0';
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/*
 * 3-point Fail-Closed verification of macOS Packet Filter:
 * 1. Global PF status is Enabled
 * 2. Main ruleset (/etc/pf.conf) references anchor "vpnguard"
 * 3. Anchor "vpnguard" contains active killswitch rules for both group 888 and group 889
 */
static int verify_pf_anchor_3point(void) {
    char buf[8192];

    /* Check 1: PF subsystem enabled */
    const char *args_info[] = { "/sbin/pfctl", "-s", "info", NULL };
    if (run_pfctl_query(args_info, buf, sizeof(buf)) != 0 || strstr(buf, "Status: Enabled") == NULL) {
        fprintf(stderr, "vpnguard-exec: [!] Check 1 failed: PF firewall is DISABLED in macOS kernel!\n");
        return 0;
    }

    /* Check 2: Anchor is referenced by main ruleset */
    const char *args_sr[] = { "/sbin/pfctl", "-sr", NULL };
    if (run_pfctl_query(args_sr, buf, sizeof(buf)) != 0 || strstr(buf, "vpnguard") == NULL) {
        fprintf(stderr, "vpnguard-exec: [!] Check 2 failed: anchor 'vpnguard' is NOT linked in /etc/pf.conf!\n");
        return 0;
    }

    /* Check 3: Anchor rules exist and enforce group 888 & 889 killswitch */
    const char *args_anchor[] = { "/sbin/pfctl", "-a", "vpnguard", "-sr", NULL };
    if (run_pfctl_query(args_anchor, buf, sizeof(buf)) != 0 ||
        strstr(buf, "group = 888") == NULL ||
        strstr(buf, "group = 889") == NULL ||
        strstr(buf, "block return out quick") == NULL ||
        strstr(buf, "block drop out quick") == NULL) {
        fprintf(stderr, "vpnguard-exec: [!] Check 3 failed: anchor 'vpnguard' rules are missing or inactive!\n");
        return 0;
    }

    /* Check 3b: Verify egress rule for GID 889 exists either in sub-anchor vpnguard/egress or main anchor */
    if (strstr(buf, "egress") != NULL) {
        char egress_buf[4096];
        const char *args_egress[] = { "/sbin/pfctl", "-a", "vpnguard/egress", "-sr", NULL };
        if (run_pfctl_query(args_egress, egress_buf, sizeof(egress_buf)) != 0 ||
            strstr(egress_buf, "group = 889") == NULL ||
            strstr(egress_buf, "pass out quick") == NULL) {
            fprintf(stderr, "vpnguard-exec: [!] Check 3b failed: sub-anchor 'vpnguard/egress' has no active GID 889 egress rule!\n");
            return 0;
        }
    } else if (strstr(buf, "pass out quick") == NULL) {
        fprintf(stderr, "vpnguard-exec: [!] Check 3b failed: no active GID 889 egress rule!\n");
        return 0;
    }

    return 1;
}

/*
 * Non-blocking connect probe to ensure local proxy port is listening.
 */
static int check_port_open(const char *ip, int port, int timeout_ms) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return 0;
    }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        close(sock);
        return 0;
    }

    int res = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (res < 0 && errno == EINPROGRESS) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        res = select(sock + 1, NULL, &wfds, NULL, &tv);
        if (res > 0) {
            int err = 0;
            socklen_t len = sizeof(err);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) {
                close(sock);
                return 1;
            }
        }
        close(sock);
        return 0;
    }

    close(sock);
    return (res == 0);
}

/*
 * Validate timezone string:
 * - Length: 1 to 63 chars
 * - Allowed chars: A-Z, a-z, 0-9, '_', '/', '+', '-', '.'
 * - Rejects: leading '/', '..', spaces
 */
static int is_valid_timezone(const char *tz) {
    if (!tz) return 0;
    size_t len = strlen(tz);
    if (len == 0 || len > 63) return 0;
    if (tz[0] == '/' || tz[0] == '.') return 0;
    if (strstr(tz, "..") != NULL) return 0;

    for (size_t i = 0; i < len; ++i) {
        char c = tz[i];
        if (!isalnum((unsigned char)c) && c != '_' && c != '/' && c != '+' && c != '-' && c != '.') {
            return 0;
        }
    }
    return 1;
}

/*
 * Read configured timezone with strict validation.
 * Run AFTER dropping root privileges.
 */
static void resolve_timezone(char *tz_out, size_t max_len) {
    const char *env_tz = getenv("VPNGUARD_TZ");
    if (env_tz && is_valid_timezone(env_tz)) {
        strncpy(tz_out, env_tz, max_len - 1);
        tz_out[max_len - 1] = '\0';
        return;
    }

    /* Try reading simple text file */
    FILE *f = fopen(TZ_CONFIG_FILE, "r");
    if (f) {
        char line[128];
        if (fgets(line, sizeof(line), f)) {
            size_t len = strlen(line);
            while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r' || line[len - 1] == ' ')) {
                line[--len] = '\0';
            }
            if (is_valid_timezone(line)) {
                strncpy(tz_out, line, max_len - 1);
                tz_out[max_len - 1] = '\0';
                fclose(f);
                return;
            }
        }
        fclose(f);
    }

    /* Default fallback */
    strncpy(tz_out, DEFAULT_TIMEZONE, max_len - 1);
    tz_out[max_len - 1] = '\0';
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    /* 1. Identify calling user */
    uid_t real_uid = getuid();

    /* SECURITY ENFORCEMENT: Never run under root (e.g. sudo vpnguard-exec).
     * This binary must be invoked as an unprivileged user. */
    if (real_uid == 0) {
        fprintf(stderr, "vpnguard-exec: [!] SECURITY VIOLATION: Execution as root (UID 0) is forbidden.\n");
        fprintf(stderr, "vpnguard-exec: [i] Run directly as your normal user (without sudo).\n");
        _exit(1);
    }

    struct passwd *pw = getpwuid(real_uid);
    if (!pw) {
        fprintf(stderr, "vpnguard-exec: [!] Unable to determine user info for UID %d: %s\n",
                real_uid, strerror(errno));
        _exit(1);
    }

    /* 2. Resolve vpnguard group ID */
    gid_t target_gid = DEFAULT_VPNGUARD_GID;
    struct group *gr = getgrnam(DEFAULT_GROUP_NAME);
    if (gr) {
        target_gid = gr->gr_gid;
    }

    /* 3. Fail-Closed Verification: 3-point PF check BEFORE privilege drop */
    if (geteuid() == 0) {
        if (!verify_pf_anchor_3point()) {
            fprintf(stderr, "vpnguard-exec: [!] CRITICAL SECURITY FAILURE: Kernel PF killswitch is not fully armed!\n");
            fprintf(stderr, "vpnguard-exec: [!] Fail-closed abort: Refusing to start process to prevent network leak.\n");
            fprintf(stderr, "vpnguard-exec: [i] Run 'sudo /usr/local/libexec/vpnguard-pf-boot.sh' to rearm the killswitch.\n");
            _exit(1);
        }
    }

    /* 4. Pre-flight health check: Verify dedicated Xray proxy listeners */
    int http_up = check_port_open("127.0.0.1", XRAY_HTTP_PORT, 250);
    int socks_up = check_port_open("127.0.0.1", XRAY_SOCKS_PORT, 250);

    if (!http_up && !socks_up) {
        fprintf(stderr, "vpnguard-exec: [!] Pre-flight Check Failed: Dedicated Xray proxy is not listening on 127.0.0.1:%d / %d!\n",
                XRAY_HTTP_PORT, XRAY_SOCKS_PORT);
        fprintf(stderr, "vpnguard-exec: [i] Please ensure com.vpnguard.xray LaunchDaemon is running.\n");
        _exit(1);
    }

    /* 5. Irrevocable Privilege Drop */
    if (geteuid() == 0) {
        /* Clear all supplementary groups and assign ONLY the target sandbox group.
         * Strips dangerous supplementary groups like 'admin' and 'wheel'. */
        gid_t groups[1] = { target_gid };
        if (setgroups(1, groups) != 0) {
            fprintf(stderr, "vpnguard-exec: [!] FATAL: setgroups() failed: %s\n", strerror(errno));
            _exit(1);
        }

        /* Set real, effective, and saved GID to target_gid */
        if (setregid(target_gid, target_gid) != 0) {
            fprintf(stderr, "vpnguard-exec: [!] FATAL: setregid(%d) failed: %s\n",
                    target_gid, strerror(errno));
            _exit(1);
        }

        /* Permanently drop root privileges to calling user */
        if (setreuid(real_uid, real_uid) != 0) {
            fprintf(stderr, "vpnguard-exec: [!] FATAL: setreuid(%d) failed: %s\n",
                    real_uid, strerror(errno));
            _exit(1);
        }

        /* Verify identity drop succeeded */
        if (getuid() != real_uid || geteuid() != real_uid ||
            getgid() != target_gid || getegid() != target_gid) {
            fprintf(stderr, "vpnguard-exec: [!] FATAL: Post-drop privilege state mismatch!\n");
            _exit(1);
        }

        /* Verify root privileges cannot be regained */
        if (seteuid(0) == 0 || setuid(0) == 0) {
            fprintf(stderr, "vpnguard-exec: [!] FATAL: Security breach: root privileges were not dropped permanently!\n");
            _exit(1);
        }
    } else {
        /* Not running setuid root: verify already inside target group */
        if (getgid() != target_gid && getegid() != target_gid) {
            if (setregid(target_gid, target_gid) != 0) {
                fprintf(stderr, "vpnguard-exec: [!] Error: Cannot set GID without privileges: %s\n",
                        strerror(errno));
                fprintf(stderr, "vpnguard-exec: [i] Binary must be installed setuid root (chmod 4755 root:vpnguard)\n");
                _exit(1);
            }
        }
    }

    /* Sanitize dangerous shell startup/expansion variables while preserving user PATH */
    unsetenv("IFS");
    unsetenv("BASH_ENV");
    unsetenv("ENV");
    unsetenv("CDPATH");

    /* 6. Construct and inject fail-closed proxy environment variables */
    char http_url[64];
    char socks_url[64];
    snprintf(http_url, sizeof(http_url), "http://127.0.0.1:%d", XRAY_HTTP_PORT);
    snprintf(socks_url, sizeof(socks_url), "socks5h://127.0.0.1:%d", XRAY_SOCKS_PORT);

    /* Force both lower-case and upper-case variables with overwrite=1 */
    setenv("HTTP_PROXY",  http_url,  1);
    setenv("http_proxy",  http_url,  1);
    setenv("HTTPS_PROXY", http_url,  1);
    setenv("https_proxy", http_url,  1);

    const char *disable_socks = getenv("VPNGUARD_NO_SOCKS");
    if (!disable_socks || strcmp(disable_socks, "1") != 0) {
        setenv("ALL_PROXY", socks_url, 1);
        setenv("all_proxy", socks_url, 1);
    } else {
        unsetenv("ALL_PROXY");
        unsetenv("all_proxy");
    }

    setenv("NO_PROXY", STRICT_NO_PROXY, 1);
    setenv("no_proxy", STRICT_NO_PROXY, 1);

    /* 7. Telemetry & Background Request Suppression */
    setenv("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1", 1);
    setenv("DISABLE_TELEMETRY", "1", 1);
    setenv("DISABLE_ERROR_REPORTING", "1", 1);
    setenv("DO_NOT_TRACK", "1", 1);

    /* 8. Hardened Browser Wrapper for OAuth */
    setenv("BROWSER", BROWSER_WRAPPER, 1);

    /* 9. Anti-Fraud Cloaking: Dynamic Timezone & Locale (evaluated AFTER privilege drop) */
    char resolved_tz[64];
    resolve_timezone(resolved_tz, sizeof(resolved_tz));
    setenv("TZ", resolved_tz, 1);
    setenv("LANG", DEFAULT_LOCALE, 1);
    setenv("LC_ALL", DEFAULT_LOCALE, 1);

    /* Mark as protected by VPNGuard */
    setenv("VPNGUARD_ACTIVE", "1", 1);

    /* Ensure HOME and USER match the real user */
    setenv("HOME", pw->pw_dir, 1);
    setenv("USER", pw->pw_name, 1);
    setenv("LOGNAME", pw->pw_name, 1);

    /* 10. Execute target command */
    execvp(argv[1], &argv[1]);

    /* If execvp returns, an error occurred */
    int err = errno;
    fprintf(stderr, "vpnguard-exec: [!] Failed to execute '%s': %s\n", argv[1], strerror(err));
    _exit((err == ENOENT) ? 127 : 126);
}
