/*
 * pam_facelock.c - Native PAM authentication module for FaceLock (Kali Linux)
 *
 * Author: Muheeb
 * License: MIT
 *
 * Invokes the root-owned FaceLock authentication helper (/usr/lib/facelock/facelock-pam-helper)
 * which launches the Windows Hello-style 3-method prompt (Face / Fingerprint / System Password)
 * on the active desktop display, or falls back cleanly to standard PAM conversation.
 *
 * Exit code protocol from helper:
 *   0  -> PAM_SUCCESS   (User verified via Face, Fingerprint, or System Password)
 *   10 -> PAM_AUTH_ERR  (Explicit authentication rejection / lockout)
 *   *  -> PAM_IGNORE    (User clicked fallback/cancel or no camera/display -> fall through to pam_unix)
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#ifndef FACELOCK_HELPER_PATH
#define FACELOCK_HELPER_PATH "/usr/lib/facelock/facelock-pam-helper"
#endif

#define DEFAULT_TIMEOUT_SEC 40

static int verify_root_owned_executable(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        return -1;
    }
    /* Must be owned by root and not writable by group or others */
    if (st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return -2;
    }
    if ((st.st_mode & S_IXUSR) == 0) {
        return -3;
    }
    return 0;
}

static void copy_env_if_present(pam_handle_t *pamh, const char *key) {
    const char *val = pam_getenv(pamh, key);
    if (!val || val[0] == '\0') {
        val = getenv(key);
    }
    if (val && val[0] != '\0') {
        setenv(key, val, 1);
    }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user = NULL;
    const char *service = NULL;
    const char *tty = NULL;
    const char *rhost = NULL;
    const char *helper_path = FACELOCK_HELPER_PATH;
    int timeout_sec = DEFAULT_TIMEOUT_SEC;

    (void)flags;

    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "timeout=", 8) == 0) {
            int parsed = atoi(argv[i] + 8);
            if (parsed >= 5 && parsed <= 180) {
                timeout_sec = parsed;
            }
        } else if (strncmp(argv[i], "helper=", 7) == 0) {
            helper_path = argv[i] + 7;
        }
    }

    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user || user[0] == '\0') {
        return PAM_IGNORE;
    }

    (void)pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
    (void)pam_get_item(pamh, PAM_TTY, (const void **)&tty);
    (void)pam_get_item(pamh, PAM_RHOST, (const void **)&rhost);

    /* Never trigger local webcam/fingerprint on remote SSH logins */
    if (rhost && rhost[0] != '\0' && strcmp(rhost, "localhost") != 0 && strcmp(rhost, "::1") != 0) {
        pam_syslog(pamh, LOG_INFO, "Skipping FaceLock for remote host login (%s)", rhost);
        return PAM_IGNORE;
    }

    int check = verify_root_owned_executable(helper_path);
    if (check != 0) {
        pam_syslog(pamh, LOG_WARNING,
                   "Helper %s missing or failed root ownership verification (code=%d); falling back",
                   helper_path, check);
        return PAM_IGNORE;
    }

    pid_t pid = fork();
    if (pid < 0) {
        pam_syslog(pamh, LOG_ERR, "fork() failed: %s", strerror(errno));
        return PAM_IGNORE;
    }

    if (pid == 0) {
        /* Child process: sanitize PATH and pass PAM context to helper */
        setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
        setenv("PAM_USER", user, 1);
        setenv("PAM_SERVICE", service ? service : "unknown", 1);
        if (tty && tty[0] != '\0') {
            setenv("PAM_TTY", tty, 1);
        }

        copy_env_if_present(pamh, "DISPLAY");
        copy_env_if_present(pamh, "WAYLAND_DISPLAY");
        copy_env_if_present(pamh, "XAUTHORITY");
        copy_env_if_present(pamh, "XDG_RUNTIME_DIR");
        copy_env_if_present(pamh, "DBUS_SESSION_BUS_ADDRESS");
        copy_env_if_present(pamh, "SUDO_USER");

        char *const args[] = {
            (char *)helper_path,
            "--user",
            (char *)user,
            "--service",
            (char *)(service ? service : "pam"),
            NULL
        };

        execv(helper_path, args);
        _exit(2);
    }

    /* Parent process: poll child with watchdog timeout so PAM never hangs */
    int status = 0;
    time_t start_time = time(NULL);
    while (1) {
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) {
            break;
        }
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return PAM_IGNORE;
        }
        if ((time(NULL) - start_time) >= timeout_sec) {
            pam_syslog(pamh, LOG_WARNING, "FaceLock prompt timed out after %ds; falling back", timeout_sec);
            kill(pid, SIGTERM);
            usleep(150000);
            kill(pid, SIGKILL);
            (void)waitpid(pid, &status, 0);
            return PAM_IGNORE;
        }
        usleep(40000); /* 40ms poll interval */
    }

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 0) {
            pam_syslog(pamh, LOG_INFO, "Authenticated user '%s' for service '%s'",
                       user, service ? service : "pam");
            return PAM_SUCCESS;
        }
        if (code == 10) {
            pam_syslog(pamh, LOG_NOTICE, "Authentication rejected for user '%s'", user);
            return PAM_AUTH_ERR;
        }
    }

    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}
