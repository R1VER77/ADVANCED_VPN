/*
 * isolate: start the packaged llama-server with no network at all.
 *
 * It enters a new user and network namespace (the only interface is a downed loopback;
 * the app reaches the model over a Unix socket), maps the caller's own uid and gid (not
 * root), sets no_new_privs, and execs the one fixed server path. Nothing else can be
 * started through it, so the AppArmor permission that lets it create the namespace on
 * systems restricting unprivileged user namespaces (Ubuntu 24.04 and later; profile
 * cypherpunk-vpn-assistant) covers exactly this.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#ifndef SERVER
#define SERVER "/usr/lib/cypherpunk-vpn/assistant/llama-server"
#endif

static int put(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t n = strlen(text);
    ssize_t written = write(fd, text, n);
    close(fd);
    return written == (ssize_t)n ? 0 : -1;
}

int main(int argc, char **argv) {
    char map[64];
    uid_t uid = getuid();
    gid_t gid = getgid();
    (void)argc;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fprintf(stderr, "isolate: no_new_privs: %s\n", strerror(errno));
        return 125;
    }
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0) {
        fprintf(stderr, "isolate: unshare: %s\n", strerror(errno));
        return 125;
    }
    snprintf(map, sizeof map, "%u %u 1\n", (unsigned)uid, (unsigned)uid);
    if (put("/proc/self/setgroups", "deny") != 0 || put("/proc/self/uid_map", map) != 0) {
        fprintf(stderr, "isolate: unshare: uid map: %s\n", strerror(errno));
        return 125;
    }
    snprintf(map, sizeof map, "%u %u 1\n", (unsigned)gid, (unsigned)gid);
    if (put("/proc/self/gid_map", map) != 0) {
        fprintf(stderr, "isolate: unshare: gid map: %s\n", strerror(errno));
        return 125;
    }
    argv[0] = (char *)SERVER;
    execv(SERVER, argv);
    fprintf(stderr, "isolate: exec %s: %s\n", SERVER, strerror(errno));
    return 126;
}
