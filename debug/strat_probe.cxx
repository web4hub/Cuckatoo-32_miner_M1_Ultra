/* strat_probe: a non-hanging probe of the grin stratum login/job response.
 * Sends the exact login + getjobtemplate frames the miner sends (same formatter)
 * and dumps the node's raw replies. Hard SO_RCVTIMEO so it cannot hang. Debug only. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/time.h>
#include "m1mean_sidecar_job_assigner.h"

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    const char *port = argc > 2 ? argv[2] : "3416";
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) { printf("DNS_FAIL\n"); return 1; }
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { printf("SOCKET_FAIL\n"); return 2; }
    struct timeval tv = {4, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) { printf("CONNECT_FAIL\n"); return 3; }
    printf("CONNECTED %s:%s\n", host, port); fflush(stdout);

    char msg[4096];
    size_t n = m1mean_sidecar_format_login_frame("login", "m1miner", "x", "mine34-live", msg, sizeof msg);
    if (n == 0) { printf("FORMAT_LOGIN_FAIL\n"); return 4; }
    printf("SEND_LOGIN(%zu): %.*s", n, (int)n, msg); fflush(stdout);
    if (send(fd, msg, n, 0) != (ssize_t)n) { printf("SEND_FAIL\n"); return 5; }

    int requested_job = 0;
    char buf[65536];
    for (int i = 0; i < 10; i++) {
        ssize_t r = recv(fd, buf, sizeof buf - 1, 0);
        if (r <= 0) { printf("[recv=%zd, done/timeout]\n", r); break; }
        buf[r] = 0;
        printf("RECV: %s", buf);
        if (buf[r-1] != '\n') printf("\n");
        fflush(stdout);
        if (!requested_job) {
            size_t m = m1mean_sidecar_format_getjobtemplate_frame("getjob", msg, sizeof msg);
            if (m) { send(fd, msg, m, 0); printf("SEND_GETJOB(%zu): %.*s", m, (int)m, msg); fflush(stdout); }
            requested_job = 1;
        }
    }
    close(fd);
    printf("PROBE_DONE\n");
    return 0;
}
