/*
 * hamza_client.c
 * RFMP C Client - Spring 2026
 * Group: Hamza (415001013), Akour (433002101), Kawtar (433006015), Aya (433000484)
 *
 * This is the simple C version of the client. No encryption - just connects,
 * does the SS/CC handshake, sends an openRead command, prints the file, then quits.
 *
 * Compile:  gcc -o rfmp_c hamza_client.c
 * Run:      ./rfmp_c 127.0.0.1 9090 data.txt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUF 4096


/*
 * send_pkt - sends a packet to the server
 *
 * We add a newline at the end because the server reads until '\n' to know
 * where the packet ends. snprintf into a local buffer keeps us from writing
 * past the end.
 */
void send_pkt(int sock, const char *msg) {
    char buf[BUF];
    snprintf(buf, sizeof(buf), "%s\n", msg);
    send(sock, buf, strlen(buf), 0);
}

/*
 * recv_pkt - reads one packet from the server into buf
 *
 * We read one byte at a time and stop when we hit a newline. It's
 * the simplest way to handle this without a partial-read
 * buffer. The newline gets stripped before returning.
 * Returns the number of bytes read, or -1 if the connection dropped.
 */
int recv_pkt(int sock, char *buf, int maxlen) {
    int n = 0;
    char c;
    while (n < maxlen - 1) {
        if (recv(sock, &c, 1, 0) <= 0) return -1;
        buf[n++] = c;
        if (c == '\n') break;
    }
    buf[n] = '\0';
    if (n > 0 && buf[n-1] == '\n') buf[--n] = '\0';
    return n;
}

/*
 * first_field - pulls out the first pipe-delimited field from a packet
 *
 * Our packets look like "TYPE|field1|field2", so we just find the first
 * pipe and copy everything before it. If there's no pipe, we copy the
 * whole string. Used to check what type of packet the server sent back.
 */
void first_field(const char *pkt, char *out, int maxlen) {
    const char *pipe = strchr(pkt, '|');
    int len = pipe ? (int)(pipe - pkt) : (int)strlen(pkt);
    if (len >= maxlen) len = maxlen - 1;
    strncpy(out, pkt, len);
    out[len] = '\0';
}


int main(int argc, char *argv[]) {
    /*
     * We need exactly three arguments: server IP, port, and the filename
     * to read. If the user didn't provide them, print usage and exit.
     */
    if (argc < 4) {
        fprintf(stderr, "usage: %s <server_ip> <port> <filename>\n", argv[0]);
        return 1;
    }

    const char *ip    = argv[1];
    int         port  = atoi(argv[2]);
    const char *fname = argv[3];

    /* connect */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        fprintf(stderr, "bad IP address: %s\n", ip);
        return 1;
    }
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }
    printf("connected to %s:%d\n", ip, port);

    char buf[BUF], ptype[16], cmd[BUF];

    /*
     * Setup phase: send SS with encryption flag = 0 (no encryption in C client).
     * The server should reply with CC to confirm the session is ready.
     */
    send_pkt(sock, "SS|RFMP|v1.0|0");

    /* wait for CC */
    if (recv_pkt(sock, buf, sizeof(buf)) < 0) {
        fprintf(stderr, "no response to SS\n");
        close(sock);
        return 1;
    }
    first_field(buf, ptype, sizeof(ptype));
    if (strcmp(ptype, "CC") != 0) {
        fprintf(stderr, "expected CC, got: %s\n", buf);
        close(sock);
        return 1;
    }
    printf("handshake ok\n");

    /*
     * Send the openRead command with the filename the user gave us.
     * The server will either reply with DP (file data) or EE (error).
     */
    snprintf(cmd, sizeof(cmd), "CM|openRead|%s", fname);
    send_pkt(sock, cmd);

    /* read the response */
    if (recv_pkt(sock, buf, sizeof(buf)) < 0) {
        fprintf(stderr, "no response to openRead\n");
        close(sock);
        return 1;
    }
    first_field(buf, ptype, sizeof(ptype));

    if (strcmp(ptype, "DP") == 0) {
        /* file contents start after the first pipe */
        const char *content = strchr(buf, '|');
        content = content ? content + 1 : "(empty)";
        printf("\n[%s]\n%s\n", fname, content);
    } else if (strcmp(ptype, "EE") == 0) {
        fprintf(stderr, "server error: %s\n", buf);
    } else {
        fprintf(stderr, "unexpected response: %s\n", buf);
    }

    /* closing phase: send END and wait for the server's goodbye before closing */
    send_pkt(sock, "END");
    recv_pkt(sock, buf, sizeof(buf));
    printf("done\n");

    close(sock);
    return 0;
}
