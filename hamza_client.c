/*
 * hamza_client.c — connect + SS/CC handshake
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUF 4096

void send_pkt(int sock, const char *msg) {
    char buf[BUF];
    snprintf(buf, sizeof(buf), "%s\n", msg);
    send(sock, buf, strlen(buf), 0);
}

int recv_pkt(int sock, char *buf, int maxlen) {
    int n = 0; char c;
    while (n < maxlen-1) {
        if (recv(sock,&c,1,0) <= 0) return -1;
        buf[n++] = c;
        if (c == '\n') break;
    }
    buf[n] = '\0';
    if (n > 0 && buf[n-1] == '\n') buf[--n] = '\0';
    return n;
}

int main(int argc, char *argv[]) {
    if (argc < 4) { fprintf(stderr,"usage: %s <ip> <port> <file>\n",argv[0]); return 1; }
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr; memset(&addr,0,sizeof(addr));
    addr.sin_family=AF_INET; addr.sin_port=htons(atoi(argv[2]));
    inet_pton(AF_INET, argv[1], &addr.sin_addr);
    if (connect(sock,(struct sockaddr*)&addr,sizeof(addr))<0) { perror("connect"); return 1; }
    printf("connected\n");
    char buf[BUF];
    send_pkt(sock, "SS|RFMP|v1.0|0");
    recv_pkt(sock, buf, sizeof(buf));
    printf("server: %s\n", buf);
    close(sock);
    return 0;
}
