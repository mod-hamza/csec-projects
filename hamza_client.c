/*
 * hamza_client.c — RFMP C client skeleton
 * Spring 2026
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <ip> <port> <filename>\n", argv[0]);
        return 1;
    }
    printf("C RFMP client starting...\n");
    return 0;
}
