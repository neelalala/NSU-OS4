#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <poll.h>

#define PORT 6666
#define ADDRESS "127.0.0.1"
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 128

int main() {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    int addr_len = sizeof(client_addr);

    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket creation failed");
        exit(1);
    }

    struct pollfd fds[MAX_CLIENTS + 1];
    int nfds = 1;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ADDRESS);
    server_addr.sin_port = htons(PORT);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(2);
    }

    if (listen(server_sock, 5) < 0) {
        perror("listen failed");
        exit(3);
    }

    fds[0].fd = server_sock;
    fds[0].events = POLLIN;

    printf("TCP Echo Server listening on port %d\n", PORT);

    char buffer[BUFFER_SIZE];

    while (1) {
        if(poll(fds, nfds, -1) < 0) {
            perror("poll failed");
            continue;
        }
        for (int i = 0; i < nfds; i++) {
            if (fds[i].revents & POLLIN) {
                if (i == 0) {
                    client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);
                    if (client_sock < 0) {
                        perror("accept failed");
                        continue;
                    }

                    if (nfds < MAX_CLIENTS + 1) {
                        fds[nfds].fd = client_sock;
                        fds[nfds].events = POLLIN;
                        nfds++;
                        printf("New connection accepted, client fd: %d\n", client_sock);
                    } else {
                        printf("Too many clients\n");
                        close(client_sock);
                    }
                } else {
                    int n = read(fds[i].fd, buffer, BUFFER_SIZE - 1);
                    if (n > 0) {
                        buffer[n] = '\0';
                        printf("Received from client (fd %d): %s\n", fds[i].fd, buffer);
                        write(fds[i].fd, buffer, n);
                        printf("Sent back to client (fd %d): %s\n", fds[i].fd, buffer);
                    } else if (n == 0) {
                        printf("Client disconnected (fd %d)\n", fds[i].fd);
                        close(fds[i].fd);
                        fds[i].fd = -1;
                    } else {
                        perror("read failed");
                        close(fds[i].fd);
                        fds[i].fd = -1;
                    }
                }
            }
        }

        int new_nfds = 1;
        for (int i = 1; i < nfds; i++) {
            if (fds[i].fd != -1) {
                fds[new_nfds] = fds[i];
                new_nfds++;
            }
        }
        nfds = new_nfds;
    }
}


