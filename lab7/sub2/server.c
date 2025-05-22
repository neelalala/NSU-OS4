#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>

#define PORT 6666
#define ADDRESS "127.0.0.1"
#define BUFFER_SIZE 1024

void handle_client(int client_sock) {
    char buffer[BUFFER_SIZE];
    int n;

    while ((n = read(client_sock, buffer, BUFFER_SIZE - 1)) > 0) {
        buffer[n] = '\0';
        printf("(pid: %d) Received from client: %s\n", getpid(), buffer);
        write(client_sock, buffer, n);
        printf("(pid: %d) Sent back to client: %s\n", getpid(), buffer);
    }

    if (n == 0) {
        printf("Client disconnected\n");
    } else {
        perror("read failed");
    }
    close(client_sock);
}

int main() {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    int addr_len = sizeof(client_addr);

    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket creation failed");
        exit(1);
    }

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

    printf("TCP Echo Server listening on port %d\n", PORT);

    while (1) {
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0) {
            perror("accept failed");
            continue;
        }

        int pid = fork();
        if (pid == 0) {
            close(server_sock);
            handle_client(client_sock);
            exit(0);
        } else if (pid > 0) {
            close(client_sock);
            while (waitpid(-1, NULL, WNOHANG) > 0);
        } else {
            perror("fork failed");
        }
    }

    close(server_sock);
    return 0;
}
