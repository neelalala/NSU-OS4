#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 6666
#define ADDRESS "127.0.0.1"
#define BUFFER_SIZE 1024

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    char message[BUFFER_SIZE];
    char buffer[BUFFER_SIZE];

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket creation failed");
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ADDRESS);
    server_addr.sin_port = htons(PORT);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect failed");
        exit(2);
    }

    fgets(message, BUFFER_SIZE - 1, stdin);

    while(message[0] != '\0') {
	int len = strlen(message);
        write(sockfd, message, len);

	int n = read(sockfd, buffer, BUFFER_SIZE - 1);
	
	if (n > 0) {
	    buffer[n] = '\0';
	    printf(buffer);
	} else if (n == 0) {
	    printf("Server closed connection\n");
	} else {
	    perror("read failed");
	    break;
	}

	fgets(message, BUFFER_SIZE - 1, stdin);
    }

    close(sockfd);
    return 0;
}
