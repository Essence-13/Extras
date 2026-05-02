#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>

#define SIZE 1024
#define PORT_CHAT 8080
#define PORT_FILE 8081
#define SERVER_IP "10.0.2.7" // CHANGE THIS TO YOUR SERVER IP

void send_file_func(char *filename) {
    int sock_file;
    struct sockaddr_in addr;
    int fd;
    char buffer[SIZE];
    int n;

    sock_file = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT_FILE);
    addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(sock_file, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("[-] File connection failed.\n");
        return;
    }

    filename[strcspn(filename, "\n")] = 0; 
    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        printf("[-] Could not open file: %s\n", filename);
        close(sock_file);
        return;
    }

    printf("[+] Uploading file: %s ...\n", filename);
    while ((n = read(fd, buffer, SIZE)) > 0) {
        send(sock_file, buffer, n, 0);
    }
    printf("[+] File sent successfully.\n");
    close(fd);
    close(sock_file);
}

int main() {
    int sock_chat;
    struct sockaddr_in addr;
    char buffer[SIZE];

    sock_chat = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT_CHAT);
    addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(sock_chat, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("[-] Chat connection failed");
        exit(1);
    }

    printf("[+] Connected to Chat Server.\n");
    printf("commands:\n  Type text to chat.\n  Type 'sendfile <filename>' to send a file.\n");
    printf("You> ");
    fflush(stdout);

    // FORK: Split into Listener and Typer
    pid_t pid = fork();

    if (pid == 0) {
        // --- CHILD: RECEIVER (Listens for Server) ---
        while (1) {
            bzero(buffer, SIZE);
            int n = recv(sock_chat, buffer, SIZE, 0);
            if (n <= 0) {
                printf("\n[-] Server disconnected.\n");
                kill(getppid(), SIGKILL); // Kill parent
                exit(0);
            }
            buffer[strcspn(buffer, "\n")] = 0;
            printf("\n[Server]: %s\nYou> ", buffer);
            fflush(stdout);
        }
    } else {
        // --- PARENT: SENDER (Reads Keyboard) ---
        while (1) {
            bzero(buffer, SIZE);
            fgets(buffer, SIZE, stdin);

            if (strncmp(buffer, "sendfile", 8) == 0) {
                char *filename = buffer + 9;
                send_file_func(filename);
                printf("You> "); // Reprints prompt after file transfer
            } else {
                send(sock_chat, buffer, strlen(buffer), 0);
                printf("You> ");
            }
        }
    }

    close(sock_chat);
    return 0;
}
