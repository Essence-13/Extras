#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include <sys/socket.h> 

#define SIZE 1024

void send_file(FILE *fp, int sockfd){
    char data[SIZE] = {0};

    while(fgets(data, SIZE, fp) != NULL) {
 
        if (send(sockfd, data, strlen(data), 0) == -1) {
            perror("[-]Error in sending file.");
            exit(1);
        }
        bzero(data, SIZE);
    }
}

int main(){
    char *ip = "10.0.2.7"; 
    int port = 8080;
    int e;
    char buffer[SIZE];
    int sockfd;
    struct sockaddr_in server_addr;
    FILE *fp;
    char *filename = "send.txt"; // Make sure this file exists!

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {
        perror("[-]Error in socket");
        exit(1);
    }
    printf("[+]Server socket created successfully.\n");

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = port;
    server_addr.sin_addr.s_addr = inet_addr(ip);

    e = connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if(e == -1) {
        perror("[-]Error in socket");
        exit(1);
    }
    printf("[+]Connected to Server.\n");

    fp = fopen(filename, "r");
    if (fp == NULL) {
        perror("[-]Error in reading file.");
        exit(1);
    }

    send_file(fp, sockfd);
    printf("[+]File data sent successfully.\n");

 
    shutdown(sockfd, SHUT_WR);


    printf("[+]Waiting for server response...\n");
    int n = recv(sockfd, buffer, SIZE, 0);
    
    if (n <= 0){
        printf("[-]Failed to receive response from Server (or server closed).\n");
    } else {

        buffer[n] = '\0'; 
        printf("[+]Server says: %s\n", buffer);
    }
    

    close(sockfd);
    fclose(fp);

    return 0;
}
