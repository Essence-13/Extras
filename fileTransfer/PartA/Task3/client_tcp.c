#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h> 

#define SIZE 100

void send_file(int fd, int sockfd){
    char data[SIZE];
    char recv_buffer[200]; 
    int n;

    while((n = read(fd, data, SIZE)) > 0) {
 
        if (send(sockfd, data, n, 0) == -1) {
            perror("[-]Error in sending file.");
            exit(1);
        }

        int bytes_recvd = recv(sockfd, recv_buffer, sizeof(recv_buffer)-1, 0);
        if (bytes_recvd > 0) {
            recv_buffer[bytes_recvd] = '\0';
            printf("Server says: %s\n", recv_buffer);
        } else {
            printf("[-]Server disconnected during transfer.\n");
            exit(1);
        }
        
        bzero(data, SIZE);
    }
}

int main(){
    char *ip = "10.0.2.7"; 
    int port = 8080;
    int e;
    char buffer[200];
    int sockfd;
    struct sockaddr_in server_addr;
    int fd; 
    char *filename = "send.txt"; 

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

    
    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror("[-]Error in reading file.");
        exit(1);
    }

    send_file(fd, sockfd);
    printf("[+]File data sent successfully.\n");

    shutdown(sockfd, SHUT_WR);


    printf("[+]Waiting for final server stats...\n");
    int n = recv(sockfd, buffer, sizeof(buffer)-1, 0);
    
    if (n <= 0){
        printf("[-]Failed to receive final response.\n");
    } else {
        buffer[n] = '\0'; 
        printf("[+]Server Final Report: %s\n", buffer);
    }
    
    close(sockfd);
    close(fd); 

    return 0;
}
