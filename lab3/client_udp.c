#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX 80
#define CHAT_PORT 8080       // Port for Generic UDP Server
#define DNS_PORT 6000       // Port for DNS Server
#define DNS_SERVER_IP "10.0.2.7" 

void chat_func(int sockfd, struct sockaddr_in servaddr) {
    char buff[MAX];
    int n;
    socklen_t len = sizeof(servaddr);

    for (;;) {
        bzero(buff, sizeof(buff));
        printf("Enter string to send to Server (UDP): ");
        n = 0;
        while ((buff[n++] = getchar()) != '\n');
        buff[n-1] = '\0'; // Remove newline for cleaner communication

        // 1. Use sendto instead of write
        sendto(sockfd, buff, strlen(buff), 0, (struct sockaddr*)&servaddr, len);

        bzero(buff, sizeof(buff));
        
        // 2. Use recvfrom instead of read
        recvfrom(sockfd, buff, sizeof(buff), 0, (struct sockaddr*)&servaddr, &len);
        
        printf("From Server: %s\n", buff);

        if ((strncmp(buff, "exit", 4)) == 0) {
            printf("Client Exit...\n");
            break;
        }
    }
}

int main() {
    // --- STEP 1: DNS LOOKUP (UDP) ---
    int dns_sockfd;
    struct sockaddr_in dns_addr;
    char dns_buffer[1024];
    char target_domain[100];
    socklen_t addr_len = sizeof(dns_addr);

    printf("Enter domain to resolve: ");
    scanf("%s", target_domain);
    getchar(); 

    dns_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&dns_addr, 0, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(DNS_PORT);
    dns_addr.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);

    sendto(dns_sockfd, target_domain, strlen(target_domain), 0, (const struct sockaddr *)&dns_addr, sizeof(dns_addr));
    int n = recvfrom(dns_sockfd, dns_buffer, 1024, 0, (struct sockaddr *)&dns_addr, &addr_len);
    dns_buffer[n] = '\0';
    close(dns_sockfd);

    printf("[Client] DNS Resolved IP: %s\n", dns_buffer);

    if (strcmp(dns_buffer, "0.0.0.0") == 0) return 0;

    // --- STEP 2: CHAT SETUP (UDP) ---
    int chat_sockfd;
    struct sockaddr_in servaddr;

    // Create UDP Socket for Chat
    chat_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(CHAT_PORT);
    servaddr.sin_addr.s_addr = inet_addr(dns_buffer); // Resolved IP

    // No connect() call needed for UDP!
    printf("\n[Client] Ready to chat with %s via UDP...\n", dns_buffer);

    chat_func(chat_sockfd, servaddr); 
    close(chat_sockfd);

    return 0;
}
