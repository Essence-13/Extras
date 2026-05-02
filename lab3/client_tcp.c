#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX 80
#define TCP_PORT 8080       // Port for Generic Server
#define DNS_PORT 6000       // Port for DNS Server
#define DNS_SERVER_IP "10.0.2.7" // IP of VM 2 (Where DNS is running)

void func(int sockfd) {
    char buff[MAX];
    int n;
    for (;;) {
        bzero(buff, sizeof(buff));
        printf("Enter string to send to Generic Server: ");
        n = 0;
        while ((buff[n++] = getchar()) != '\n');
        
        write(sockfd, buff, sizeof(buff));
        bzero(buff, sizeof(buff));
        read(sockfd, buff, sizeof(buff));
        printf("From Server: %s", buff);
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

    printf("Enter domain to resolve (e.g., www.abc.com): ");
    scanf("%s", target_domain);
    getchar(); // Consume newline left by scanf

    // Create UDP Socket
    if ((dns_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("DNS socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&dns_addr, 0, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(DNS_PORT);
    dns_addr.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);

    printf("[Client] Sending DNS query for %s...\n", target_domain);
    sendto(dns_sockfd, target_domain, strlen(target_domain), 0, (const struct sockaddr *)&dns_addr, sizeof(dns_addr));

    // Receive IP
    int n = recvfrom(dns_sockfd, (char *)dns_buffer, 1024, 0, (struct sockaddr *)&dns_addr, &addr_len);
    dns_buffer[n] = '\0';
    close(dns_sockfd);

    printf("[Client] DNS Resolved IP: %s\n", dns_buffer);

    if (strcmp(dns_buffer, "0.0.0.0") == 0) {
        printf("Domain not found. Exiting.\n");
        return 0;
    }

    // --- STEP 2: PING (System Call) ---
    char ping_cmd[1100];
    sprintf(ping_cmd, "ping -c 3 %s", dns_buffer); // Use "-c 3" for Linux, remove "-c 3" if Windows
    printf("\n[Client] Pinging Server...\n");
    system(ping_cmd);

    // --- STEP 3: CONNECT TO GENERIC SERVER (TCP) ---
    int sockfd;
    struct sockaddr_in servaddr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("TCP socket creation failed...\n");
        exit(0);
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(dns_buffer); // Use the IP we got from DNS!
    servaddr.sin_port = htons(TCP_PORT);

    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0) {
        printf("Connection to Generic Server failed...\n");
        exit(0);
    } else {
        printf("\n[Client] Connected to Generic Server at %s..\n", dns_buffer);
    }

    func(sockfd); // Start Chat
    close(sockfd);
}
