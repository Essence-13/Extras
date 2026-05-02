#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define SIZE 1024
#define PORT_CHAT 8080
#define PORT_FILE 8081
#define DNS_PORT 6000
#define DNS_SERVER_IP "10.0.2.7" 

unsigned char aes_key[] = "01234567890123456789012345678901";
unsigned char aes_iv[]  = "0123456789012345";

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, c_len;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    c_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    c_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return c_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, p_len;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    p_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    p_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return p_len;
}

void send_file_func(char *filename) {
    int sock_file = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(PORT_FILE) };
    addr.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);
    if (connect(sock_file, (struct sockaddr*)&addr, sizeof(addr)) < 0) return;

    int fd = open(filename, O_RDONLY);
    if (fd < 0) { printf("[-] File not found\n"); close(sock_file); return; }

    unsigned char buffer[SIZE], cipher[SIZE + 32];
    int n;
    while ((n = read(fd, buffer, SIZE)) > 0) {
        int c_len = encrypt(buffer, n, cipher);
        send(sock_file, &c_len, sizeof(int), 0); // Send size
        send(sock_file, cipher, c_len, 0);        // Send data
    }
    int stop = 0;
    send(sock_file, &stop, sizeof(int), 0);
    close(fd); close(sock_file);
    printf("[+] File sent securely!\n");
}

int main() {
    
    int dns_sockfd;
    struct sockaddr_in dns_addr;
    char dns_buffer[1024];
    char target_domain[100];
    socklen_t addr_len = sizeof(dns_addr);
    
    printf("Enter domain to resolve: ");
    scanf("%s", target_domain);
    getchar();
    
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
    sprintf(ping_cmd, "ping -c 3 %s", dns_buffer); 
    printf("\n[Client] Pinging Server...\n");
    system(ping_cmd);




    int sock_chat = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(PORT_CHAT) };
    addr.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);
    if (connect(sock_chat, (struct sockaddr*)&addr, sizeof(addr)) < 0) exit(1);

    if (fork() == 0) { // Receiver
        while (1) {
            unsigned char enc[SIZE + 32], dec[SIZE + 32];
            int n = recv(sock_chat, enc, SIZE, 0);
            if (n <= 0) exit(0);
            int d_len = decrypt(enc, n, dec);
            dec[d_len] = '\0';
            printf("\n[Server]: %s\nYou> ", dec);
            fflush(stdout);
        }
    } else { // Sender
        while (1) {
            char input[SIZE];
            printf("You> ");
            fgets(input, SIZE, stdin);
            if (strncmp(input, "sendfile", 8) == 0) {
                char *fname = input + 9;
                fname[strcspn(fname, "\n")] = 0;
                send_file_func(fname);
            } else {
                unsigned char cipher[SIZE + 32];
                int c_len = encrypt((unsigned char*)input, strlen(input), cipher);
                send(sock_chat, cipher, c_len, 0);
            }
        }
    }
    return 0;
}
