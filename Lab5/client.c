#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define SIZE 1024
#define PORT_CHAT 8080
#define PORT_FILE 8081
#define DNS_PORT 6000
#define DNS_SERVER_IP "10.0.2.7" 

EVP_PKEY *receiver_pub_key = NULL;
EVP_PKEY *priv_key = NULL;

EVP_PKEY* setup_identity(const char* my_hostname) {
    // 1. Generate local RSA key pair
    EVP_PKEY *my_keys = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) return NULL;
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) return NULL;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) return NULL;
    if (EVP_PKEY_keygen(ctx, &my_keys) <= 0) return NULL;
    EVP_PKEY_CTX_free(ctx);

    // 2. Extract Public Key to PEM string
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, my_keys);
    char *pub_pem;
    long pub_len = BIO_get_mem_data(bio, &pub_pem);

    // 3. Connect to Key Server (Port 7000)
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in ks_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(7000),
        .sin_addr.s_addr = inet_addr(DNS_SERVER_IP)
    };

    if (connect(sock, (struct sockaddr*)&ks_addr, sizeof(ks_addr)) == 0) {
        char reg_packet[4096];
        // Format: REG:hostname:PEM_DATA
        snprintf(reg_packet, sizeof(reg_packet), "REG:%s:%s", my_hostname, pub_pem);
        send(sock, reg_packet, strlen(reg_packet), 0);
        printf("[+] Registered %s with Key Server\n", my_hostname);
    } else {
        perror("[-] Failed to connect to Key Server for registration");
    }

    close(sock);
    BIO_free(bio);
    return my_keys; // This is your local private key for decryption
}

EVP_PKEY* retrieve_public_key(const char* hostname) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in key_server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(7000) // The Key Server Port
    };
    key_server_addr.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);

    if (connect(sock, (struct sockaddr*)&key_server_addr, sizeof(key_server_addr)) < 0) {
        perror("[-] Key Server connection failed");
        return NULL;
    }

    // Request the key for the specific hostname
    send(sock, hostname, strlen(hostname), 0);

    char buffer[2048];
    int n = recv(sock, buffer, 2048, 0);
    close(sock);

    if (n <= 0 || strncmp(buffer, "NOT_FOUND", 9) == 0) {
        printf("[-] Public key not found for %s\n", hostname);
        return NULL;
    }

    // Convert the received PEM string into an EVP_PKEY object
    BIO *bio = BIO_new_mem_buf(buffer, n);
    EVP_PKEY *pub_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!pub_key) {
        printf("[-] Failed to parse Public Key\n");
    } else {
        printf("[+] Successfully retrieved Public Key for %s\n", hostname);
    }

    return pub_key;
}

int rsa_encrypt(unsigned char *plaintext, int len, unsigned char *ciphertext, EVP_PKEY *pub_key) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub_key, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_encrypt_init(ctx) <= 0) return -1;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) return -1;

    size_t outlen;
    // Determine the buffer size needed
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, plaintext, len) <= 0) return -1;
    
    // Perform actual encryption
    if (EVP_PKEY_encrypt(ctx, ciphertext, &outlen, plaintext, len) <= 0) return -1;

    EVP_PKEY_CTX_free(ctx);
    return (int)outlen;
}

int rsa_decrypt(unsigned char *ciphertext, int len, unsigned char *plaintext, EVP_PKEY *priv_key) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_decrypt_init(ctx) <= 0) return -1;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) return -1;

    size_t outlen;
    // Determine the buffer size needed for plaintext
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, ciphertext, len) <= 0) return -1;

    // Perform actual decryption
    if (EVP_PKEY_decrypt(ctx, plaintext, &outlen, ciphertext, len) <= 0) return -1;

    EVP_PKEY_CTX_free(ctx);
    return (int)outlen;
}

void send_file_func(char *filename) {
    int sock_file = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(PORT_FILE) };
    addr.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);
    if (connect(sock_file, (struct sockaddr*)&addr, sizeof(addr)) < 0) return;

    int fd = open(filename, O_RDONLY);
    if (fd < 0) { printf("[-] File not found\n"); close(sock_file); return; }

    unsigned char buffer[214], cipher[256];
    int n;
    while ((n = read(fd, buffer, 214)) > 0) {
        int c_len = rsa_encrypt(buffer, n, cipher, receiver_pub_key);
        if(c_len > 0){
        send(sock_file, &c_len, sizeof(int), 0); // Send size
        send(sock_file, cipher, c_len, 0);        // Send data
        }
    }
    int stop = 0;
    send(sock_file, &stop, sizeof(int), 0);
    close(fd); close(sock_file);
    printf("[+] File sent securely!\n");
}

int main() {
    
        priv_key = setup_identity("client.com");
    if (!priv_key) exit(1);
    
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

	receiver_pub_key = retrieve_public_key(target_domain);
if (!receiver_pub_key) {
    printf("Cannot proceed without public key. Exiting.\n");
    return 1;
}


    int sock_chat = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(PORT_CHAT) };
    addr.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);
    if (connect(sock_chat, (struct sockaddr*)&addr, sizeof(addr)) < 0) exit(1);

    if (fork() == 0) { // Receiver
        while (1) {
            unsigned char enc[SIZE + 32], dec[SIZE + 32];
            int n = recv(sock_chat, enc, SIZE, 0);
            if (n <= 0) exit(0);
            int d_len = rsa_decrypt(enc, n, dec, priv_key);
            dec[d_len] = '\0';
            printf("\n[Server]: %s\nYou> ", dec);
            fflush(stdout);
        }
    } else { // Sender
        while (1) {
            char input[SIZE];
            printf("You> ");
            fgets(input, SIZE, stdin);
            input[strcspn(input, "\n")] = 0;
            if (strlen(input) == 0) continue;
            if (strncmp(input, "sendfile", 8) == 0) {
                char *fname = input + 9;
                fname[strcspn(fname, "\n")] = 0;
                send_file_func(fname);
            } else {
                unsigned char cipher[512]; // RSA 2048 output is 256 bytes
int c_len = rsa_encrypt((unsigned char*)input, strlen(input), cipher, receiver_pub_key);
send(sock_chat, cipher, c_len, 0);
            }
        }
    }
    return 0;
}
