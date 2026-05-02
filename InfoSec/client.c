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
#include <sys/socket.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/rand.h>

#define SIZE 1024
#define PORT_CHAT 8080
#define PORT_FILE 8081
#define DNS_PORT 6000
#define DNS_SERVER_IP "10.0.2.7" 

// ==============================================================================
// GLOBAL SESSION SECURITY CONTEXT
// ==============================================================================
// These hold the ephemeral AES-256 key and IV derived from the PFS handshake.
// They are populated ONLY after the Ephemeral RSA exchange succeeds.
unsigned char session_aes_key[32]; // 256-bit Key
unsigned char session_aes_iv[16];  // 128-bit Initialization Vector
int session_active = 0;            // Flag to ensure we don't encrypt before handshake


// Helper to sign a buffer of data using your Long-Term Private Key
int sign_data(const unsigned char *data, size_t data_len, unsigned char *sig, size_t *sig_len, EVP_PKEY *long_term_priv) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) return 0;
    
    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, long_term_priv) <= 0 ||
        EVP_DigestSignUpdate(md_ctx, data, data_len) <= 0 ||
        EVP_DigestSignFinal(md_ctx, sig, sig_len) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }
    EVP_MD_CTX_free(md_ctx);
    return 1;
}

// Helper to verify a signature using the Peer's Long-Term Public Key (from their certificate)
int verify_signature(const unsigned char *data, size_t data_len, const unsigned char *sig, size_t sig_len, EVP_PKEY *peer_long_term_pub) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) return 0;

    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, peer_long_term_pub) <= 0 ||
        EVP_DigestVerifyUpdate(md_ctx, data, data_len) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }
    
    int result = EVP_DigestVerifyFinal(md_ctx, sig, sig_len);
    EVP_MD_CTX_free(md_ctx);
    return result == 1; // Returns 1 on success, 0 on failure
}

// Global variables to hold cryptographic keys during the chat session
EVP_PKEY *receiver_pub_key = NULL; // The validated public key of the peer we are chatting with
EVP_PKEY *priv_key = NULL;         // Our own private key to decrypt incoming messages

/**
 * ==============================================================================
 * setup_csr()
 * ==============================================================================
 * Bootstraps the client's cryptographic identity.
 * 1. Generates a fresh 2048-bit RSA key pair.
 * 2. Formats a Certificate Signing Request (CSR).
 * 3. Connects to the central Certificate Authority (CA) to get it signed.
 * 4. Saves the resulting certificate, the Root CA certificate, and the private key.
 */
EVP_PKEY* setup_csr() {
    printf("[Init] Generating local RSA key pair...\n");
    
    // 1. Initialize and generate the RSA private/public key pair
    EVP_PKEY *my_keys = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 || EVP_PKEY_keygen(ctx, &my_keys) <= 0) {
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);

    // 2. Create the Certificate Signing Request (X.509 format)
    X509_REQ *req = X509_REQ_new();
    X509_REQ_set_version(req, 0);
    X509_REQ_set_pubkey(req, my_keys);
    
    // Define who we are (Subject Name)
    X509_NAME *name = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"ChatClient", -1, -1, 0);
    
    // Cryptographically sign the request to prove ownership of the public key
    X509_REQ_sign(req, my_keys, EVP_sha256());

    // Write the CSR to an in-memory string for transmission
    BIO *csr_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_REQ(csr_bio, req);
    char *csr_pem = NULL;
    long csr_len = BIO_get_mem_data(csr_bio, &csr_pem);

    // 3. Connect to the Central Certificate Authority (CA)
    printf("[Init] Connecting to CA at %s:7000...\n", DNS_SERVER_IP);
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in ks_addr = { .sin_family = AF_INET, .sin_port = htons(7000), .sin_addr.s_addr = inet_addr(DNS_SERVER_IP) };
    if (connect(sock, (struct sockaddr*)&ks_addr, sizeof(ks_addr)) < 0) return NULL;

    // Send the CSR to the CA
    send(sock, csr_pem, csr_len, 0);
    printf("[Init] CSR sent. Waiting for signed certificates...\n");

    // Receive the combined CA response
    char recv_buffer[8192];
    int total_received = 0, bytes_read;
    while ((bytes_read = recv(sock, recv_buffer + total_received, sizeof(recv_buffer) - total_received - 1, 0)) > 0) {
        total_received += bytes_read;
    }
    recv_buffer[total_received] = '\0';
    close(sock);

    // 4. Parse the CA's response and save the files locally
    if (total_received > 0) {
        char *delimiter = "\n---END_OF_CLIENT_CERT---\n";
        char *split_point = strstr(recv_buffer, delimiter);
        
        if (split_point != NULL) {
            *split_point = '\0'; // Split the string at the delimiter
            
            // Save our newly signed certificate and the Root CA certificate
            FILE *f_cert = fopen("client.crt", "w"); 
            if (f_cert) { fputs(recv_buffer, f_cert); fclose(f_cert); }
            
            FILE *f_ca = fopen("ca.crt", "w"); 
            if (f_ca) { fputs(split_point + strlen(delimiter), f_ca); fclose(f_ca); }
            
            printf("[Init] Successfully received and saved certificates.\n");
        }
    }
    
    // Save the private key to disk
    FILE *f_key = fopen("client.key", "w"); 
    if (f_key) { PEM_write_PrivateKey(f_key, my_keys, NULL, NULL, 0, NULL, NULL); fclose(f_key); }
    
    X509_REQ_free(req); 
    BIO_free(csr_bio);
    return my_keys; 
}

/**
 * ==============================================================================
 * perform_secure_handshake()
 * ==============================================================================
 * Custom Mutual Authentication Protocol (replaces standard TLS).
 * 1. Sends local certificate to the peer.
 * 2. Receives peer's certificate.
 * 3. Verifies peer's certificate against the trusted Root CA.
 * 4. Extracts and returns the peer's public key for encrypted communication.
 */
EVP_PKEY* perform_secure_handshake(int sock) {
    printf("[Handshake] Starting mutual certificate exchange...\n");
    
    // --- Phase 1: Send Local Certificate ---
    FILE *f_cert = fopen("client.crt", "r");
    if (!f_cert) return NULL;
    
    fseek(f_cert, 0, SEEK_END); 
    long my_cert_len = ftell(f_cert); 
    fseek(f_cert, 0, SEEK_SET);
    char *my_cert_pem = (char *)malloc(my_cert_len + 1);
    fread(my_cert_pem, 1, my_cert_len, f_cert); 
    my_cert_pem[my_cert_len] = '\0'; 
    fclose(f_cert);

    printf("[Handshake] Sending local certificate...\n");
    uint32_t net_len = htonl((uint32_t)my_cert_len);
    send(sock, &net_len, sizeof(net_len), 0);
    send(sock, my_cert_pem, my_cert_len, 0); 
    free(my_cert_pem);

    // --- Phase 2: Receive Peer Certificate ---
    printf("[Handshake] Waiting for peer certificate...\n");
    uint32_t peer_net_len;
    if (recv(sock, &peer_net_len, sizeof(peer_net_len), MSG_WAITALL) <= 0) return NULL;
    
    long peer_cert_len = ntohl(peer_net_len);
    char *peer_cert_pem = (char *)malloc(peer_cert_len + 1);
    if (recv(sock, peer_cert_pem, peer_cert_len, MSG_WAITALL) <= 0) { free(peer_cert_pem); return NULL; }
    peer_cert_pem[peer_cert_len] = '\0';

    // --- Phase 3: Verify the Peer Certificate ---
    BIO *cert_bio = BIO_new_mem_buf(peer_cert_pem, -1);
    X509 *peer_cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    BIO_free(cert_bio); 
    free(peer_cert_pem);

    if (!peer_cert) return NULL;
    
    // Load the Root CA we trust into an OpenSSL verification store
    X509_STORE *store = X509_STORE_new();
    if (X509_STORE_load_locations(store, "ca.crt", NULL) != 1) return NULL;
    
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, peer_cert, NULL);

    // Perform the mathematical signature verification
    if (X509_verify_cert(ctx) != 1) {
        printf("[-] Handshake Verification Failed. Man-in-the-Middle detected!\n");
        return NULL;
    }
    printf("[Handshake] Peer certificate successfully verified against Root CA!\n");
    
    // --- Phase 4: Extract Public Key ---
    EVP_PKEY *peer_pub_key = X509_get_pubkey(peer_cert);
    
    X509_STORE_CTX_free(ctx); 
    X509_STORE_free(store); 
    X509_free(peer_cert);
    
    return peer_pub_key;
}


/**
 * ==============================================================================
 * aes_encrypt()
 * ==============================================================================
 * Encrypts data using AES-256-CBC with the global session key and IV.
 * Returns: The length of the ciphertext, or -1 on error.
 */
int aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext) {
    if (!session_active) return -1; // Safety check

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    if (!ctx) return -1;

    // Initialize encryption with our global PFS-derived keys
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, session_aes_key, session_aes_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Provide the message to be encrypted, and obtain the encrypted output.
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    // Finalize the encryption. Further ciphertext bytes may be written at this stage.
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

/**
 * ==============================================================================
 * aes_decrypt()
 * ==============================================================================
 * Decrypts data using AES-256-CBC with the global session key and IV.
 * Returns: The length of the plaintext, or -1 on error.
 */
int aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext) {
    if (!session_active) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    if (!ctx) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, session_aes_key, session_aes_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}



/**
 * ==============================================================================
 * rsa_encrypt() & rsa_decrypt()
 * ==============================================================================
 * Wrappers for OpenSSL EVP_PKEY functions using highly secure OAEP padding.
 * Because RSA-2048 encrypts in fixed blocks, plaintext cannot exceed 214 bytes,
 * and the resulting ciphertext is always exactly 256 bytes.
 */
int rsa_encrypt(unsigned char *plaintext, int len, unsigned char *ciphertext, EVP_PKEY *pub_key) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub_key, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) return -1;
    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, plaintext, len) <= 0 || EVP_PKEY_encrypt(ctx, ciphertext, &outlen, plaintext, len) <= 0) return -1;
    EVP_PKEY_CTX_free(ctx); 
    return (int)outlen;
}

int rsa_decrypt(unsigned char *ciphertext, int len, unsigned char *plaintext, EVP_PKEY *priv_key) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) return -1;
    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, ciphertext, len) <= 0 || EVP_PKEY_decrypt(ctx, plaintext, &outlen, ciphertext, len) <= 0) return -1;
    EVP_PKEY_CTX_free(ctx); 
    return (int)outlen;
}

/**
 * ==============================================================================
 * send_file_func()
 * ==============================================================================
 * Out-of-band encrypted file transfer. Opens a new connection to the target's
 * file port, reads the local file in 214-byte chunks, RSA encrypts them, and
 * transmits them over the socket.
 */
/**
 * ==============================================================================
 * send_file_func()
 * ==============================================================================
 */
void send_file_func(char *filename, const char *target_ip) {
    if (!session_active) {
        printf("[-] Cannot send file: Secure chat session not established yet.\n");
        return;
    }

    int sock_file = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(PORT_FILE) };
    addr.sin_addr.s_addr = inet_addr(target_ip); 
    
    if (connect(sock_file, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("[-] File socket connection failed"); return;
    }

    int fd = open(filename, O_RDONLY);
    if (fd < 0) { 
        printf("[-] File not found locally: %s\n", filename); 
        close(sock_file); return; 
    }

    printf("[FILE] Securing file channel and transmitting %s...\n", filename);

    // 1. SECURE BOOTSTRAP: Send the current AES session keys to the file port
    // Encrypt the 48-byte AES context using the Server's RSA Public Key
    unsigned char key_payload[48];
    memcpy(key_payload, session_aes_key, 32);
    memcpy(key_payload + 32, session_aes_iv, 16);
    
    unsigned char enc_key_payload[256];
    rsa_encrypt(key_payload, 48, enc_key_payload, receiver_pub_key);
    send(sock_file, enc_key_payload, 256, 0);

    // 2. TRANSMIT FILE: Now safely use AES-256 for rapid file transfer
    unsigned char buffer[1024], cipher[2048];
    int n;
    
    while ((n = read(fd, buffer, 1024)) > 0) {
        int c_len = aes_encrypt(buffer, n, cipher);
        if (c_len > 0) {
            int net_len = htonl(c_len);
            send(sock_file, &net_len, sizeof(int), 0);
            send(sock_file, cipher, c_len, 0);
        }
    }
    
    // Send 0 to indicate end of file transfer
    int stop = 0; 
    send(sock_file, &stop, sizeof(int), 0);
    
    close(fd); 
    close(sock_file);
    printf("[+] File sent securely!\n");
}

/**
 * ==============================================================================
 * main()
 * ==============================================================================
 * Entry point. Initializes identity, queries the custom DNS server, establishes
 * the peer connection, and forks into concurrent send/receive loops.
 */
int main() {
    printf("--- Starting Secure Chat Client ---\n");
    
    // 1. Fetch certificates from CA
    priv_key = setup_csr();
    if (!priv_key) exit(1);
    
    // 2. Query Custom DNS for Peer IP
    int dns_sockfd;
    struct sockaddr_in dns_addr;
    char target_domain[100];
    char target_ip[100];
    socklen_t addr_len = sizeof(dns_addr);
    
    printf("Enter domain to resolve (e.g., server.com): ");
    scanf("%s", target_domain); 
    getchar(); // Consume the trailing newline
    
    if ((dns_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) exit(1);
    memset(&dns_addr, 0, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET; 
    dns_addr.sin_port = htons(DNS_PORT); 
    dns_addr.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);

    printf("[Client] Sending UDP DNS query for %s...\n", target_domain);
    sendto(dns_sockfd, target_domain, strlen(target_domain), 0, (const struct sockaddr *)&dns_addr, sizeof(dns_addr));

    int n = recvfrom(dns_sockfd, target_ip, 1024, 0, (struct sockaddr *)&dns_addr, &addr_len);
    target_ip[n] = '\0'; 
    close(dns_sockfd);

    if (strcmp(target_ip, "0.0.0.0") == 0) { 
        printf("[-] Domain not found in DNS registry.\n"); 
        return 0; 
    }
    
    // Verify reachability
    char ping_cmd[1100]; 
    sprintf(ping_cmd, "ping -c 1 %s", target_ip); 
    system(ping_cmd);

    // 3. Connect to the Peer's Chat Port
    int sock_chat = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(PORT_CHAT) };
    addr.sin_addr.s_addr = inet_addr(target_ip); 
    
    printf("\n[Client] Connecting to peer chat port at %s...\n", target_ip);
    if (connect(sock_chat, (struct sockaddr*)&addr, sizeof(addr)) < 0) { 
        perror("[-] Chat connection failed"); 
        exit(1); 
    }

    // 4. Perform Mutual TLS-style Handshake
    receiver_pub_key = perform_secure_handshake(sock_chat);
    if (!receiver_pub_key) { 
        printf("[-] Handshake failed.\n"); 
        close(sock_chat); 
        return 1; 
    }
    printf("[+] Mutual handshake successful. Secure channel open.\n");

// ... inside main(), after perform_secure_handshake() succeeds ...
    printf("[PFS Handshake] Generating Ephemeral RSA Key...\n");

    // 1. Generate Temporary RSA Key
    EVP_PKEY *temp_rsa_key = NULL;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048);
    EVP_PKEY_keygen(kctx, &temp_rsa_key);
    EVP_PKEY_CTX_free(kctx);

    // 2. Serialize Temporary Public Key to bytes (so we can send it)
    unsigned char *temp_pub_bytes = NULL;
    int temp_pub_len = i2d_PUBKEY(temp_rsa_key, &temp_pub_bytes);

    // 3. Sign the serialized Public Key with our Long-Term Private Key
    unsigned char signature[256]; // 2048-bit RSA signature is 256 bytes
    size_t sig_len = sizeof(signature);
    sign_data(temp_pub_bytes, temp_pub_len, signature, &sig_len, priv_key);

    // 4. Transmit to Server
    uint32_t net_pub_len = htonl(temp_pub_len);
    uint32_t net_sig_len = htonl(sig_len);
    
    send(sock_chat, &net_pub_len, sizeof(uint32_t), 0);
    send(sock_chat, temp_pub_bytes, temp_pub_len, 0);
    send(sock_chat, &net_sig_len, sizeof(uint32_t), 0);
    send(sock_chat, signature, sig_len, 0);

    // 5. Wait for Server to reply with the AES Session Key
    unsigned char enc_aes_payload[256];
    recv(sock_chat, enc_aes_payload, 256, MSG_WAITALL);

    // 6. Decrypt AES Key using our TEMPORARY Private Key
    unsigned char aes_payload[48]; // 32 bytes for Key + 16 bytes for IV
    rsa_decrypt(enc_aes_payload, 256, aes_payload, temp_rsa_key);
    
    memcpy(session_aes_key, aes_payload, 32);
    memcpy(session_aes_iv, aes_payload + 32, 16);

    // 7. ACHIEVE PFS: Destroy the temporary private key from memory immediately
    EVP_PKEY_free(temp_rsa_key);
    OPENSSL_free(temp_pub_bytes);
    
    printf("[+] Perfect Forward Secrecy established. AES Session Active.\n");

// ... (decryption of aes_payload using temp_rsa_key happens here) ...

    // COPY the raw bytes into our global security context
    memcpy(session_aes_key, aes_payload, 32);      // First 32 bytes = Key
    memcpy(session_aes_iv, aes_payload + 32, 16);  // Next 16 bytes = IV
    session_active = 1;                            // Enable the encryption wrappers
    
    // Securely wipe the temporary buffer
    memset(aes_payload, 0, 48);
    
    
    // 5. Split execution into two concurrent loops for async chat
    if (fork() == 0) { 
        // --- CHILD PROCESS: Receiver Loop ---
// --- CHILD PROCESS: Receiver Loop (AES Updated) ---
        while (1) {
            unsigned char enc_msg[2048]; // Buffer for ciphertext
            unsigned char dec_msg[2048]; // Buffer for plaintext
            int net_len;

            // 1. Receive the 4-byte size of the incoming AES ciphertext
            if (recv(sock_chat, &net_len, sizeof(int), MSG_WAITALL) <= 0) {
                printf("\n[!] Peer disconnected.\n");
                exit(0);
            }

            // Convert length from network byte order back to host integer
            int msg_len = ntohl(net_len); 

            // Prevent buffer overflows from maliciously large length packets
            if (msg_len <= 0 || msg_len > sizeof(enc_msg)) {
                continue; 
            }

            // 2. Receive the exact amount of AES ciphertext bytes
            int n = recv(sock_chat, enc_msg, msg_len, MSG_WAITALL);
            if (n <= 0) {
                printf("\n[!] Peer disconnected.\n");
                exit(0);
            }
            
            // 3. Decrypt using the global PFS session key/IV
            int dec_len = aes_decrypt(enc_msg, n, dec_msg);
            
            if (dec_len > 0) { 
                dec_msg[dec_len] = '\0'; // Null-terminate so it prints safely
                printf("\n[Server]: %s\nYou> ", dec_msg); 
                fflush(stdout); 
            } else {
                printf("\n[!] Decryption failed or packet tampered.\nYou> ");
                fflush(stdout);
            }
        }
    } else { 
        // --- PARENT PROCESS: Sender Loop ---
        while (1) {
            char input[SIZE];
            printf("You> "); 
            fgets(input, SIZE, stdin); 
            input[strcspn(input, "\n")] = 0; // Strip trailing newline
            
            if (strlen(input) == 0) continue;
            
            // Check if the user is invoking the file transfer command
            if (strncmp(input, "sendfile", 8) == 0) {
                // Extract the filename portion of the string
                char *fname = input + 9; 
                while(*fname == ' ') fname++; 
                
                send_file_func(fname, target_ip); 
            } else {
                // Otherwise, encrypt and send as a standard chat message
                // AES-256-CBC adds padding, so buffer must be slightly larger than input
unsigned char cipher[1024]; 
int c_len = aes_encrypt((unsigned char*)input, strlen(input), cipher);

if (c_len > 0) {
    // Send the length of the ciphertext first!
    int net_len = htonl(c_len);
    send(sock_chat, &net_len, sizeof(int), 0);
    send(sock_chat, cipher, c_len, 0);
}
            }
        }
    }
    return 0;
}
