/*
 * ==============================================================================
 * Secure Chat — Client/Peer
 * ==============================================================================
 * Hybrid post-quantum key exchange: ECDHE (X25519) + ML-KEM-768 (Kyber)
 * Application-layer security: AES-256-GCM (AEAD) with per-message nonces,
 * sequence numbers (anti-replay), and 16-byte authentication tags.
 * Supports BOTH connect-to-peer and listen-for-peer modes.
 *
 * Compile: gcc -o client client.c -lssl -lcrypto -loqs
 */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <oqs/oqs.h>

#define SIZE       1024
#define PORT_CHAT  8080
#define PORT_FILE  8081
#define DNS_PORT   6000
#define DNS_SERVER_IP  "172.18.15.74"

/* Identity files — different in server.c */
#define MY_CERT_FILE   "client.crt"
#define MY_KEY_FILE    "client.key"
#define MY_CN          "ChatClient"
#define PEER_LABEL     "Server"

/* GCM constants */
#define GCM_NONCE_LEN  12
#define GCM_TAG_LEN    16
#define SEQ_LEN        8
#define GCM_OVERHEAD   (SEQ_LEN + GCM_NONCE_LEN + GCM_TAG_LEN)  /* 36 bytes */

/* ===========================================================================
 * Global Session Security Context
 * =========================================================================== */
unsigned char session_aes_key[32];   /* AES-256 key (from HKDF) */
uint64_t      send_seq = 0;         /* monotonic send sequence counter */
uint64_t      recv_seq = 0;         /* expected receive sequence number */
int           session_active = 0;

EVP_PKEY *peer_pub_key = NULL;       /* peer's validated long-term RSA pub */
EVP_PKEY *priv_key     = NULL;       /* our long-term RSA private key */
char      peer_ip[100] = {0};       /* peer IP for file transfers */

/* ===========================================================================
 * Portable big-endian 64-bit helpers
 * =========================================================================== */
static void write_be64(unsigned char *buf, uint64_t v) {
    for (int i = 7; i >= 0; i--) { buf[i] = v & 0xFF; v >>= 8; }
}
static uint64_t read_be64(const unsigned char *buf) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | buf[i];
    return v;
}

/* ===========================================================================
 * RSA Signing / Verification (long-term identity keys)
 * =========================================================================== */
int sign_data(const unsigned char *data, size_t data_len,
              unsigned char *sig, size_t *sig_len, EVP_PKEY *key) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key) <= 0 ||
        EVP_DigestSignUpdate(ctx, data, data_len) <= 0 ||
        EVP_DigestSignFinal(ctx, sig, sig_len) <= 0)
        { EVP_MD_CTX_free(ctx); return 0; }
    EVP_MD_CTX_free(ctx);
    return 1;
}

int verify_signature(const unsigned char *data, size_t data_len,
                     const unsigned char *sig, size_t sig_len,
                     EVP_PKEY *key) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key) <= 0 ||
        EVP_DigestVerifyUpdate(ctx, data, data_len) <= 0)
        { EVP_MD_CTX_free(ctx); return 0; }
    int r = EVP_DigestVerifyFinal(ctx, sig, sig_len);
    EVP_MD_CTX_free(ctx);
    return r == 1;
}

/* ===========================================================================
 * HKDF-SHA256 (RFC 5869) — Extract-then-Expand
 * =========================================================================== */
int hkdf_sha256(const unsigned char *salt, size_t salt_len,
                const unsigned char *ikm,  size_t ikm_len,
                const unsigned char *info, size_t info_len,
                unsigned char *okm, size_t okm_len) {
    /* Extract: PRK = HMAC-SHA256(salt, IKM) */
    unsigned char prk[32];
    unsigned int prk_len = 32;
    HMAC(EVP_sha256(), salt, salt_len, ikm, ikm_len, prk, &prk_len);

    /* Expand */
    unsigned char prev[32];
    unsigned int prev_len = 0;
    size_t done = 0;
    unsigned char counter = 1;

    while (done < okm_len) {
        unsigned char buf[32 + 256 + 1];
        size_t blen = 0;
        if (prev_len) { memcpy(buf, prev, prev_len); blen += prev_len; }
        memcpy(buf + blen, info, info_len); blen += info_len;
        buf[blen++] = counter;

        unsigned int out = 32;
        HMAC(EVP_sha256(), prk, 32, buf, blen, prev, &out);
        prev_len = 32;

        size_t n = (okm_len - done < 32) ? okm_len - done : 32;
        memcpy(okm + done, prev, n);
        done += n;
        counter++;
    }
    OPENSSL_cleanse(prk, 32);
    return 1;
}

/* ===========================================================================
 * AES-256-GCM Authenticated Encryption
 *
 * Seal output : [8B seq_be][12B nonce][ciphertext][16B tag]
 * Open  input : same layout
 *
 * AAD = sequence number (authenticated but not encrypted)
 * Per-message random nonce prevents IV reuse.
 * Monotonic sequence counter provides anti-replay protection.
 * 16-byte GCM tag provides integrity + authenticity.
 * =========================================================================== */
int aes_gcm_seal(const unsigned char *key, uint64_t *seq,
                 const unsigned char *pt, int pt_len,
                 unsigned char *out) {
    /* 1. Write sequence number (big-endian) */
    write_be64(out, *seq);

    /* 2. Random 12-byte nonce */
    RAND_bytes(out + SEQ_LEN, GCM_NONCE_LEN);

    /* 3. Encrypt */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, out + SEQ_LEN);

    int len;
    /* AAD = seq bytes */
    EVP_EncryptUpdate(ctx, NULL, &len, out, SEQ_LEN);
    /* Ciphertext starts after seq + nonce = offset 20 */
    int ct_len;
    EVP_EncryptUpdate(ctx, out + SEQ_LEN + GCM_NONCE_LEN, &ct_len, pt, pt_len);
    EVP_EncryptFinal_ex(ctx, out + SEQ_LEN + GCM_NONCE_LEN + ct_len, &len);
    ct_len += len;
    /* 4. Append 16-byte authentication tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN,
                        out + SEQ_LEN + GCM_NONCE_LEN + ct_len);
    EVP_CIPHER_CTX_free(ctx);

    (*seq)++;
    return SEQ_LEN + GCM_NONCE_LEN + ct_len + GCM_TAG_LEN;
}

int aes_gcm_open(const unsigned char *key, uint64_t *seq,
                 const unsigned char *in, int in_len,
                 unsigned char *pt) {
    if (in_len < (int)GCM_OVERHEAD) return -1;

    /* 1. Extract & verify sequence number */
    uint64_t msg_seq = read_be64(in);
    if (msg_seq < *seq) {
        printf("\n[!] REPLAY ATTACK blocked (seq %lu < expected %lu)\n",
               (unsigned long)msg_seq, (unsigned long)*seq);
        return -1;
    }

    /* 2. Pointers into the buffer */
    const unsigned char *nonce = in + SEQ_LEN;
    int ct_len = in_len - GCM_OVERHEAD;
    const unsigned char *ct    = in + SEQ_LEN + GCM_NONCE_LEN;
    const unsigned char *tag   = ct + ct_len;

    /* 3. Decrypt + authenticate */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce);

    int len;
    EVP_DecryptUpdate(ctx, NULL, &len, in, SEQ_LEN);           /* AAD */
    int pt_len;
    EVP_DecryptUpdate(ctx, pt, &pt_len, ct, ct_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, (void*)tag);
    int ret = EVP_DecryptFinal_ex(ctx, pt + pt_len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        printf("\n[!] GCM authentication FAILED — message tampered or corrupted!\n");
        return -1;
    }
    pt_len += len;
    *seq = msg_seq + 1;
    return pt_len;
}

/* ===========================================================================
 * RSA-OAEP Encrypt / Decrypt (file transfer key bootstrap)
 * =========================================================================== */
int rsa_encrypt(unsigned char *pt, int len, unsigned char *ct, EVP_PKEY *pub) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) return -1;
    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, pt, len) <= 0 ||
        EVP_PKEY_encrypt(ctx, ct, &outlen, pt, len) <= 0) return -1;
    EVP_PKEY_CTX_free(ctx);
    return (int)outlen;
}

int rsa_decrypt(unsigned char *ct, int len, unsigned char *pt, EVP_PKEY *key) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) return -1;
    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, ct, len) <= 0 ||
        EVP_PKEY_decrypt(ctx, pt, &outlen, ct, len) <= 0) return -1;
    EVP_PKEY_CTX_free(ctx);
    return (int)outlen;
}

/* ===========================================================================
 * setup_csr() — Bootstrap identity via CA
 * =========================================================================== */
EVP_PKEY* setup_csr(void) {
    printf("[Init] Generating RSA-2048 key pair...\n");
    EVP_PKEY *keys = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, &keys) <= 0) return NULL;
    EVP_PKEY_CTX_free(ctx);

    X509_REQ *req = X509_REQ_new();
    X509_REQ_set_version(req, 0);
    X509_REQ_set_pubkey(req, keys);
    X509_NAME *name = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char*)MY_CN, -1, -1, 0);
    X509_REQ_sign(req, keys, EVP_sha256());

    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_REQ(bio, req);
    char *pem = NULL;
    long pem_len = BIO_get_mem_data(bio, &pem);

    printf("[Init] Connecting to CA at %s:7000...\n", DNS_SERVER_IP);
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in ca = { .sin_family = AF_INET, .sin_port = htons(7000),
                              .sin_addr.s_addr = inet_addr(DNS_SERVER_IP) };
    if (connect(sock, (struct sockaddr*)&ca, sizeof(ca)) < 0) return NULL;
    send(sock, pem, pem_len, 0);
    printf("[Init] CSR sent. Waiting for signed certificates...\n");

    char buf[8192];
    int total = 0, n;
    while ((n = recv(sock, buf + total, sizeof(buf) - total - 1, 0)) > 0) total += n;
    buf[total] = '\0';
    close(sock);

    if (total > 0) {
        char *delim = "\n---END_OF_CLIENT_CERT---\n";
        char *sp = strstr(buf, delim);
        if (sp) {
            *sp = '\0';
            FILE *f = fopen(MY_CERT_FILE, "w");
            if (f) { fputs(buf, f); fclose(f); }
            f = fopen("ca.crt", "w");
            if (f) { fputs(sp + strlen(delim), f); fclose(f); }
            printf("[Init] Certificates saved.\n");
        }
    }
    FILE *f = fopen(MY_KEY_FILE, "w");
    if (f) { PEM_write_PrivateKey(f, keys, NULL, NULL, 0, NULL, NULL); fclose(f); }

    X509_REQ_free(req);
    BIO_free(bio);
    return keys;
}

/* ===========================================================================
 * perform_secure_handshake() — Mutual certificate authentication
 * =========================================================================== */
EVP_PKEY* perform_secure_handshake(int sock) {
    printf("[Handshake] Mutual certificate exchange...\n");

    /* Send our certificate */
    FILE *f = fopen(MY_CERT_FILE, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long clen = ftell(f); fseek(f, 0, SEEK_SET);
    char *cbuf = malloc(clen + 1);
    fread(cbuf, 1, clen, f); cbuf[clen] = '\0'; fclose(f);

    uint32_t nlen = htonl((uint32_t)clen);
    send(sock, &nlen, 4, 0);
    send(sock, cbuf, clen, 0);
    free(cbuf);

    /* Receive peer certificate */
    uint32_t pnlen;
    if (recv(sock, &pnlen, 4, MSG_WAITALL) <= 0) return NULL;
    long plen = ntohl(pnlen);
    char *pbuf = malloc(plen + 1);
    if (recv(sock, pbuf, plen, MSG_WAITALL) <= 0) { free(pbuf); return NULL; }
    pbuf[plen] = '\0';

    /* Parse and verify */
    BIO *bio = BIO_new_mem_buf(pbuf, -1);
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio); free(pbuf);
    if (!cert) return NULL;

    X509_STORE *store = X509_STORE_new();
    if (X509_STORE_load_locations(store, "ca.crt", NULL) != 1) return NULL;
    X509_STORE_CTX *vctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(vctx, store, cert, NULL);
    if (X509_verify_cert(vctx) != 1) {
        printf("[-] Certificate verification FAILED!\n");
        X509_STORE_CTX_free(vctx); X509_STORE_free(store); X509_free(cert);
        return NULL;
    }
    printf("[Handshake] Peer certificate verified against Root CA.\n");

    EVP_PKEY *pub = X509_get_pubkey(cert);
    X509_STORE_CTX_free(vctx); X509_STORE_free(store); X509_free(cert);
    return pub;
}

/* ===========================================================================
 * pq_handshake_initiator() — Client/connector role
 *
 * Sends: [X25519_pub(32) | KEM_pub(1184)] + RSA signature
 * Receives: [X25519_pub(32) | KEM_ciphertext(1088)] + RSA signature
 * Derives: HKDF(ECDH_secret || KEM_secret) → AES-256 key
 * =========================================================================== */
int pq_handshake_initiator(int sock) {
    printf("[PQ-Handshake] Initiator: generating ephemeral keys...\n");

    /* X25519 keypair */
    EVP_PKEY_CTX *ec = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *ecdh = NULL;
    if (!ec || EVP_PKEY_keygen_init(ec) <= 0 || EVP_PKEY_keygen(ec, &ecdh) <= 0)
        { printf("[-] X25519 keygen failed\n"); return 0; }
    EVP_PKEY_CTX_free(ec);
    unsigned char ecdh_pub[32]; size_t eplen = 32;
    EVP_PKEY_get_raw_public_key(ecdh, ecdh_pub, &eplen);

    /* ML-KEM-768 keypair */
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) { printf("[-] ML-KEM-768 unavailable\n"); return 0; }
    uint8_t *kpub = malloc(kem->length_public_key);
    uint8_t *ksec = malloc(kem->length_secret_key);
    if (OQS_KEM_keypair(kem, kpub, ksec) != OQS_SUCCESS)
        { printf("[-] KEM keypair failed\n"); return 0; }

    /* Build and sign payload: [ecdh_pub | kem_pub] */
    size_t payload_len = 32 + kem->length_public_key;
    unsigned char *payload = malloc(payload_len);
    memcpy(payload, ecdh_pub, 32);
    memcpy(payload + 32, kpub, kem->length_public_key);
    free(kpub);

    unsigned char sig[256]; size_t slen = sizeof(sig);
    if (!sign_data(payload, payload_len, sig, &slen, priv_key))
        { printf("[-] Signing failed\n"); return 0; }

    /* Transmit */
    uint32_t nl = htonl((uint32_t)payload_len);
    uint32_t sl = htonl((uint32_t)slen);
    send(sock, &nl, 4, 0); send(sock, payload, payload_len, 0);
    send(sock, &sl, 4, 0); send(sock, sig, slen, 0);
    free(payload);
    printf("[PQ-Handshake] Sent ephemeral public keys.\n");

    /* Receive responder's data */
    uint32_t rnl; recv(sock, &rnl, 4, MSG_WAITALL);
    uint32_t rlen = ntohl(rnl);
    unsigned char *rbuf = malloc(rlen);
    recv(sock, rbuf, rlen, MSG_WAITALL);
    uint32_t rsl; recv(sock, &rsl, 4, MSG_WAITALL);
    uint32_t rslen = ntohl(rsl);
    unsigned char rsig[256];
    recv(sock, rsig, rslen, MSG_WAITALL);

    /* Verify responder's signature */
    if (!verify_signature(rbuf, rlen, rsig, rslen, peer_pub_key)) {
        printf("[-] MITM! Responder signature invalid.\n");
        free(rbuf); return 0;
    }
    printf("[PQ-Handshake] Responder signature verified.\n");

    /* Extract X25519 pub + KEM ciphertext */
    unsigned char rpub[32]; memcpy(rpub, rbuf, 32);
    uint8_t *kct = malloc(kem->length_ciphertext);
    memcpy(kct, rbuf + 32, kem->length_ciphertext);
    free(rbuf);

    /* ECDH shared secret */
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, rpub, 32);
    EVP_PKEY_CTX *dc = EVP_PKEY_CTX_new(ecdh, NULL);
    EVP_PKEY_derive_init(dc); EVP_PKEY_derive_set_peer(dc, peer);
    size_t elen = 32; unsigned char esec[32];
    EVP_PKEY_derive(dc, esec, &elen);
    EVP_PKEY_CTX_free(dc); EVP_PKEY_free(peer); EVP_PKEY_free(ecdh);

    /* KEM decapsulation */
    uint8_t ksecret[32];
    if (OQS_KEM_decaps(kem, ksecret, kct, ksec) != OQS_SUCCESS)
        { printf("[-] KEM decaps failed\n"); return 0; }
    free(kct);
    OQS_MEM_cleanse(ksec, kem->length_secret_key); free(ksec);
    OQS_KEM_free(kem);

    /* HKDF: combine both secrets → 32-byte AES key */
    unsigned char ikm[64];
    memcpy(ikm, esec, 32); memcpy(ikm + 32, ksecret, 32);
    hkdf_sha256((const unsigned char*)"hybrid-pq-handshake-salt", 24,
                ikm, 64,
                (const unsigned char*)"ecdhe-x25519-mlkem768-aes256-gcm", 32,
                session_aes_key, 32);
    OPENSSL_cleanse(esec, 32); OPENSSL_cleanse(ksecret, 32);
    OPENSSL_cleanse(ikm, 64);
    session_active = 1;
    send_seq = recv_seq = 0;
    printf("[+] PQ key exchange complete. AES-256-GCM session active.\n");
    return 1;
}

/* ===========================================================================
 * pq_handshake_responder() — Server/listener role
 * =========================================================================== */
int pq_handshake_responder(int sock) {
    printf("[PQ-Handshake] Responder: waiting for initiator's keys...\n");

    /* Receive initiator's payload + signature */
    uint32_t pnl; recv(sock, &pnl, 4, MSG_WAITALL);
    uint32_t plen = ntohl(pnl);
    unsigned char *pbuf = malloc(plen);
    recv(sock, pbuf, plen, MSG_WAITALL);
    uint32_t snl; recv(sock, &snl, 4, MSG_WAITALL);
    uint32_t slen = ntohl(snl);
    unsigned char psig[256];
    recv(sock, psig, slen, MSG_WAITALL);

    /* Verify signature */
    if (!verify_signature(pbuf, plen, psig, slen, peer_pub_key)) {
        printf("[-] MITM! Initiator signature invalid.\n");
        free(pbuf); return 0;
    }
    printf("[PQ-Handshake] Initiator signature verified.\n");

    /* Extract X25519 pub + KEM pub */
    unsigned char ipub[32]; memcpy(ipub, pbuf, 32);
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) { printf("[-] ML-KEM-768 unavailable\n"); return 0; }
    uint8_t *kpub = malloc(kem->length_public_key);
    memcpy(kpub, pbuf + 32, kem->length_public_key);
    free(pbuf);

    /* Generate our X25519 keypair */
    EVP_PKEY_CTX *ec = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *ecdh = NULL;
    if (!ec || EVP_PKEY_keygen_init(ec) <= 0 || EVP_PKEY_keygen(ec, &ecdh) <= 0)
        { printf("[-] X25519 keygen failed\n"); return 0; }
    EVP_PKEY_CTX_free(ec);
    unsigned char ecdh_pub[32]; size_t eplen = 32;
    EVP_PKEY_get_raw_public_key(ecdh, ecdh_pub, &eplen);

    /* ECDH shared secret */
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, ipub, 32);
    EVP_PKEY_CTX *dc = EVP_PKEY_CTX_new(ecdh, NULL);
    EVP_PKEY_derive_init(dc); EVP_PKEY_derive_set_peer(dc, peer);
    size_t elen = 32; unsigned char esec[32];
    EVP_PKEY_derive(dc, esec, &elen);
    EVP_PKEY_CTX_free(dc); EVP_PKEY_free(peer); EVP_PKEY_free(ecdh);

    /* KEM encapsulation */
    uint8_t *kct = malloc(kem->length_ciphertext);
    uint8_t ksecret[32];
    if (OQS_KEM_encaps(kem, kct, ksecret, kpub) != OQS_SUCCESS)
        { printf("[-] KEM encaps failed\n"); return 0; }
    free(kpub);

    /* HKDF → session key */
    unsigned char ikm[64];
    memcpy(ikm, esec, 32); memcpy(ikm + 32, ksecret, 32);
    hkdf_sha256((const unsigned char*)"hybrid-pq-handshake-salt", 24,
                ikm, 64,
                (const unsigned char*)"ecdhe-x25519-mlkem768-aes256-gcm", 32,
                session_aes_key, 32);
    OPENSSL_cleanse(esec, 32); OPENSSL_cleanse(ksecret, 32);
    OPENSSL_cleanse(ikm, 64);
    session_active = 1;
    send_seq = recv_seq = 0;

    /* Build and sign response: [ecdh_pub | kem_ciphertext] */
    size_t rlen = 32 + kem->length_ciphertext;
    unsigned char *rbuf = malloc(rlen);
    memcpy(rbuf, ecdh_pub, 32);
    memcpy(rbuf + 32, kct, kem->length_ciphertext);
    free(kct); OQS_KEM_free(kem);

    unsigned char sig[256]; size_t siglen = sizeof(sig);
    if (!sign_data(rbuf, rlen, sig, &siglen, priv_key))
        { printf("[-] Signing failed\n"); return 0; }

    uint32_t rnl = htonl((uint32_t)rlen);
    uint32_t rsl = htonl((uint32_t)siglen);
    send(sock, &rnl, 4, 0); send(sock, rbuf, rlen, 0);
    send(sock, &rsl, 4, 0); send(sock, sig, siglen, 0);
    free(rbuf);

    printf("[+] PQ key exchange complete. AES-256-GCM session active.\n");
    return 1;
}

/* ===========================================================================
 * Utility: create a listening TCP socket
 * =========================================================================== */
int create_server_socket(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port),
                             .sin_addr.s_addr = INADDR_ANY };
    if (bind(fd, (struct sockaddr*)&a, sizeof(a)) < 0) {
        perror("[-] Bind failed");
        close(fd);
        return -1;
    }
    listen(fd, 10);
    return fd;
}

/* ===========================================================================
 * send_file_func() — Encrypted file transfer (AES-256-GCM)
 * =========================================================================== */
void send_file_func(char *filename) {
    if (!session_active) {
        printf("[-] No active session.\n"); return;
    }
    int fd = open(filename, O_RDONLY);
    if (fd < 0) { printf("[-] File not found: %s\n", filename); return; }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(PORT_FILE) };
    a.sin_addr.s_addr = inet_addr(peer_ip);
    if (connect(sock, (struct sockaddr*)&a, sizeof(a)) < 0) {
        perror("[-] File connection failed"); close(fd); return;
    }
    printf("[FILE] Sending %s to %s...\n", filename, peer_ip);

    /* Bootstrap: send 32-byte AES key encrypted with peer's RSA public key */
    unsigned char enc_key[256];
    rsa_encrypt(session_aes_key, 32, enc_key, peer_pub_key);
    send(sock, enc_key, 256, 0);

    /* Send file chunks with AES-256-GCM (local seq counter) */
    uint64_t fseq = 0;
    unsigned char rbuf[1024], ebuf[1024 + GCM_OVERHEAD];
    int n;
    while ((n = read(fd, rbuf, 1024)) > 0) {
        int elen = aes_gcm_seal(session_aes_key, &fseq, rbuf, n, ebuf);
        if (elen > 0) {
            uint32_t nl = htonl(elen);
            send(sock, &nl, 4, 0);
            send(sock, ebuf, elen, 0);
        }
    }
    uint32_t stop = 0;
    send(sock, &stop, 4, 0);
    close(fd); close(sock);
    printf("[+] File sent securely.\n");
}

/* ===========================================================================
 * handle_file() — Receive encrypted file transfers (GCM)
 * =========================================================================== */
void handle_file(int server_fd) {
    struct sockaddr_in ca;
    socklen_t al = sizeof(ca);
    printf("[FILE] Listening on port %d...\n", PORT_FILE);

    while (1) {
        int cs = accept(server_fd, (struct sockaddr*)&ca, &al);
        if (cs < 0) continue;
        printf("\n[FILE] Incoming file transfer...\n");
        FILE *fp = fopen("received_file.dat", "wb");

        /* Receive RSA-encrypted AES key */
        unsigned char enc_key[256], file_key[48];
        if (recv(cs, enc_key, 256, MSG_WAITALL) <= 0) {
            close(cs); fclose(fp); continue;
        }
        int klen = rsa_decrypt(enc_key, 256, file_key, priv_key);
        if (klen < 32) {
            printf("[-] File key decryption failed.\n");
            close(cs); fclose(fp); continue;
        }

        /* Receive GCM-encrypted chunks */
        uint64_t fseq = 0;
        uint32_t chunk_nl;
        while (recv(cs, &chunk_nl, 4, MSG_WAITALL) > 0) {
            int chunk_len = ntohl(chunk_nl);
            if (chunk_len <= 0) break;
            unsigned char enc_buf[2048], dec_buf[2048];
            int n = recv(cs, enc_buf, chunk_len, MSG_WAITALL);
            if (n > 0) {
                int dlen = aes_gcm_open(file_key, &fseq, enc_buf, n, dec_buf);
                if (dlen > 0) fwrite(dec_buf, 1, dlen, fp);
                else printf("[-] File chunk auth failed!\n");
            }
        }
        fclose(fp); close(cs);
        OPENSSL_cleanse(file_key, 32);
        printf("[FILE] Saved as received_file.dat\nYou> ");
        fflush(stdout);
    }
}

/* ===========================================================================
 * main() — Bidirectional: connect to peer OR listen for peer
 * =========================================================================== */
int main(void) {
    printf("=== Secure Chat — Client/Peer ===\n");

    priv_key = setup_csr();
    if (!priv_key) { fprintf(stderr, "[-] CSR setup failed.\n"); exit(1); }

    int mode;
    printf("\nSelect mode:\n");
    printf("  1) Connect to a peer\n");
    printf("  2) Listen for incoming connection\n");
    printf("Choice [1/2]: ");
    scanf("%d", &mode);
    getchar();

    int chat_sock;

    if (mode == 2) {
        /* ── LISTEN MODE (responder) ── */
        int lsock = create_server_socket(PORT_CHAT);
        if (lsock < 0) { printf("[-] Cannot listen on port %d.\n", PORT_CHAT); return 1; }
        printf("[Peer] Listening on port %d for incoming chat...\n", PORT_CHAT);
        struct sockaddr_in ca; socklen_t al = sizeof(ca);
        chat_sock = accept(lsock, (struct sockaddr*)&ca, &al);
        close(lsock);

        inet_ntop(AF_INET, &ca.sin_addr, peer_ip, sizeof(peer_ip));
        printf("[Peer] Connection from %s\n", peer_ip);

        peer_pub_key = perform_secure_handshake(chat_sock);
        if (!peer_pub_key) { printf("[-] Handshake failed.\n"); return 1; }

        if (!pq_handshake_responder(chat_sock)) { printf("[-] PQ handshake failed.\n"); return 1; }

    } else {
        /* ── CONNECT MODE (initiator — default) ── */
        int dns_sock;
        struct sockaddr_in da;
        char domain[100];
        socklen_t al = sizeof(da);

        printf("Enter domain to resolve (e.g., www.abc.com): ");
        scanf("%s", domain); getchar();

        if ((dns_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) exit(1);
        memset(&da, 0, sizeof(da));
        da.sin_family = AF_INET;
        da.sin_port = htons(DNS_PORT);
        da.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);

        sendto(dns_sock, domain, strlen(domain), 0, (struct sockaddr*)&da, sizeof(da));
        int n = recvfrom(dns_sock, peer_ip, sizeof(peer_ip) - 1, 0,
                         (struct sockaddr*)&da, &al);
        peer_ip[n] = '\0';
        close(dns_sock);

        if (strcmp(peer_ip, "0.0.0.0") == 0) {
            printf("[-] Domain not found.\n"); return 0;
        }

        char cmd[256]; snprintf(cmd, sizeof(cmd), "ping -c 1 %s", peer_ip); system(cmd);

        chat_sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(PORT_CHAT) };
        sa.sin_addr.s_addr = inet_addr(peer_ip);
        printf("[Peer] Connecting to %s:%d...\n", peer_ip, PORT_CHAT);
        if (connect(chat_sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
            perror("[-] Connection failed"); exit(1);
        }

        peer_pub_key = perform_secure_handshake(chat_sock);
        if (!peer_pub_key) { printf("[-] Handshake failed.\n"); return 1; }

        if (!pq_handshake_initiator(chat_sock)) { printf("[-] PQ handshake failed.\n"); return 1; }
    }

    printf("[+] Secure session established with %s\n", peer_ip);
    printf("    Cipher : AES-256-GCM (authenticated encryption)\n");
    printf("    KEx    : X25519 + ML-KEM-768 (post-quantum hybrid)\n");
    printf("    Features: per-message nonce, anti-replay seq#, 128-bit auth tag\n\n");

    /* Start file listener (both modes can receive files) */
    int file_sock = create_server_socket(PORT_FILE);
    if (file_sock >= 0) {
        if (fork() == 0) {
            close(chat_sock);
            handle_file(file_sock);
            exit(0);
        }
        close(file_sock);
    } else {
        printf("[!] File receive disabled (port %d busy). Chat continues.\n", PORT_FILE);
    }

    /* Chat loop: fork into sender + receiver */
    if (fork() == 0) {
        /* ── CHILD: Receiver ── */
        while (1) {
            uint32_t nl;
            if (recv(chat_sock, &nl, 4, MSG_WAITALL) <= 0) {
                printf("\n[!] Peer disconnected.\n"); exit(0);
            }
            int mlen = ntohl(nl);
            if (mlen <= 0 || mlen > 4096) continue;

            unsigned char enc[4096], dec[4096];
            int n = recv(chat_sock, enc, mlen, MSG_WAITALL);
            if (n <= 0) { printf("\n[!] Peer disconnected.\n"); exit(0); }

            int dlen = aes_gcm_open(session_aes_key, &recv_seq, enc, n, dec);
            if (dlen > 0) {
                dec[dlen] = '\0';
                printf("\n[%s]: %s\nYou> ", PEER_LABEL, dec);
            } else {
                printf("\n[!] Message authentication failed — possible tampering!\nYou> ");
            }
            fflush(stdout);
        }
    } else {
        /* ── PARENT: Sender ── */
        while (1) {
            char input[SIZE];
            printf("You> ");
            fgets(input, SIZE, stdin);
            input[strcspn(input, "\n")] = 0;
            if (strlen(input) == 0) continue;

            if (strncmp(input, "sendfile ", 9) == 0) {
                char *fname = input + 9;
                while (*fname == ' ') fname++;
                send_file_func(fname);
            } else {
                unsigned char enc[SIZE + GCM_OVERHEAD];
                int elen = aes_gcm_seal(session_aes_key, &send_seq,
                                        (unsigned char*)input, strlen(input), enc);
                if (elen > 0) {
                    uint32_t nl = htonl(elen);
                    send(chat_sock, &nl, 4, 0);
                    send(chat_sock, enc, elen, 0);
                }
            }
        }
    }
    return 0;
}
