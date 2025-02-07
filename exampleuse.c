#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>

unsigned char* hex_to_bytes(const char *hex, size_t *out_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0) return NULL;
    *out_len = len / 2;
    unsigned char *result = malloc(*out_len);
    if (!result) return NULL;
    for (size_t i = 0; i < *out_len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &result[i]);
    }
    return result;
}

int main(void) {
    FILE *fp = fopen("private_key.pem", "r");
    if (!fp) { fprintf(stderr, "error opening private_key.pem\n"); return 1; }
    RSA *private_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!private_key) { fprintf(stderr, "error reading private key\n"); return 1; }
    fp = fopen("public_key.pem", "r");
    if (!fp) { fprintf(stderr, "error opening public_key.pem\n"); return 1; }
    RSA *public_key = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!public_key) { fprintf(stderr, "error reading public key\n"); return 1; }
    BIO *bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_RSA_PUBKEY(bio, public_key)) { fprintf(stderr, "error exporting public key\n"); return 1; }
    size_t pub_len = BIO_pending(bio);
    char *pub_pem = malloc(pub_len + 1);
    BIO_read(bio, pub_pem, pub_len);
    pub_pem[pub_len] = '\0';
    BIO_free(bio);
    printf("please encrypt your message using the following public key with rsa encryption and pkcs1_oaep padding:\n\n%s\n\nrespond with the encrypted message in hex format:\n", pub_pem);
    free(pub_pem);
    char hex_input[8192];
    if (fgets(hex_input, sizeof(hex_input), stdin) == NULL) { fprintf(stderr, "error reading input\n"); return 1; }
    hex_input[strcspn(hex_input, "\n")] = '\0';
    size_t encrypted_len;
    unsigned char *encrypted = hex_to_bytes(hex_input, &encrypted_len);
    if (!encrypted) { fprintf(stderr, "invalid hex string\n"); return 1; }
    int rsa_size = RSA_size(private_key);
    unsigned char *decrypted = malloc(rsa_size + 1);
    int dec_len = RSA_private_decrypt(encrypted_len, encrypted, decrypted, private_key, RSA_PKCS1_OAEP_PADDING);
    if (dec_len == -1) {
        fprintf(stderr, "decryption failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        free(encrypted);
        free(decrypted);
        return 1;
    }
    decrypted[dec_len] = '\0';
    printf("\ndecrypted msg ;;; %s\n", decrypted);
    free(encrypted);
    free(decrypted);
    RSA_free(private_key);
    RSA_free(public_key);
    return 0;
}