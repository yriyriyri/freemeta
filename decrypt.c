#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

unsigned char* hex_to_bytes(const char *hexstr, size_t *out_len) {
    size_t len = strlen(hexstr);
    if (len % 2 != 0) return NULL;
    *out_len = len / 2;
    unsigned char *result = malloc(*out_len);
    if (!result) return NULL;
    for (size_t i = 0; i < *out_len; i++) {
        if (sscanf(hexstr + 2 * i, "%2hhx", &result[i]) != 1) {
            free(result);
            return NULL;
        }
    }
    return result;
}

int main(void) {
    char hex_input[4096];
    printf("encrypted message  ;;(hexformat): ");
    if (fgets(hex_input, sizeof(hex_input), stdin) == NULL) {
        fprintf(stderr, "error reading input\n");
        return 1;
    }
    hex_input[strcspn(hex_input, "\n")] = '\0';
    size_t encrypted_len;
    unsigned char *encrypted_message = hex_to_bytes(hex_input, &encrypted_len);
    if (encrypted_message == NULL) {
        fprintf(stderr, "invalid hex string\n");
        return 1;
    }
    FILE *fp = fopen("private_key.pem", "r");
    if (fp == NULL) {
        fprintf(stderr, "cannot open private_key.pem\n");
        free(encrypted_message);
        return 1;
    }
    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (rsa == NULL) {
        fprintf(stderr, "error reading private key: %s\n", ERR_error_string(ERR_get_error(), NULL));
        free(encrypted_message);
        return 1;
    }
    int rsa_size = RSA_size(rsa);
    unsigned char *decrypted_message = malloc(rsa_size + 1);
    if (decrypted_message == NULL) {
        fprintf(stderr, "memory allocation error\n");
        RSA_free(rsa);
        free(encrypted_message);
        return 1;
    }
    int decrypted_len = RSA_private_decrypt(encrypted_len, encrypted_message, decrypted_message, rsa, RSA_PKCS1_OAEP_PADDING);
    if (decrypted_len == -1) {
        fprintf(stderr, "rsa decryption failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        RSA_free(rsa);
        free(encrypted_message);
        free(decrypted_message);
        return 1;
    }
    decrypted_message[decrypted_len] = '\0';
    printf("decrypted Message ;; %s\n", decrypted_message);
    RSA_free(rsa);
    free(encrypted_message);
    free(decrypted_message);
    return 0;
}