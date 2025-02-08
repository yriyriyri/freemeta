#include <stdio.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>

int main(void) {
    int bits = 1024;
    unsigned long e = RSA_F4;
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    if (!BN_set_word(bn, e)) {
        fprintf(stderr, "error in BN_set_word\n");
        exit(EXIT_FAILURE);
    }
    if (!RSA_generate_key_ex(rsa, bits, bn, NULL)) {
        fprintf(stderr, "error in RSA_generate_key_ex\n");
        exit(EXIT_FAILURE);
    }
    BN_free(bn);
    FILE *priv = fopen("private_key.pem", "wb");
    if (!priv) {
        fprintf(stderr, "cannot open private_key.pem for writing\n");
        exit(EXIT_FAILURE);
    }
    if (!PEM_write_RSAPrivateKey(priv, rsa, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "error writing private  key\n");
        fclose(priv);
        exit(EXIT_FAILURE);
    }
    fclose(priv);
    FILE *pub = fopen("public_key.pem", "wb");
    if (!pub) {
        fprintf(stderr, "cannot open public_key.pem for writing\n");
        exit(EXIT_FAILURE);
    }
    if (!PEM_write_RSA_PUBKEY(pub, rsa)) {
        fprintf(stderr, "error writing public key\n");
        fclose(pub);
        exit(EXIT_FAILURE);
    }
    fclose(pub);
    RSA_free(rsa);
    printf("rsa key pair generated and saved 'private_key.pem' + 'public_key.pem'.\n");
    return 0;
}