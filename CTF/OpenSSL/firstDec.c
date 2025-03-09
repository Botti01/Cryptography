#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define DECRYPT 0

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int base64_decode(const char *input, unsigned char **output) {
    BIO *bio, *b64;
    int input_len = strlen(input);
    *output = (unsigned char *)malloc(input_len);
    if (!*output) return -1;

    bio = BIO_new_mem_buf(input, input_len);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    int decoded_len = BIO_read(bio, *output, input_len);
    BIO_free_all(bio);

    return decoded_len;
}

int main() {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    const char *key_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    const char *iv_hex = "11111111111111112222222222222222";
    const char *base64_ciphertext = "jyS3NIBqenyCWpDI2jkSu+z93NkDbWkUMitg2Q==";

    // Convert hex key to binary (32 bytes)
    unsigned char key[32];
    for (int i = 0; i < 64; i += 2) {
        sscanf(key_hex + i, "%2hhx", &key[i/2]);
    }

    // Convert hex IV to binary (16 bytes)
    unsigned char iv[16];
    for (int i = 0; i < 32; i += 2) {
        sscanf(iv_hex + i, "%2hhx", &iv[i/2]);
    }

    // Base64 decode the ciphertext
    unsigned char *ciphertext;
    int ciphertext_len = base64_decode(base64_ciphertext, &ciphertext);
    if (ciphertext_len < 0) {
        fprintf(stderr, "Base64 decode failed\n");
        abort();
    }

    // Initialize decryption context
    if (!EVP_CipherInit(ctx, EVP_chacha20(), key, iv, DECRYPT))
        handle_errors();

    unsigned char plaintext[ciphertext_len + 16]; // Extra space for padding
    int plaintext_len = 0, len;

    // Perform decryption
    if (!EVP_CipherUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handle_errors();
    plaintext_len += len;

    if (!EVP_CipherFinal(ctx, plaintext + plaintext_len, &len))
        handle_errors();
    plaintext_len += len;

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);

    // Output the decrypted flag
    printf("Decrypted Flag: ");
    for(int i = 0; i < plaintext_len; i++)
        printf("%c", plaintext[i]);
    printf("\n");

    return 0;
    
}