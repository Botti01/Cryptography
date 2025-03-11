#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#define DECRYPT 0

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Base64 decoding function using OpenSSL's BIO
int base64_decode(const char *input, unsigned char *output, int output_len) {

    BIO *bio, *b64; // Two BIO objects: one for Base64 filter, one for memory buffer
    
    // Get input length (Base64 encoded string)
    int input_len = strlen(input);
    // Create a memory BIO that reads from the input string
    bio = BIO_new_mem_buf(input, input_len);
    // Create a Base64 filter BIO
    b64 = BIO_new(BIO_f_base64());
    // Configure Base64 BIO to ignore newline characters
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    // Chain the BIOs: b64 (Base64 decoder) -> bio (memory buffer)
    bio = BIO_push(b64, bio);
    // Read decoded data from BIO chain into output buffer
    int decoded_len = BIO_read(bio, output, output_len);
    // Free the entire BIO chain
    BIO_free_all(bio);

    return decoded_len; // Returns length of decoded binary data

}

int main() {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    char key_hex[] = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    char iv_hex[] = "11111111111111112222222222222222";
    char base64_ciphertext[] = "jyS3NIBqenyCWpDI2jkSu+z93NkDbWkUMitg2Q==";

    // Convert hex key to binary (32 bytes)
    int key_len = strlen(key_hex)/2;
    unsigned char key[key_len];
    for(int i = 0; i < key_len; i ++) {
        sscanf(&key_hex[2*i], "%2hhx", &key[i]);
    }
    printf("\nKey: ");
    for(int i = 0; i < key_len; i++)
        printf("%02x", key[i]);
    printf("\n");

    // Convert hex IV to binary (16 bytes)
    int iv_len = strlen(iv_hex)/2;
    unsigned char iv[iv_len];
    for(int i = 0; i < iv_len; i++) {
        sscanf(&iv_hex[2*i], "%2hhx", &iv[i]);
    }
    printf("IV: ");
    for(int i = 0; i < iv_len; i++)
        printf("%02x", iv[i]);
    printf("\n");

    // Base64 decode the ciphertext
    // Calculate the maximum possible length of the decoded ciphertext.
    // Base64 encoding uses 4 characters to represent 3 bytes of binary data.
    // Formula: (input_length * 3) / 4 + 1 (for null terminator or padding).
    int max_ciphertext_len = (strlen(base64_ciphertext) * 3) / 4 + 1;
    // Allocate a buffer for the decoded ciphertext with the calculated maximum length.
    // This ensures the buffer is large enough to hold the decoded binary data.
    unsigned char ciphertext[max_ciphertext_len];
    int ciphertext_len = base64_decode(base64_ciphertext, ciphertext, sizeof(ciphertext));
    
    if (ciphertext_len < 0) {
        fprintf(stderr, "Base64 decode failed\n");
        abort();
    }

    // chacha20: 32 bytes key, 16 bytes IV
    if(!EVP_CipherInit(ctx, EVP_chacha20(), key, iv, DECRYPT))
        handle_errors();

    unsigned char plaintext[ciphertext_len];
    int plaintext_len = 0, len;

    if(!EVP_CipherUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handle_errors();
    plaintext_len += len;
    printf("\nAfter update: %d\n", plaintext_len);

    if(!EVP_CipherFinal_ex(ctx, plaintext + plaintext_len, &len))
        handle_errors();
    plaintext_len += len;
    printf("After final: %d\n", plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    
    printf("\nDecrypted Flag: ");
    for(int i = 0; i < plaintext_len; i++)
        printf("%c", plaintext[i]);
    printf("\n");

    return 0;

}