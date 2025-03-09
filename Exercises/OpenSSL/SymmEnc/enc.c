#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(){

    // Initialize OpenSSL libraries
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();     // Create a new context.   check NULL

    unsigned char key[] = "1234567890abcdef";       // 128-bit key  ASCII characters (16 bytes)
    unsigned char iv[] = "abcdef1234567890";        // 128-bit IV   ASCII characters (16 bytes)

    if (!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT))                       // Initialize the context
        handle_errors();

    unsigned char plaintext[] = "This variable contains very important data!";    // 44, Plaintext to encrypt
    unsigned char ciphertext[48];                    // 48 Ciphertext buffer to store the encrypted data (approximate the size of the plaintext)

    int lenght;
    int ciphertext_len = 0;

    // Encrypt the plaintext in blocks
    if(!EVP_CipherUpdate(ctx, ciphertext, &lenght, plaintext, strlen(plaintext)))
        handle_errors();

    printf("After update: %d\n", lenght);
    ciphertext_len += lenght;

    // Finalize encryption (handles padding)
    if(!EVP_CipherFinal(ctx, ciphertext + ciphertext_len, &lenght))    // Finalize the encryption
        handle_errors();
    printf("After final: %d\n", lenght);
    ciphertext_len += lenght;

    // Free the encryption context
    EVP_CIPHER_CTX_free(ctx);

    printf("Size of the ciphertext: %d\n", ciphertext_len);
    for (int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");

    // Cleanup OpenSSL resources
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;

}