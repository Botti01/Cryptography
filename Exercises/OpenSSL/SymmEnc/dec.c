#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

#define ENCRYPT 1
#define DECRYPT 0

int main(){

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();     // Create a new context

    unsigned char key[] = "1234567890abcdef";       // 128-bit key  ASCII characters
    unsigned char iv[] = "abcdef1234567890";        // 128-bit IV   ASCII characters
    unsigned char ciphertext[] = "13713c9b8081468892c518592730b34911238dd797a66c0f103fcb7253568dcd22c6af73776da2bf5b5d3c5748502211";

    EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, DECRYPT);                       // Initialize the context

    unsigned char plaintext[strlen(ciphertext)/2];                    // 48 Ciphertext buffer to store the encrypted data
    unsigned char ciphertext_bin[strlen(ciphertext)/2];

    for (int i = 0; i < strlen(ciphertext)/2; i++){
        sscanf(&ciphertext[2*i], "%2hhx", &ciphertext_bin[i]);       // Convert the ciphertext from hex to binary
    }

    int lenght;
    int plaintext_len = 0;

    EVP_CipherUpdate(ctx, plaintext, &lenght, ciphertext_bin, strlen(ciphertext)/2);   

    printf("After update: %d\n", lenght);
    plaintext_len += lenght;

    EVP_CipherFinal(ctx, plaintext + plaintext_len, &lenght);    // Finalize the encryption
    printf("After final: %d\n", lenght);
    plaintext_len += lenght;

    EVP_CIPHER_CTX_free(ctx);

    plaintext[plaintext_len] = '\0';          // Add the null terminator to the plaintext

    printf("Plaintext: %s\n", plaintext);

    return 0;

}