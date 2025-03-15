/*
You sniffed the following Base64 string

ZZJ+BKJNdpXA2jaX8Zg5ItRola18hi95MG8fA/9RPvg=

You know it is an encrypted payload that has been ciphered with these parameters: key = "0123456789ABCDEF" iv = "0123456789ABCDEF" 
(Note: key and iv are not to be taken as hex strings)

Write a program (based for instance on dec1.c or a modification of enc4.c) to decrypt it and obtain decryptedcontent.

Then, take note of the following instruction in your decryption program if(!EVP_CipherInit(ctx,algorithm_name(), key, iv, ENCRYPT))

When you succeed, build the flag in this way (Python-style string concatenation)

"CRYPTO25{" + decryptedcontent + algorithm_name + "}"
*/


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

// Structure to hold callback data.
typedef struct {
    unsigned char *ciphertext;
    int ciphertext_len;
    unsigned char *key;
    unsigned char *iv;
} callback_data_t;


// Callback function for EVP_CIPHER_do_all.
// It attempts to decrypt the provided ciphertext using the current cipher.
// If decryption is successful, the algorithm name and the decrypted result are printed.
void cipher_callback(const EVP_CIPHER *cipher, const char *algo, const char *unused, void *userdata) {
    callback_data_t *data = (callback_data_t *)userdata;
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return;
    
    // Initialize decryption context with the current cipher, key, and IV.
    if (!EVP_CipherInit_ex(ctx, cipher, NULL, data->key, data->iv, DECRYPT)) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    
    // Allocate a buffer for the decrypted output (add extra space for possible padding).
    int block_size = EVP_CIPHER_block_size(cipher);
    int outbuf_size = data->ciphertext_len + block_size;
    unsigned char *plaintext = malloc(outbuf_size);
    if (!plaintext) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    memset(plaintext, 0, outbuf_size);
    
    int out_len = 0, total_len = 0;
    
    // Attempt decryption (update phase).
    if (!EVP_CipherUpdate(ctx, plaintext, &out_len, data->ciphertext, data->ciphertext_len)) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    total_len += out_len;
    
    // Finalize decryption (this step verifies padding correctness).
    if (!EVP_CipherFinal_ex(ctx, plaintext + total_len, &out_len)) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    total_len += out_len;
    
    // Ensure null termination for printing as a string.
    if(total_len < outbuf_size)
        plaintext[total_len] = '\0';

    // Print the current algorithm name.
    printf("Algorithm: %s\n", algo);
    
    // Print the decrypted result.
    printf("Decrypted result: %s\n\n", plaintext);
    // printf("%s\n\n", plaintext);

    free(plaintext);
    EVP_CIPHER_CTX_free(ctx);
}


int main() {


    char key[] = "0123456789ABCDEF";
    char iv[] = "0123456789ABCDEF";
    char base64_ciphertext[] = "ZZJ+BKJNdpXA2jaX8Zg5ItRola18hi95MG8fA/9RPvg=";

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

    // Prepare callback data.
    callback_data_t data;
    data.ciphertext = ciphertext;
    data.ciphertext_len = ciphertext_len;
    data.key = (unsigned char *)key;
    data.iv = (unsigned char *)iv;

    // Initialize OpenSSL algorithms and load error strings.
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Iterate over all available ciphers and try to decrypt the ciphertext.
    EVP_CIPHER_do_all(cipher_callback, &data);

    // Cleanup.
    EVP_cleanup();
    ERR_free_strings();

    return 0;

}