#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>
// for HMAC
#include <openssl/hmac.h>

#define MAXBUF 1024

void handle_errors(void){
    ERR_print_errors_fp(stderr);
    abort();
}


int main(int argc, char **argv){

    if(argc != 2){
        fprintf(stderr, "Invalid parameters num. Usage: %s filename\n", argv[0]);
        exit(-1);
    }

    FILE *f_in;
    if((f_in = fopen(argv[1], "r")) == NULL){
        fprintf(stderr, "Couldn't open the input file, try again\n");
        exit(-1);
    }

    // Load the human readable error strings for libcrypto
    ERR_load_crypto_strings();
    // Load all digest and cipher algorithms
    OpenSSL_add_all_algorithms();


    unsigned char key[] = "1234567887654321";   // ASCII 
    // using this function to permorf the initialization of the data structure that will be used
    // for computing the HMAC using this different approach
    EVP_PKEY *hmac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, 16);
    
    EVP_MD_CTX *hmac_ctx = EVP_MD_CTX_new();
    if(hmac_ctx == NULL)
        handle_errors();

    // chage the HMAC_Init_ex to EVP_DigestSignInit and the definition of the function
    // ctx, NULL (used when we need to compute digital signature, this is the context for managing  
    // public key material. In this case we compute the HMAC so this NULL is not required to the engine.
    // all the public key material is managed by the EVP_PKEY structure), algorithm, NULL (no engine),
    // and the key that will be used to compute the HMAC
    if(!EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha1(), NULL, hmac_key))
        handle_errors();

    
    int n_read;
    unsigned char buffer[MAXBUF];
    // change the HMAC_Update to EVP_DigestSignUpdate
    while ((n_read = fread(buffer, 1, MAXBUF, f_in)) > 0){
        if(!EVP_DigestSignUpdate(hmac_ctx, buffer, n_read))
            handle_errors();
    }

    // HMAC_size returns the size of the HMAC in bytes using the given context
    unsigned char hmac_value[HMAC_size(hmac_ctx)];
    int hmac_len;

    // change the HMAC_Final to EVP_DigestSignFinal
    if(!EVP_DigestSignFinal(hmac_ctx, hmac_value, &hmac_len))
        handle_errors();

    EVP_MD_CTX_free(hmac_ctx);

    printf("The HMAC is: ");
    for (int i = 0; i < 20; i++)
        printf("%02x", hmac_value[i]);
    printf("\n");

    // completely free all the ciper data
    CRYPTO_cleanup_all_ex_data();
    // Remove error strings
    ERR_free_strings();


    return 0;

}
