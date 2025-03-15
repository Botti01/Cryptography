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
    
    HMAC_CTX *hmac_ctx = HMAC_CTX_new();
    if(hmac_ctx == NULL)
        handle_errors();

    // NULL indicating to the system that we don't have any external engine
    if(!HMAC_Init_ex(hmac_ctx, key, strlen(key), EVP_sha1(), NULL))
        handle_errors();

    int n_read;
    unsigned char buffer[MAXBUF];
    while ((n_read = fread(buffer, 1, MAXBUF, f_in)) > 0){
        if(!HMAC_Update(hmac_ctx, buffer, n_read))
            handle_errors();
    }

    // HMAC_size returns the size of the HMAC in bytes using the given context
    // change the content of HMAC_size using the algorithm
    unsigned char hmac_value[HMAC_size(EVP_sha1())];
    int hmac_len;

    if(!HMAC_Final(hmac_ctx, hmac_value, &hmac_len))
        handle_errors();

    HMAC_CTX_free(hmac_ctx);

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
