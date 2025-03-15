#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define MAXBUF 1024

// firts parameter is the name of the file to hash

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

    EVP_MD_CTX *md;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();


    // pedantic mode: also check if md == NULL
    md  = EVP_MD_CTX_new();

    if (!EVP_DigestInit(md, EVP_sha1())){
        handle_errors();
    }

    // EVP_DigestUpdate(md, argv[1], strlen(argv[1]));

    // fread returns the number of elements read, stops when it reaches the end of the file
    // n_read is the number of bytes read
    unsigned char buffer[MAXBUF];
    int n_read;
    while((n_read = fread(buffer, 1, MAXBUF, f_in)) > 0){
        if(!EVP_DigestUpdate(md, buffer, n_read)){
            handle_errors();
        }
    }

    // 20 bytes for SHA1
    unsigned char md_value[EVP_MD_size(EVP_sha1())];
    int md_len;

    if(!EVP_DigestFinal(md, md_value, &md_len)){
        handle_errors();
    }

    EVP_MD_CTX_free(md);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    printf("Digest is: ");
    for(int i = 0; i < md_len; i++)
        printf("%02x", md_value[i]);
    printf("\n");

    return 0;

}
