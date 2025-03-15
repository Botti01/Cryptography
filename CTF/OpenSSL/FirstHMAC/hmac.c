/*
Write a program that computes the HMAC-SHA256 of two files whose names are passed as parameters from the command line (start from HMAC_computation_EVP).

The flag is obtained as

CRYPTO25{hmac}

where hmac is obtained using the secret "keykeykeykeykeykey" and the two files attached to this challenge (and hexdigits in lowercase):

hmac = hex(HMAC-SHA256("keykeykeykeykeykey", file,file2))

where "keykeykeykeykeykey" is an ASCII string (no quotation marks)
*/


#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#define MAXBUF 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}


int main(int argc, char **argv){
    
    unsigned char secret[] = "keykeykeykeykeykey";
    
    if(argc != 3){
        fprintf(stderr,"Invalid parameters. Usage: %s filename1 filename2\n",argv[0]);
        exit(1);
    }


    FILE *f_in;
    if((f_in = fopen(argv[1],"r")) == NULL) {
            fprintf(stderr,"Couldn't open the first input file, try again\n");
            exit(1);
    }

    FILE *f_in2;
    if((f_in2 = fopen(argv[2],"r")) == NULL) {
            fprintf(stderr,"Couldn't open the second input file, try again\n");
            exit(1);
    }


    //EVP_MD_CTX *EVP_MD_CTX_new(void);
    //pedantic mode? Check if md == NULL
    EVP_MD_CTX  *hmac_ctx = EVP_MD_CTX_new();

    //int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
    // int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
    // Returns 1 for success and 0 for failure.
    EVP_PKEY *hkey;
    hkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, secret, strlen(secret));

    if(!EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha256(), NULL, hkey))
        handle_errors();


    size_t n;
    unsigned char buffer[MAXBUF];
    // HMAC of the first file
    while((n = fread(buffer,1,MAXBUF,f_in)) > 0){
    // Returns 1 for success and 0 for failure.
        if(!EVP_DigestSignUpdate(hmac_ctx, buffer, n))
            handle_errors();
    }

    size_t n2;
    unsigned char buffer2[MAXBUF];
    // HMAC of the second file
    while((n2 = fread(buffer2,1,MAXBUF,f_in2)) > 0){
    // Returns 1 for success and 0 for failure.
        if(!EVP_DigestSignUpdate(hmac_ctx, buffer2, n2))
            handle_errors();
    }

    unsigned char hmac_value[EVP_MD_size(EVP_sha256())];
    size_t hmac_len = EVP_MD_size(EVP_sha256());

    //int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned size_t *s);
    // EVP_DigestSignFinal(hmac_ctx, NULL, &hmac_len);
    if(!EVP_DigestSignFinal(hmac_ctx, hmac_value, &hmac_len))
        handle_errors();

    // void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
    EVP_MD_CTX_free(hmac_ctx);
    EVP_PKEY_free(hkey);
    fclose(f_in);
    fclose(f_in2);

    printf("The HMAC is: ");
    for(int i = 0; i < hmac_len; i++)
        printf("%02x", hmac_value[i]);
    printf("\n");


	return 0;

}


// Flag: CRYPTO25{9453ac565269a96ea3ea583b15b410111b42ae03d1054a02fe4ba4b1029734d3}