#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>     // Saving the data in output into the file, RSA_print_fp

#define MAXBUF 1024

void handle_errors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


// argv[1] = is the name of the file to sign
// argv[2] = is the name of the file where the private key is stored

int main(int argc, char **argv[]){

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if(argc != 3){
        fprintf(stderr, "Invalid parameters. Usage: %s <file to sign> <private key file>\n", argv[0]);
        exit(1);
    }

    FILE *f_in;
    if((f_in = fopen(argv[1], "r")) == NULL){
        fprintf(stderr, "Couldn't open the input file, try again\n");
        exit(1);
    }

    FILE *f_key;
    if((f_key = fopen(argv[2], "r")) == NULL){
        fprintf(stderr, "Couldn't open the private key file, try again\n");
        exit(1);
    }



    // DigestSign --> EVP_PKEY *
    EVP_PKEY *private_key = PEM_read_PrivateKey(f_key, NULL, NULL, NULL);
    fclose(f_key);

    EVP_MD_CTX *sign_ctx = EVP_MD_CTX_new();

    if (!EVP_DigestSignInit(sign_ctx, NULL, EVP_sha256(), NULL, private_key))
        handle_errors();

    unsigned char buffer[MAXBUF];
    // size_t is the same as unsigned long
    size_t n_read;

    while((n_read = fread(buffer, 1, MAXBUF, f_in)) > 0){
        if(!EVP_DigestSignUpdate(sign_ctx, buffer, n_read))
            handle_errors();
    }
    fclose(f_in);

    unsigned char signature[EVP_PKEY_size(private_key)];
    size_t sign_len;
    size_t dgst_len;

    // The first call to EVP_DigestSignFinal returns the length of the signature
    if (!EVP_DigestSignFinal(sign_ctx, NULL, &dgst_len))
        handle_errors();

    // The second call to EVP_DigestSignFinal writes the signature to the buffer
    if (!EVP_DigestSignFinal(sign_ctx, signature, &sign_len))
        handle_errors();

    EVP_MD_CTX_free(sign_ctx);

    FILE *out;
    if( (out = fopen("signature.bin", "w")) == NULL){
        fprintf(stderr, "Problems creating the signature file\n");
        abort();
    }

    if (fwrite(signature, 1, sign_len, out) < sign_len){
        fprintf(stderr, "Couldn't save data\n");
        abort();
    }
    fclose(out);

    printf("Signature written!\n");


    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;

}

// To check the signature:
// openssl dgst -sha256 -signature signature.bin -verify public.pem rsa_keygen1.c
