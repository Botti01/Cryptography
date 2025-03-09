#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0
#define MAX 1024

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

// argv[1]: input file
// argv[2]: key (hexadecimalstring)
// argv[3]: iv (hexadecimalstring)
// argv[4]: output file
// save in a buffer in memory theresult of the encryption

int main(int argc, char **argv) {

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (argc !=5 ){
        fprintf(stderr, "Invalid parameters. Usage: %s input_file key IV out_file\n", argv[0]);
        exit(1);
    }

    FILE *f_in;
    if ((f_in = fopen(argv[1], "r")) == NULL){
        fprintf(stderr, "Error opening the input file %s\n", argv[1]);
        exit(1);
    }

    FILE *f_out;
    if ((f_out = fopen(argv[4], "wb")) == NULL){
        fprintf(stderr, "Error opening the output file %s\n", argv[4]);
        exit(1);
    }

    if (strlen(argv[2])/2 != 32){
        fprintf(stderr, "Wrong key length!\n");
        exit(1);
    }

    unsigned char key[strlen(argv[2])/2];
    for (int i = 0; i < strlen(argv[2])/2; i++)
        sscanf(&argv[2][2*i], "%2hhx", &key[i]);
    

    if (strlen(argv[3])/2 != 32){
        fprintf(stderr, "Wrong IV length!\n");
        exit(1);
    }

    unsigned char iv[strlen(argv[3])/2];
    for (int i = 0; i < strlen(argv[3])/2; i++)
        sscanf(&argv[3][2*i], "%2hhx", &iv[i]);


    if(!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT))
        handleErrors();
    
    int n_read;
    unsigned char buffer[MAX];
    unsigned char ciphertext[MAX + 16];
    int len, ciphertext_len = 0;

    while ((n_read = fread(buffer, 1, MAX, f_in)) > 0){

        if (!EVP_CipherUpdate(ctx, ciphertext, &len, buffer, n_read))
            handleErrors();
        ciphertext_len += len;

        if (fwrite(ciphertext, 1, len, f_out) < len){
            fprintf(stderr, "Error writing intothe output file\n");
            abort();
        }
    }

    if (!EVP_CipherFinal(ctx, ciphertext, &len))
        handleErrors();
    ciphertext_len += len;

    if (fwrite(ciphertext, 1, len, f_out) < len){
        fprintf(stderr, "Error writing intothe output file\n");
        abort();
    }

    EVP_CIPHER_CTX_free(ctx);

    printf("\nCiphertext lenght = %d\n\n", ciphertext_len);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    fclose(f_in);
    fclose(f_out);

    return 0;

}


// input
// key: 6a1d8c4e2f3b9a6c8d5e1f4b3c7a2e8f6a1d8c4e2f3b9a6c8d5e1f4b3c7a2e8f
// iv: 9f2d4b6e7a3c1f8d5e2f4a9b6c7d3e1f9f2d4b6e7a3c1f8d5e2f4a9b6c7d3e1f

// to decript the file: 
// openssl enc -d -aes-128-cbc -in enc3.enc -K 6a1d8c4e2f3b9a6c8d5e1f4b3c7a2e8f6a1d8c4e2f3b9a6c8d5e1f4b3c7a2e8f -iv 9f2d4b6e7a3c1f8d5e2f4a9b6c7d3e1f9f2d4b6e7a3c1f8d5e2f4a9b6c7d3e1f
