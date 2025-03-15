/*
Write a program in C that, using the OpenSSL library, encrypts the content of a file using a user-selected algorithm.

The input filename is passed as first parameter from the command line, key and IV are the second and third parameter, the output 
file is the fourth parameter, the algorithm is the last parameter.

The algorithm name must be an OpenSSL-compliant string (e.g., aes-128-cbc or aes-256-ecb). (In short, you have to extend enc4.c)

Look for the proper function here https://www.openssl.org/docs/man3.1/man3/EVP_EncryptInit.html

In doing the exercise you have found a very relevant function, build the flag as "CRYPTO25{" + relevantFunctionName + "}"
*/


#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>


#define ENCRYPT 1
#define DECRYPT 0
#define MAX_BUFFER 1024

// argv[1]: input file
// argv[2]: key (hexadecimalstring)
// argv[3]: iv (hexadecimalstring)
// argv[4]: output file
// argv[5]: algorithm

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv)
{

//  int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv, int enc);
//  int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
//  int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

    if(argc != 6){
        fprintf(stderr,"Invalid parameters. Usage: %s file_in key iv file_out algorithm\n",argv[0]);
        exit(1);
    }


    FILE *f_in;
    if((f_in = fopen(argv[1],"r")) == NULL) {
            fprintf(stderr,"Couldn't open the input file, try again\n");
            abort();
    }
 
    if(strlen(argv[2])!=32){
        fprintf(stderr,"Wrong key length\n");
        abort();
    }   
    if(strlen(argv[3])!=32){
        fprintf(stderr,"Wrong IV length\n");
        abort();
    }
    
    // wb: write binary
    FILE *f_out;
    if((f_out = fopen(argv[4],"wb")) == NULL) {
            fprintf(stderr,"Couldn't open the output file, try again\n");
            abort();
    }

    unsigned char key[strlen(argv[2])/2];
    for(int i = 0; i < strlen(argv[2])/2;i++){
        sscanf(&argv[2][2*i],"%2hhx", &key[i]);
    }

    unsigned char iv[strlen(argv[3])/2];
    for(int i = 0; i < strlen(argv[3])/2;i++){
        sscanf(&argv[3][2*i],"%2hhx", &iv[i]);
    }

    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms(); // deprecated since version 1.1.1


    /*

    EVP_get_cipherbyname(), EVP_get_cipherbynid() and EVP_get_cipherbyobj()
    Returns an EVP_CIPHER structure when passed a cipher name, a cipher NID or an ASN1_OBJECT structure respectively.
    
    EVP_get_cipherbyname() will return NULL for algorithms such as "AES-128-SIV", "AES-128-CBC-CTS" and "CAMELLIA-128-CBC-CTS" which were previously
    only accessible via low level interfaces.
    
    The EVP_get_cipherbyname() function is present for backwards compatibility with OpenSSL prior to version 3 and is different to the EVP_CIPHER_fetch()
    function since it does not attempt to "fetch" an implementation of the cipher. Additionally, it only knows about ciphers that are built-in to OpenSSL 
    and have an associated NID. Similarly EVP_get_cipherbynid() and EVP_get_cipherbyobj() also return objects without an associated implementation.
    
    When the cipher objects returned by these functions are used (such as in a call to EVP_EncryptInit_ex()) an implementation of the cipher will be 
    implicitly fetched from the loaded providers. This fetch could fail if no suitable implementation is available. Use EVP_CIPHER_fetch() instead to 
    explicitly fetch the algorithm and an associated implementation from a provider.
    
    The cipher objects returned from these functions do not need to be freed with EVP_CIPHER_free().
    
    */

    // Retrieve the cipher based on the provided algorithm name
    // if(!EVP_get_cipherbyname(argv[5])){
    //     fprintf(stderr,"Invalid algorithm\n");
    //     abort();
    // }

    const EVP_CIPHER *cipher = EVP_get_cipherbyname(argv[5]);
    if(!cipher){
        fprintf(stderr, "Invalid algorithm\n");
        abort();
    }

    // pedantic mode: check NULL
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();


    // if(!EVP_CipherInit(ctx, EVP_get_cipherbyname(argv[5]), key, iv, ENCRYPT))
    //     handle_errors();
    if(!EVP_CipherInit(ctx, cipher, key, iv, ENCRYPT))
        handle_errors();
    
    int length;
    unsigned char ciphertext[MAX_BUFFER+16];

    int n_read;
    unsigned char buffer[MAX_BUFFER];

    while((n_read = fread(buffer,1,MAX_BUFFER,f_in)) > 0){
        printf("n_Read=%d-",n_read);
        if(!EVP_CipherUpdate(ctx,ciphertext,&length,buffer,n_read))
            handle_errors();
        printf("length=%d\n",length);
        if(fwrite(ciphertext, 1, length,f_out) < length){
            fprintf(stderr,"Error writing the output file\n");
            abort();
        }
    }
            
    if(!EVP_CipherFinal_ex(ctx,ciphertext,&length))
        handle_errors();

    printf("lenght=%d\n",length);

    if(fwrite(ciphertext,1, length, f_out) < length){
        fprintf(stderr,"Error writing in the output file\n");
        abort();
    }

    EVP_CIPHER_CTX_free(ctx);

    fclose(f_in);
    fclose(f_out);

    printf("File encrypted!\n");


    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();

    return 0;
}



// Flag: CRYPTO25{EVP_get_cipherbyname()}