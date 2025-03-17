#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>     // Saving the data in output into the file, RSA_print_fp


void handle_errors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main(){

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();


    RSA *rsa_keypair;
    BIGNUM *bne = BN_new();
    if(!BN_set_word(bne, RSA_F4))
        handle_errors();

    rsa_keypair = RSA_new();

    if(!RSA_generate_key_ex(rsa_keypair, 2048, bne, NULL))
        handle_errors();

    FILE *rsa_file;
    if( (rsa_file = fopen("private.pem", "w")) == NULL){
        fprintf(stderr, "Problems creating the file\n");
        abort();
    }

    if(!PEM_write_RSAPrivateKey(rsa_file, rsa_keypair, NULL, NULL, 0, NULL, NULL))
        handle_errors();

    fclose(rsa_file);
    
    if( (rsa_file = fopen("public.pem", "w")) == NULL){
        fprintf(stderr, "Problems creating the file\n");
        abort();
    }

    if(!PEM_write_RSAPublicKey(rsa_file, rsa_keypair))
        handle_errors();

    fclose(rsa_file);

    //////////////////////////////////////////
    // Encrypting a message

    unsigned char msg[] = "This is the message to encrypt";
    unsigned char encrypted_msg[RSA_size(rsa_keypair)];
    int encrypted_len;

    // +1 to include the null character
    if ((encrypted_len = RSA_public_encrypt(strlen(msg)+1, msg, encrypted_msg, rsa_keypair, RSA_PKCS1_OAEP_PADDING)) == -1)
        handle_errors();

    FILE *out;
    if( (out = fopen("encrypted.enc", "w")) == NULL){
        fprintf(stderr, "Problems creating the file\n");
        abort();
    }

    if(fwrite(encrypted_msg, 1, encrypted_len, out) < encrypted_len){
        fprintf(stderr, "Problems writing the file\n");
        abort();
    }

    fclose(out);

    printf("File saved\n");

    //////////////////////////////////////////
    // Decrypting the message

    printf("I'm reading the encrypted file...\n");

    // here encrypted_msg can be used again

    FILE *in;
    if( (in = fopen("encrypted.enc", "r")) == NULL){
        fprintf(stderr, "Problems reading the file\n");
        abort();
    }

    if( (encrypted_len = fread(encrypted_msg, 1, RSA_size(rsa_keypair), in)) != RSA_size(rsa_keypair))
        handle_errors();

    fclose(in);

    unsigned char decrypted_msg[RSA_size(rsa_keypair)];
    int decrypted_len;

    if (RSA_private_decrypt(encrypted_len, encrypted_msg, decrypted_msg, rsa_keypair, RSA_PKCS1_OAEP_PADDING) == -1)
        handle_errors();

    printf("\nDecrypted message: %s\n\n", decrypted_msg);



    RSA_free(rsa_keypair);



    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;

}


// To print the content of the encrypted file:
// hexdump encrypted.enc