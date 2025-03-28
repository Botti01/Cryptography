/*

Starting from the C source file encrypt.c, change it so that:
- the key is the string "012340123401234012340123401234012340123401234012"
- the IV is the string "ABCDEFABCDEFABCDEFABCDEFABCDEFAB"
- the encryption algorithm is Camellia192 in CBC mode

Now run the command

echo "2025-03-28 CLASS" | ./encrypt.exe | base64  

*/



#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>


#define ENCRYPT 1
#define DECRYPT 0
#define MAX_BUFFER 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv)
{

    char key_str[] = "012340123401234012340123401234012340123401234012";
    char iv_str[]  = "ABCDEFABCDEFABCDEFABCDEFABCDEFAB";
    unsigned char iv[] = "ABCDEFABCDEFABCDEFABCDEFABCDEFAB";
    unsigned char key[] = "012340123401234012340123401234012340123401234012";

    for(int i = 0; i < strlen(key_str)/2;i++){
       sscanf(&key_str[2*i],"%2hhx", &key[i]);
    }
    for(int i = 0; i < strlen(iv_str)/2;i++){
       sscanf(&iv_str[2*i],"%2hhx", &iv[i]);
    }

    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if(!EVP_CipherInit(ctx, EVP_camellia_192_cbc(), key, iv,ENCRYPT))
        handle_errors();

    int length;
    unsigned char ciphertext[MAX_BUFFER+16];

    int n_read;
    unsigned char buffer[MAX_BUFFER];

    while((n_read = fread(buffer,1,MAX_BUFFER,stdin)) > 0){
        if(!EVP_CipherUpdate(ctx,ciphertext,&length,buffer,n_read))
            handle_errors();
        
        fwrite(ciphertext, 1, length,stdout);
    }
            
    if(!EVP_CipherFinal(ctx,ciphertext,&length))
        handle_errors();

 
    fwrite(ciphertext,1, length, stdout);
    
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

