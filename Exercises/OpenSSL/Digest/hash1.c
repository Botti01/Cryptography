#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

int main(){

    char message[] = "This is the message to hash!!!";

    EVP_MD_CTX *md;

    md  = EVP_MD_CTX_new();

    EVP_DigestInit(md, EVP_sha1());

    EVP_DigestUpdate(md, message, strlen(message));

    // variable memory to store the hash value
    // 20 bytes for SHA1
    unsigned char md_value[20];
    // variable to store the length of the hash value
    int md_len;

    EVP_DigestFinal(md, md_value, &md_len);

    EVP_MD_CTX_free(md);

    printf("Digest is: ");
    for(int i = 0; i < md_len; i++)
        printf("%02x", md_value[i]);
    printf("\n");

    return 0;

}


// check that the hash value is correct
// openssl dgst -sha1 input.txt