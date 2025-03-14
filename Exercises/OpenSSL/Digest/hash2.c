#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

int main(int argc, char **argv){

    if(argc != 2){
        fprintf(stderr, "Invalid parameters num. Usage: %s string to hash\n", argv[0]);
        exit(-1);
    }

    EVP_MD_CTX *md;

    md  = EVP_MD_CTX_new();

    EVP_DigestInit(md, EVP_sha1());

    EVP_DigestUpdate(md, argv[1], strlen(argv[1]));

    // 20 bytes for SHA1
    unsigned char md_value[EVP_MD_size(EVP_sha1())];
    int md_len;

    EVP_DigestFinal(md, md_value, &md_len);

    EVP_MD_CTX_free(md);

    printf("Digest is: ");
    for(int i = 0; i < md_len; i++)
        printf("%02x", md_value[i]);
    printf("\n");

    return 0;

}
