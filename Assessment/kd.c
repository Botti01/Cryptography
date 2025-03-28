/*

Starting from the template file kd.c, write a program that 

- uses as secret the string "key4keyeddigest"
- uses SHA3 384 as digest algorithm

Call it now this way
echo "2025-03-28 CLASS" | ./kd.exe

*/

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#define MAXBUF 1024

int main(int argc, char **argv){
      
		EVP_MD_CTX *md = EVP_MD_CTX_new();
        EVP_DigestInit(md, EVP_sha3_384());

        int n;
        unsigned char secret[] = "key4keyeddigest";
        unsigned char buffer[MAXBUF];
        EVP_DigestUpdate(md, secret, strlen(secret));
        while((n = fread(buffer,1,MAXBUF,stdin)) > 0){
            EVP_DigestUpdate(md, buffer, n);
        }
        EVP_DigestUpdate(md, secret, strlen(secret));


        unsigned char md_value[EVP_MD_size(EVP_sha3_384())];
        int md_len;

        EVP_DigestFinal_ex(md, md_value, &md_len);
		EVP_MD_CTX_free(md);

        printf("The digest is: ");
        for(int i = 0; i < md_len; i++)
			     printf("%02x", md_value[i]);
        printf("\n");

	return 0;

}