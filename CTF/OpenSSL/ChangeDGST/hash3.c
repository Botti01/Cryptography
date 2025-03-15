/*
Starting from the file hash3.c, change the code to compute the SHA256.

After having modified it, compute the hash of the modified file (do not add any space, newlines, just do the minimum number of changes),

The flag will be "CRYPTO25{" + hex(SHA256digest(new_file) + "}" where newfile is the hash3.c after the modifications and hex() is the function 
that represents the binary digest as a string of hex digits.


*/


#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#define MAXBUF 1024

int main(int argc, char **argv){
       
      
        if(argc != 2){
            fprintf(stderr,"Invalid parameters. Usage: %s filename\n",argv[0]);
            exit(1);
        }


        FILE *f_in;
        if((f_in = fopen(argv[1],"r")) == NULL) {
                fprintf(stderr,"Couldn't open the input file, try again\n");
                exit(1);
        }


       //EVP_MD_CTX *EVP_MD_CTX_new(void);
		EVP_MD_CTX *md = EVP_MD_CTX_new();

        //int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
        // int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
        EVP_DigestInit(md, EVP_sha256());

        int n;
        unsigned char buffer[MAXBUF];
        while((n = fread(buffer,1,MAXBUF,f_in)) > 0){
            EVP_DigestUpdate(md, buffer, n);
        }

        unsigned char md_value[EVP_MD_size(EVP_sha256())];
        int md_len;

        //int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
        EVP_DigestFinal_ex(md, md_value, &md_len);

        // void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
		EVP_MD_CTX_free(md);

        printf("The digest is: ");
        for(int i = 0; i < md_len; i++)
			     printf("%02x", md_value[i]);
        printf("\n");

	return 0;

}


// Flag: CRYPTO25{cf5c2b2a17c55a6986156b993e4ab3f2a261b85dff5591c62e0caaf9e4808975}