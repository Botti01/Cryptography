#include <stdio.h>
#include <openssl/rand.h>

#define MAX 64

int main(){
    unsigned char random_string[MAX];

    if(RAND_load_file("/dev/random", 64) != 64)
        fprintf(stderr,"Error with rand init\n");

    if(!RAND_bytes(random_string,MAX))
        fprintf(stderr,"Error with rand generation\n");


    printf("Sequence generated: ");
    for (int i = 0; i < MAX; i++){
        printf("%02x", random_string[i]);      // Print the random string in hexadecimal format with a dash between each byte
        if (i < MAX - 1) {
            printf("-");            // Add hyphen only between bytes, not at the end
        }
    }
    printf("\n");

    return 0;

}