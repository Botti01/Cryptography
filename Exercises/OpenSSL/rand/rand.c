#include <stdio.h>

#include <openssl/rand.h>
#include <openssl/err.h>            // Error handling

#define MAX 128                // Maximum number of bytes to generate in the random string

void handle_errors(){
    ERR_print_errors_fp(stderr);        // Print the error stack to the standard error
    abort();                            // Abort the program
}

int main(){

    unsigned char random_string[MAX];       // Random string to store the random bytes

    if (!RAND_poll())               // Check if the PRNG has been seeded with enough randomness
        handle_errors();

    if (RAND_load_file("/dev/urandom", 64) != 64)       // initialize the PRNG with the random seed from /dev/urandom
        handle_errors();
        // fprintf(stderr, "Error with the initialization of the PRNG\n");

    // RAND_load_file("/dev/random", 64);          // Load the random seed from /dev/random
    // RAND_bytes(random_string, MAX);             // Generate a random string of 128 bytes
    
    // RAND_bytes() and RAND_priv_bytes() return 1 on success, -1 if not supported by the current RAND method, or 0 on other failure.
    if (RAND_bytes(random_string, MAX) != 1)        
        handle_errors();
        // fprintf(stderr, "Error generating the random string\n");

    printf("Sequence generated:\n");
    for (int i = 0; i < MAX; i++)
        printf("%02x-", random_string[i]);      // Print the random string in hexadecimal format with a dash between each byte
    printf("\n");

    return 0;

}
