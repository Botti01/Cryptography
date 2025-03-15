#include <stdio.h>

#
#include <openssl/bn.h>
#include <openssl/err.h>

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(){

    ERR_load_crypto_strings();

    char num_string[] = "1234512345123451234512345123451234512346";
    char hex_string[] = "3A0BE6DE14A23197B6FE071D5EBBD6DD9";

    BIGNUM *prime1 = BN_new();
    BIGNUM *prime2 = BN_new();

    // BN_generate_prime_ex2() + context

    // int BN_generate_prime_ex(BIGNUM *ret, int bits, int safe, const BIGNUM *add, 
    //                                  const BIGNUM *rem, BN_GENCB *cb);
    // result, num of minimun lenght in bits, safe prime, add, rem, callback
    // safe prime: (p-1)/2 is prime
    // add, rem -->?   p %(modulous) add == rem
    // if rem is NULL --> rem = 1
    // if rem is NULL and safe is true --> rem = 3 add must be multiple of 4
    // callback is a function that is called when the generation is in progress
    // BN_GENCB is a structure that contains the callback function
    if(!BN_generate_prime_ex(prime1, 1024, 0, NULL, NULL, NULL))
        handle_errors();

    
    BN_print_fp(stdout, prime1);
    puts("");

    // the number, number of checks, callback, ctx
    // number of checks: number of times that the number is checked
    if(BN_is_prime_ex(prime1, 16, NULL, NULL))
        printf("prime1 is prime\n");
    else
        printf("prime1 is not prime\n");
    // BN_check_prime(prime1, ctx, cb)
    // BN_CTX *ctx = BN_CTX_new();
    // if(BN_check_prime(prime1, ctx, NULL) == 1)

    

    BN_set_word(prime2, 16);
    
    if(BN_is_prime_ex(prime2, 16, NULL, NULL))
        printf("prime2 is prime\n");
    else
        printf("prime2 is not prime\n");


    printf("Bytes prime1: %d\n", BN_num_bytes(prime1));
    printf("Bytes prime2: %d\n", BN_num_bytes(prime2));
    printf("Bits prime1: %d\n", BN_num_bits(prime1));
    printf("Bits prime2: %d\n", BN_num_bits(prime2));


    BN_free(prime1);
    BN_free(prime2);
    // BN_CTX_free(ctx);


    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;

}