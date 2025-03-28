/*

Given the following 4 hexstring representation of integer numbers:
- a = 0x11111111111111111111111111111111
- b  = 0x22222222222222222222222222222222
- c = 0x3333
- d = 0x2341234123412341234

What is the result of

 (a+b) ^ c (mod d)  ?

Write the program in C using OpenSSL BIGNUMs.

*/

#include <stdio.h>
#include <openssl/bn.h>

int main() {
    char a[] = "11111111111111111111111111111111";
    char b[] = "22222222222222222222222222222222";
    char c[] = "3333";
    char d[] = "2341234123412341234";

    BIGNUM *bn_a = BN_new();
    BIGNUM *bn_b = BN_new();
    BIGNUM *bn_c = BN_new();
    BIGNUM *bn_d = BN_new();
    BIGNUM *bn_sum = BN_new();
    BIGNUM *bn_result = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    // Convert hex strings to BIGNUMs
    BN_hex2bn(&bn_a, a);
    BN_hex2bn(&bn_b, b);
    BN_hex2bn(&bn_c, c);
    BN_hex2bn(&bn_d, d);

    // Perform (a + b)
    BN_add(bn_sum, bn_a, bn_b);

    // Perform (a + b) ^ c (mod d)
    BN_mod_exp(bn_result, bn_sum, bn_c, bn_d, ctx);

    // Print the result
    printf("Result = %s\n", BN_bn2hex(bn_result));

    // Free allocated memory
    BN_free(bn_a);
    BN_free(bn_b);
    BN_free(bn_c);
    BN_free(bn_d);
    BN_free(bn_sum);
    BN_free(bn_result);
    BN_CTX_free(ctx);

    return 0;
}