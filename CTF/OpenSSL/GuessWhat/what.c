/*

You have found these data

00:9e:ee:82:dc:2c:d4:a0:0c:4f:5a:7b:86:63:b0:c1:ed:06:77:fc:eb:de:1a:23:5d:f4:c3:ff:87:6a:7d:ad:c6:07:fa:a8:35:f6:
ae:05:03:57:3e:22:36:76:d5:0d:57:4f:99:f9:58:ad:63:7a:e7:45:a6:aa:fa:02:34:23:b6:9d:34:15:7b:11:41:b6:b1:ca:b9:1a:
cd:29:55:bd:42:f5:04:ab:df:45:4a:9d:4e:ca:4e:01:f9:f8:74:59:67:ee:b6:a9:fb:96:b7:c0:94:00:17:8a:53:0e:b6:d8:31:c9:
68:e6:64:38:d3:63:3a:04:d7:88:6b:f0:e1:ad:60:7f:41:bd:85:7b:d9:04:e1:97:5b:1f:9b:05:ce:ac:2c:c4:55:3f:b4:8b:89:4d:
0a:50:9a:09:4e:5e:8f:5b:5f:55:69:72:5f:04:9b:3a:8a:09:b4:7f:8d:b2:ca:52:0e:5e:bf:f4:b0:ee:c9:ba:dc:93:4f:6d:d3:1f:
82:1a:d9:fc:2c:a7:3f:18:23:0d:d7:44:c7:28:54:67:84:ee:73:92:65:f0:1c:e8:1e:6d:4d:95:65:b4:c8:4f:b8:04:62:58:2b:ee:
32:64:a0:a7:dc:99:25:0e:50:53:76:bc:30:db:71:5e:93:d6:9f:1f:88:1c:76:5d:82:c8:59:39:51

00:d2:c6:01:32:6b:4c:4b:85:5f:52:7b:b7:8e:d6:8a:e4:c8:76:7e:6b:c9:24:9a:3e:ca:cd:2f:c9:b8:75:d4:f9:71:11:e1:cf:be:
62:d3:2c:5f:f9:fd:9b:fa:ed:62:f3:df:44:c7:57:fb:ee:9b:b2:32:cb:54:49:29:6c:69:2e:30:1d:8c:1f:fa:b1:8e:e4:49:66:c1:
fb:92:7c:82:ca:60:c9:40:a4:0a:b2:db:50:ec:f6:ff:98:a7:16:23:38:8d:06:d2:7c:a9:85:8a:c2:2b:4d:d4:e6:f1:89:e5:b0:42:
54:a0:5f:3c:dd:c7:64:33:05:11:fb:ee:8b:26:07

Find the other missing parameter using BIGNUM primitives (you may have to manipulate these data a bit before).

Use the same representation (with a ':' every two digits). Surround it with CRYPTO25{} to have your flag.
Add leading zeros if needed to equalize parameters...

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>     // Saving the data in output into the file, RSA_print_fp


void handle_errors(void){
    ERR_print_errors_fp(stderr);
    abort();
}

/*

The statement give us two BIGNUMs and we have to find the third one. Two numbers have different lengths,
so could be the RSA modulus and one of the prime factors. The third number should be the other prime factor.
To find it, we can divide the modulus by the known prime factor.
Let assume that N = p * q, where p is the known prime factor and q is the unknown prime factor.
Then q = N / p.

*/


// Function to remove colons and return a clean hex string
void remove_colons(const char *input, char *output) {
    while (*input) {
        if (*input != ':') {
            *output++ = *input;
        }
        input++;
    }
    *output = '\0';
}


// Function to insert colons every two characters in a hex string to print
void insert_colons(const char *hex_str, char *output) {
    size_t len = strlen(hex_str);
    size_t j = 0;
    for (size_t i = 0; i < len; i += 2) {
        if (i > 0)
            output[j++] = ':';
        output[j++] = hex_str[i];
        output[j++] = hex_str[i+1];
    }
    output[j] = '\0';
}

// Function to convert a string to lowercase
void str_to_lower(char *str) {
    for (; *str; str++) {
        *str = tolower(*str);
    }
}


int main(){

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();


    unsigned char str1[] =  "00:9e:ee:82:dc:2c:d4:a0:0c:4f:5a:7b:86:63:b0:c1:ed:06:77:fc:eb:de:1a:23:5d:f4:c3:ff:87:6a:7d:ad:c6:07:fa:a8:35:f6:"
                            "ae:05:03:57:3e:22:36:76:d5:0d:57:4f:99:f9:58:ad:63:7a:e7:45:a6:aa:fa:02:34:23:b6:9d:34:15:7b:11:41:b6:b1:ca:b9:1a:"
                            "cd:29:55:bd:42:f5:04:ab:df:45:4a:9d:4e:ca:4e:01:f9:f8:74:59:67:ee:b6:a9:fb:96:b7:c0:94:00:17:8a:53:0e:b6:d8:31:c9:"
                            "68:e6:64:38:d3:63:3a:04:d7:88:6b:f0:e1:ad:60:7f:41:bd:85:7b:d9:04:e1:97:5b:1f:9b:05:ce:ac:2c:c4:55:3f:b4:8b:89:4d:"
                            "0a:50:9a:09:4e:5e:8f:5b:5f:55:69:72:5f:04:9b:3a:8a:09:b4:7f:8d:b2:ca:52:0e:5e:bf:f4:b0:ee:c9:ba:dc:93:4f:6d:d3:1f:"
                            "82:1a:d9:fc:2c:a7:3f:18:23:0d:d7:44:c7:28:54:67:84:ee:73:92:65:f0:1c:e8:1e:6d:4d:95:65:b4:c8:4f:b8:04:62:58:2b:ee:"
                            "32:64:a0:a7:dc:99:25:0e:50:53:76:bc:30:db:71:5e:93:d6:9f:1f:88:1c:76:5d:82:c8:59:39:51";

    unsigned char str2[] =  "00:d2:c6:01:32:6b:4c:4b:85:5f:52:7b:b7:8e:d6:8a:e4:c8:76:7e:6b:c9:24:9a:3e:ca:cd:2f:c9:b8:75:d4:f9:71:11:e1:cf:be:"
                            "62:d3:2c:5f:f9:fd:9b:fa:ed:62:f3:df:44:c7:57:fb:ee:9b:b2:32:cb:54:49:29:6c:69:2e:30:1d:8c:1f:fa:b1:8e:e4:49:66:c1:"
                            "fb:92:7c:82:ca:60:c9:40:a4:0a:b2:db:50:ec:f6:ff:98:a7:16:23:38:8d:06:d2:7c:a9:85:8a:c2:2b:4d:d4:e6:f1:89:e5:b0:42:"
                            "54:a0:5f:3c:dd:c7:64:33:05:11:fb:ee:8b:26:07";


    // Remove colons and store the cleaned hex strings
    char N_hex[strlen(str1) + 1];
    char p_hex[strlen(str2) + 1];

    remove_colons(str1, N_hex);
    // printf("N_hex: %s\n\n", N_hex);
    remove_colons(str2, p_hex);
    // printf("p_hex: %s\n\n", p_hex);


    // Initialize BIGNUM variables
    BIGNUM *N = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BN_CTX *ctx = BN_CTX_new();  // Context for calculations


    if (!N || !p || !q || !ctx) 
        handle_errors();


    // Convert hex strings to BIGNUM
    if (!BN_hex2bn(&N, N_hex) || !BN_hex2bn(&p, p_hex)) 
        handle_errors();

    // Compute q = N / p
    if (!BN_div(q, NULL, N, p, ctx)) 
        handle_errors();

    // Convert q to a hex string
    char *q_hex = BN_bn2hex(q);
    if (!q_hex)
        handle_errors();

    // Check lengths of p_hex and q_hex
    size_t p_len = strlen(p_hex);
    size_t q_len = strlen(q_hex);

    // Convert q_hex to lowercase
    str_to_lower(q_hex);

    // in RSA the two prime factors should have the same length
    // If lengths are not equal, add leading zeros to q_hex
    if (q_len < p_len) {
        size_t diff = p_len - q_len;
        // Shift q_hex to the right and add leading zeros
        memmove(q_hex + diff, q_hex, q_len + 1); // +1 to include the null terminator
        memset(q_hex, '0', diff);
    }

    // Print the computed q with colons
    char q_colon[strlen(q_hex) * 2];
    insert_colons(q_hex, q_colon);
    printf("\nCRYPTO25{%s}\n", q_colon);

    // Free the allocated memory
    OPENSSL_free(q_hex);

    // Free BIGNUM structures
    BN_free(N);
    BN_free(p);
    BN_free(q);
    BN_CTX_free(ctx);


    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;

}



// Flag: CRYPTO25{00:c1:08:c9:57:09:e0:73:72:7d:b4:5e:4b:4b:20:bf:3c:57:41:bf:5c:bc:14:4d:a6:6a:bd:4d:86:69:06:9f:73:9d:40:2c:60:0f:29:7b:0b:4c:c7:7b:f6:5e:e5:a6:10:02:71:3e:74:a5:ac:b9:7f:f3:c5:78:42:ca:fe:50:6f:5b:1b:df:c7:ee:36:20:bb:56:73:ab:11:fa:e2:bf:a8:69:7d:e6:f4:5c:27:c1:21:69:3c:0e:1d:2d:dd:70:25:11:57:9f:8a:5a:60:58:09:90:5c:54:e0:55:2a:55:1c:e1:36:9d:14:70:ab:b4:e2:ce:c4:92:6b:fa:14:8f:e7}