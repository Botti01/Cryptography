/*

Starting from the file hash3.c, change the code to compute the SHA256.

After having modified it, compute the hash of the modified file (do not add any space, newlines, just do the minimum number of changes),

The flag will be "CRYPTO25{" + hex(SHA256digest(new_file) + "}" where newfile is the hash3.c after the modifications and hex() is the function 
that represents the binary digest as a string of hex digits.


*/


#include <stdio.h>
#include <string.h>

int main() {
    char prefix[] = "CRYPTO25{";
    char hash[] = "cf5c2b2a17c55a6986156b993e4ab3f2a261b85dff5591c62e0caaf9e4808975";
    char suffix[] = "}";

    char flag[100];  
    snprintf(flag, sizeof(flag), "%s%s%s", prefix, hash, suffix);

    printf("Flag: %s\n", flag);

    return 0;
}



// Flag: CRYPTO25{cf5c2b2a17c55a6986156b993e4ab3f2a261b85dff5591c62e0caaf9e4808975}