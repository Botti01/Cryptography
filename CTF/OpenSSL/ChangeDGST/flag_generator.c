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
