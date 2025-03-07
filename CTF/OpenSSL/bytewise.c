#include <stdio.h>

#include <openssl/rand.h>
#include <openssl/err.h>

#define MAX 64

void hex_to_bytes(const char *hex, unsigned char *bytes){
    // Loop through the hex string and convert each pair of hex digits to a byte
    for (int i=0; i<MAX; i++){
        sscanf(hex, "%2hhx", &bytes[i]);
        hex += 3;           // Move the pointer to the next pair of hex digits (skip 2 hex digits and a hyphen)
    }
}

int main (){

    const char *hex_rand1 = "ed-8a-3b-e8-17-68-38-78-f6-b1-77-3e-73-b3-f7-97-f3-00-47-76-54-ee-8d-51-0a-2f-10-79-17-f8-ea-d8-81-83-6e-0f-0c-b8-49-5a-77-ef-2d-62-b6-5e-e2-10-69-d6-cc-d6-a0-77-a2-0a-d3-f7-9f-a7-9e-a7-c9-08";
    const char *hex_rand2 = "4c-75-82-ca-02-07-bd-1d-8d-52-f0-6c-7a-d6-b7-87-83-95-06-2f-e0-f7-d4-24-f8-03-68-97-41-4c-85-29-e5-0d-b0-e4-3c-ee-74-dc-18-8a-aa-26-f0-46-94-e8-52-91-4a-43-8f-dd-ea-bb-a8-cf-51-14-79-ec-17-c2";

    unsigned char rand1[MAX], rand2[MAX];
    unsigned char k1[MAX], k2[MAX], key[MAX];

    hex_to_bytes(hex_rand1, rand1);
    hex_to_bytes(hex_rand2, rand2);

    for (int i=0; i<MAX; i++){
        k1[i] = rand1[i] | rand2[i];
        k2[i] = rand1[i] & rand2[i];
        key[i] = k1[i] ^ k2[i];
    }

    printf("Key: ");
    for (int i=0; i<MAX; i++){
        printf("%02x", key[i]);
        if (i < MAX - 1) {
            printf("-");            // Add hyphen only between bytes, not at the end
        }
    }
    printf("\n");

}