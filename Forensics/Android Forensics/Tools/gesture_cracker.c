/*
gcc -o gesture_cracker gesture_cracker.c -lcrypto
*/

#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

unsigned char hash[SHA_DIGEST_LENGTH];


void try_permutations(unsigned char target_hash[], char arr[], int n, int l, int index, char data[])
{
    if (index == l) {

        // Try the current permutation
        SHA1(data, l, hash);

        // Check if the hash matches
        int match = 1;

        for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
            if (hash[i] != target_hash[i]) {
                match = 0;
                break;
            }
        }

        // Print the result
        if (match) {
            printf("Found a match: ");
            for (int i = 0; i < 9; i++) {
                printf("%c", data[i] + '0');
            }
            printf("\n");
        }
    }
    else {
        // Compute the list of used values in data[0:index]
        char used[n];
        memset(used, 0, n);
        for (int i = 0; i < index; i++) {
            used[data[i]] = 1;
        }

        // Try all possible values after the current index
        for (int i = 0; i < n; i++) {
            if (!used[i]) {
                data[index] = arr[i];
                try_permutations(target_hash, arr, n, l, index + 1, data);
            }
        }
    }
}

int main(int argc, char const *argv[]) {

    // Check for argument
    if (argc < 2) {
        printf("Usage: %s <hash>\n", argv[0]);
        printf("The hash is the content of android/data/system/gesture.key as a string of hex values\n");
        return 1;
    }

    // Read the argument to a buffer
    int gesture_len = strlen(argv[1]);

    // Convert the hex string to bytes
    unsigned char target_hash[gesture_len / 2];
    for (int i = 0; i < gesture_len; i += 2) {
        sscanf(argv[1] + i, "%2hhx", &target_hash[i / 2]);
    }

    // Print the input hash
    printf("Input hash: ");
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        printf("%02x", target_hash[i]);
    }
    printf("\n");

    // Define the possible values
    char gesture_chars[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09";

    // Iterate over all possible lengths
    for (int l = 2; l <10; l++) {

        // Iterate over all possible permutations of gesture_chars
        char data[l];
        try_permutations(target_hash, gesture_chars, 10, l, 0, data);
    }
    return 0;
}
