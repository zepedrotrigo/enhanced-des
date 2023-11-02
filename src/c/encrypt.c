#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>
#include "edes.h"

void encrypt_des(uint8_t *ciphertext, const char *key, uint8_t *plaintext, int plaintext_len) {
    DES_key_schedule schedule;
    DES_set_key_unchecked((const_DES_cblock *)key, &schedule);
    DES_cblock padded_data[plaintext_len + 8];
    int padded_len = (plaintext_len + 7) / 8 * 8;
    pkcs7_pad(padded_data, plaintext, plaintext_len, 8);
    DES_ecb_encrypt((const_DES_cblock *)padded_data, (DES_cblock *)ciphertext, &schedule, DES_ENCRYPT);
}

void print_hex_string(const uint8_t *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s \"password\" <mode>\nExample: %s \"rkDAHX6yG9TzwLuL7HLkuMUdXrVN6q92\" --e-des\n", argv[0], argv[0]);
        exit(1);
    }

    char *password = argv[1];
    char *mode = argv[2];
    printf("> ");
    char plaintext[256];
    fgets(plaintext, sizeof(plaintext), stdin);
    int plaintext_len = strlen(plaintext) - 1; // Exclude newline character

    int ciphertext_len = (plaintext_len + 8 - 1) / 8 * 8;
    uint8_t ciphertext[ciphertext_len];

    if (strcmp(mode, "--des") == 0) {
        encrypt_des(ciphertext, password, (uint8_t *)plaintext, plaintext_len);
    } else {
        edes_encrypt(ciphertext, password, (uint8_t *)plaintext, plaintext_len);
    }

    print_hex_string(ciphertext, ciphertext_len);
    return 0;
}