#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "edes.h"


void hex_string_to_bytes(uint8_t *output, const char *hex_string) {
    int len = strlen(hex_string);
    for (int i = 0; i < len; i += 2) {
        sscanf(hex_string + i, "%2hhx", &output[i / 2]);
    }
}

void bytes_to_hex_string(char *hex_string, const uint8_t *data, int len) {
    for (int i = 0; i < len; i++) {
        sprintf(hex_string + (i * 2), "%02x", data[i]);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s \"password\" <mode>\nExample: %s \"rkDAHX6yG9TzwLuL7HLkuMUdXrVN6q92\" --e-des\n", argv[0], argv[0]);
        exit(1);
    }

    char *password = argv[1];
    char *mode = argv[2];
    printf("> ");
    char hex_ciphertext[256];
    fgets(hex_ciphertext, sizeof(hex_ciphertext), stdin);
    int hex_len = strlen(hex_ciphertext) - 1;  // Exclude newline character

    int ciphertext_len = hex_len / 2;
    uint8_t ciphertext[ciphertext_len];

    hex_string_to_bytes(ciphertext, hex_ciphertext);
    uint8_t plaintext[ciphertext_len];
    uint8_t sboxes[SBOX_COUNT][SBOX_SIZE];

    if (strcmp(mode, "--des") == 0) {
        DES_key_schedule schedule;
        DES_set_key_unchecked((const_DES_cblock *)password, &schedule);
        decrypt_des(plaintext, &schedule, ciphertext, ciphertext_len);
    } else {
        generate_sboxes(sboxes, password);
        int decrypted_len = edes_decrypt(plaintext, sboxes, ciphertext, ciphertext_len);
        plaintext[decrypted_len] = '\0';
    }

    printf("Decrypted: %s\n", plaintext);
    return 0;
}