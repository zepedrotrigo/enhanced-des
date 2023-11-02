#include "edes.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

#define BLOCK_SIZE 8
#define KEY_SIZE 32


typedef struct {
    unsigned long state;
} LCG;

unsigned int lcg_next(LCG *lcg) {
    lcg->state = (lcg->state * 1103515245 + 12345) & 0x7FFFFFFF;
    return lcg->state;
}


void generate_sboxes(uint8_t sboxes[SBOX_COUNT][SBOX_SIZE], const char *key) {
    // Seed RNG with key
    unsigned long long seed = 0;
    for(int i = 0; i < KEY_SIZE; i++)
        seed = ((seed << 5) | (seed >> (64-5))) ^ key[i];

    LCG prng = {seed};

    // Generate 16 S-Boxes
    for(int i = 0; i < SBOX_COUNT; i++) {
        // Generate a permutation of 0 to 255
        for(int j = 0; j < SBOX_SIZE; j++)
            sboxes[i][j] = lcg_next(&prng) % 256;

        // Ensure 16 zeros across all S-Boxes
        int zero_count = 0;
        for(int j = 0; j < SBOX_SIZE; j++) {
            if(sboxes[i][j] == 0) {
                zero_count++;
                if(zero_count > 1) {
                    // Replace extra zeros with missing values
                    int replacement = 1;
                    while(1) {
                        int found = 0;
                        for(int k = 0; k < SBOX_SIZE; k++) {
                            if(sboxes[i][k] == replacement) {
                                found = 1;
                                break;
                            }
                        }
                        if(!found) break;
                        replacement++;
                    }
                    sboxes[i][j] = replacement;
                }
            }
        }
    }
}


void feistel_function(uint8_t *out, uint8_t sbox[SBOX_SIZE], uint8_t *input_block) {
    int index = input_block[3];
    out[0] = sbox[index];
    index = (index + input_block[2]) % SBOX_SIZE;
    out[1] = sbox[index];
    index = (index + input_block[1]) % SBOX_SIZE;
    out[2] = sbox[index];
    index = (index + input_block[0]) % SBOX_SIZE;
    out[3] = sbox[index];
}


void edes_encrypt_block(uint8_t *ciphertext_block, uint8_t *plaintext_block, uint8_t sboxes[SBOX_COUNT][SBOX_SIZE]) {
    uint8_t L[BLOCK_SIZE / 2], R[BLOCK_SIZE / 2], temp[BLOCK_SIZE / 2];

    // Split block into L and R
    memcpy(L, plaintext_block, BLOCK_SIZE / 2);
    memcpy(R, plaintext_block + BLOCK_SIZE / 2, BLOCK_SIZE / 2);

    // 16 rounds of Feistel Network
    for(int i = 0; i < SBOX_COUNT; i++) {
        feistel_function(temp, sboxes[i], R);
        for(int j = 0; j < BLOCK_SIZE / 2; j++) {
            temp[j] = L[j] ^ temp[j];
        }
        memcpy(L, R, BLOCK_SIZE / 2);
        memcpy(R, temp, BLOCK_SIZE / 2);
    }

    // Combine R and L
    memcpy(ciphertext_block, R, BLOCK_SIZE / 2);
    memcpy(ciphertext_block + BLOCK_SIZE / 2, L, BLOCK_SIZE / 2);
}


void edes_decrypt_block(uint8_t *plaintext_block, uint8_t *ciphertext_block, uint8_t sboxes[SBOX_COUNT][SBOX_SIZE]) {
    uint8_t L[BLOCK_SIZE / 2], R[BLOCK_SIZE / 2], temp[BLOCK_SIZE / 2];

    // Split block into L and R
    memcpy(L, ciphertext_block, BLOCK_SIZE / 2);
    memcpy(R, ciphertext_block + BLOCK_SIZE / 2, BLOCK_SIZE / 2);

    // 16 rounds of Feistel Network in reverse
    for(int i = SBOX_COUNT - 1; i >= 0; i--) {
        feistel_function(temp, sboxes[i], R);
        for(int j = 0; j < BLOCK_SIZE / 2; j++) {
            temp[j] = L[j] ^ temp[j];
        }
        memcpy(L, R, BLOCK_SIZE / 2);
        memcpy(R, temp, BLOCK_SIZE / 2);
    }

    // Combine R and L
    memcpy(plaintext_block, R, BLOCK_SIZE / 2);
    memcpy(plaintext_block + BLOCK_SIZE / 2, L, BLOCK_SIZE / 2);
}


void pkcs7_pad(uint8_t *padded_data, uint8_t *data, int data_len, int block_size) {
    int padding_length = block_size - (data_len % block_size);
    memcpy(padded_data, data, data_len);
    memset(padded_data + data_len, padding_length, padding_length);
}


int pkcs7_unpad(uint8_t *unpadded_data, uint8_t *data, int data_len) {
    int padding_length = data[data_len - 1];
    memcpy(unpadded_data, data, data_len - padding_length);
    return data_len - padding_length;
}


void edes_encrypt(uint8_t *ciphertext, uint8_t sboxes[SBOX_COUNT][SBOX_SIZE], uint8_t *plaintext, int plaintext_len) {
    int padded_len = (plaintext_len + BLOCK_SIZE - 1) / BLOCK_SIZE * BLOCK_SIZE;
    uint8_t padded_data[padded_len];
    pkcs7_pad(padded_data, plaintext, plaintext_len, BLOCK_SIZE);

    // Encrypt each block using ECB mode
    for(int i = 0; i < padded_len; i += BLOCK_SIZE)
        edes_encrypt_block(ciphertext + i, padded_data + i, sboxes);
}


int edes_decrypt(uint8_t *plaintext, uint8_t sboxes[SBOX_COUNT][SBOX_SIZE], uint8_t *ciphertext, int ciphertext_len) {
    uint8_t unpadded_data[ciphertext_len];

    // Decrypt each block using ECB mode
    for(int i = 0; i < ciphertext_len; i += BLOCK_SIZE)
        edes_decrypt_block(unpadded_data + i, ciphertext + i, sboxes);

    return pkcs7_unpad(plaintext, unpadded_data, ciphertext_len);
}


// DES functions for comparison
void encrypt_des(uint8_t *ciphertext, const char *key, uint8_t *plaintext, int plaintext_len) {
    DES_key_schedule schedule;
    DES_set_key_unchecked((const_DES_cblock *)key, &schedule);
    DES_cblock padded_data[plaintext_len + 8];
    int padded_len = (plaintext_len + 7) / 8 * 8;
    pkcs7_pad(padded_data, plaintext, plaintext_len, 8);
    DES_ecb_encrypt((const_DES_cblock *)padded_data, (DES_cblock *)ciphertext, &schedule, DES_ENCRYPT);
}

void decrypt_des(uint8_t *plaintext, const char *key, uint8_t *ciphertext, int ciphertext_len) {
    DES_key_schedule schedule;
    DES_set_key_unchecked((const_DES_cblock *)key, &schedule);
    uint8_t unpadded_data[ciphertext_len];
    DES_ecb_encrypt((const_DES_cblock *)ciphertext, (DES_cblock *)unpadded_data, &schedule, DES_DECRYPT);
    int plaintext_len = pkcs7_unpad(plaintext, unpadded_data, ciphertext_len);
    plaintext[plaintext_len] = '\0';
}