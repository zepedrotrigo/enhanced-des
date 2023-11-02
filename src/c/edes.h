#ifndef EDES_H
#define EDES_H

#include <stdint.h>

#define SBOX_COUNT 16
#define SBOX_SIZE 256

void pkcs7_pad(uint8_t *padded_data, uint8_t *data, int data_len, int block_size);
int pkcs7_unpad(uint8_t *unpadded_data, uint8_t *data, int data_len);
void edes_encrypt(uint8_t *ciphertext, uint8_t sboxes[SBOX_COUNT][SBOX_SIZE], uint8_t *plaintext, int plaintext_len);
int edes_decrypt(uint8_t *plaintext, uint8_t sboxes[SBOX_COUNT][SBOX_SIZE], uint8_t *ciphertext, int ciphertext_len);

// DES functions for comparison
void encrypt_des(uint8_t *ciphertext, const char *key, uint8_t *plaintext, int plaintext_len);
void decrypt_des(uint8_t *plaintext, const char *key, uint8_t *ciphertext, int ciphertext_len);

#endif // EDES_H