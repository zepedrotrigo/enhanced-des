#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "edes.h"

#define BUFFER_SIZE 4096
#define NUM_ITERATIONS 100000

void generate_random_key(unsigned char *key, int size) {
    FILE *f = fopen("/dev/urandom", "r");
    fread(key, 1, size, f);
    fclose(f);
}

double measure_time(void (*func)(uint8_t *, uint8_t [SBOX_COUNT][SBOX_SIZE], uint8_t *, int), 
                    const char *description, int key_size) {
    unsigned char key[key_size], input[BUFFER_SIZE], output[BUFFER_SIZE];
    uint8_t sboxes[SBOX_COUNT][SBOX_SIZE];
    struct timespec start, end;

    generate_random_key(key, key_size);
    generate_sboxes(sboxes, (const char *)key);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        func(output, sboxes, input, BUFFER_SIZE);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    double time = (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
    printf("%s time: %.3f ns\n", description, time / NUM_ITERATIONS);
    return time;
}

int main() {
    printf("DES:\n");
    double des_encrypt_time = measure_time(encrypt_des, "Encryption", 8);
    double des_decrypt_time = measure_time(decrypt_des, "Decryption", 8);

    printf("\nE-DES:\n");
    double edes_encrypt_time = measure_time(edes_encrypt, "Encryption", 32);
    double edes_decrypt_time = measure_time(edes_decrypt, "Decryption", 32);

    return 0;
}