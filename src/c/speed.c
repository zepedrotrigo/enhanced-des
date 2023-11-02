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

double measure_time(void (*func)(uint8_t *, void *schedule, uint8_t *, int), void (*key_setup)(const unsigned char *, void *schedule), const char *description, int key_size) {
    unsigned char key[key_size], input[BUFFER_SIZE], output[BUFFER_SIZE];
    DES_key_schedule des_schedule;
    uint8_t sboxes[SBOX_COUNT][SBOX_SIZE];
    struct timespec start, end;

    double min_time = __DBL_MAX__;

    for (int i = 0; i < NUM_ITERATIONS; i++) {
        generate_random_key(key, key_size);
        key_setup(key, (key_size == 8) ? (void *)&des_schedule : (void *)sboxes);

        clock_gettime(CLOCK_MONOTONIC, &start);
        func(output, (key_size == 8) ? (void *)&des_schedule : (void *)sboxes, input, BUFFER_SIZE);
        clock_gettime(CLOCK_MONOTONIC, &end);

        double time = (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
        if (time < min_time) {
            min_time = time;
        }
    }

    printf("%s time: %.3f ns\n", description, min_time);
    return min_time;
}

void des_key_setup(const unsigned char *key, void *schedule) {
    DES_set_key_unchecked((const_DES_cblock *)key, (DES_key_schedule *)schedule);
}

void edes_key_setup(const unsigned char *key, void *sboxes) {
    generate_sboxes((uint8_t (*)[SBOX_SIZE])sboxes, (const char *)key);
}

int main() {
    printf("DES:\n");
    double des_encrypt_time = measure_time(encrypt_des, des_key_setup, "Encryption", 8);
    double des_decrypt_time = measure_time(decrypt_des, des_key_setup, "Decryption", 8);

    printf("\nE-DES:\n");
    double edes_encrypt_time = measure_time(edes_encrypt, edes_key_setup, "Encryption", 32);
    double edes_decrypt_time = measure_time(edes_decrypt, edes_key_setup, "Decryption", 32);

    return 0;
}
