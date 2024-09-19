#include <stdio.h>     // For printf
#include <stdint.h>    // For uint16_t
#include <stdbool.h>   // For bool, true, false
#include <time.h>      // For time functions

// S-AES constants
#define SBOX_SIZE 16
#define NUM_ROUNDS 2

// Function prototypes
bool decrypt_and_check(uint16_t key, uint16_t ciphertext, uint16_t known_plaintext);
uint16_t saes_decrypt(uint16_t ciphertext, uint16_t key);
uint16_t sub_word(uint16_t word);
uint16_t rot_word(uint16_t word);
void key_expansion(uint16_t key, uint16_t *round_keys);
uint16_t saes_encrypt(uint16_t plaintext, uint16_t key);
uint16_t mix_columns(uint16_t state);
uint16_t inv_mix_columns(uint16_t state);

// Global variables for S-AES
uint8_t sbox[SBOX_SIZE] = {0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7};
uint8_t inv_sbox[SBOX_SIZE] = {0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE};

int main() {
    uint16_t correct_key = 0;
    long keys_checked = 0;
    double start_time, end_time;
    uint16_t known_plaintext = 0x2314;
    uint16_t ciphertext;

    // Generate test vectors for S-AES
    uint16_t test_key = 0x1A2B;
    uint16_t keys = test_key;
    ciphertext = saes_encrypt(known_plaintext, test_key);

    printf("Plaintext: 0x%04X\n", known_plaintext);
    printf("Ciphertext: 0x%04X\n", ciphertext);
    printf("Test Vector - Plaintext: 0x%04X, Ciphertext: 0x%04X, Key: 0x%04X\n", known_plaintext, ciphertext, test_key);
    printf("Starting brute-force key search...\n");

    start_time = clock();

    // Brute-force search
    for (uint16_t key = 0x0000; key <= 0xFFFF; key++) {
        keys_checked++;

        if (keys_checked % 1000 == 0) {
            printf("Checking key: 0x%04X\n", key);
        }

        // Check if key decrypts correctly
        if (decrypt_and_check(key, ciphertext, known_plaintext)) {
            correct_key = keys;
            printf("Key found: 0x%04X\n", correct_key);
            break;
        }
    }

    end_time = clock();

    double time_taken = (end_time - start_time) / CLOCKS_PER_SEC;
    double keys_per_sec = keys_checked / time_taken;

    printf("Checked %ld keys in %f seconds. Rate: %f keys/second\n", keys_checked, time_taken, keys_per_sec);

    if (correct_key != 0) {
        printf("Correct key found: 0x%04X\n", correct_key);
    } else {
        printf("No key found.\n");
    }

    printf("Total time taken: %f seconds\n", time_taken);

    return 0;
}

bool decrypt_and_check(uint16_t key, uint16_t ciphertext, uint16_t known_plaintext) {
    uint16_t decrypted_text = saes_decrypt(ciphertext, key);
    if (decrypted_text == known_plaintext) {
        printf("Decrypted Text: 0x%04X\n", decrypted_text);
        return true;
    }
    return false;
}

uint16_t saes_decrypt(uint16_t ciphertext, uint16_t key) {
    uint16_t state = ciphertext;
    uint16_t round_keys[NUM_ROUNDS + 1];

    key_expansion(key, round_keys);

    // Add round key
    state ^= round_keys[NUM_ROUNDS];

    for (int round = NUM_ROUNDS - 1; round >= 0; round--) {
        // Inverse sub bytes
        uint8_t left = inv_sbox[(state >> 8) & 0x0F];
        uint8_t right = inv_sbox[state & 0x0F];
        state = (left << 8) | right;

        // Add round key
        state ^= round_keys[round];

        if (round > 0) {
            // Inverse mix columns
            state = inv_mix_columns(state);
        }
    }

    return state;
}

uint16_t saes_encrypt(uint16_t plaintext, uint16_t key) {
    uint16_t state = plaintext;
    uint16_t round_keys[NUM_ROUNDS + 1];

    key_expansion(key, round_keys);

    // Add round key
    state ^= round_keys[0];

    for (int round = 1; round <= NUM_ROUNDS; round++) {
        // Sub bytes
        uint8_t left = sbox[(state >> 8) & 0x0F];
        uint8_t right = sbox[state & 0x0F];
        state = (left << 8) | right;

        if (round < NUM_ROUNDS) {
            // Mix columns
            state = mix_columns(state);
        }

        // Add round key
        state ^= round_keys[round];
    }

    return state;
}

void key_expansion(uint16_t key, uint16_t *round_keys) {
    round_keys[0] = key;
    for (int i = 1; i <= NUM_ROUNDS; i++) {
        uint16_t temp = round_keys[i-1];
        temp = rot_word(temp);
        temp = sub_word(temp);
        temp ^= (i << 8);  // Round constant
        round_keys[i] = round_keys[i-1] ^ temp;
    }
}

uint16_t sub_word(uint16_t word) {
    uint8_t left = sbox[(word >> 8) & 0x0F];
    uint8_t right = sbox[word & 0x0F];
    return (left << 8) | right;
}

uint16_t rot_word(uint16_t word) {
    return ((word & 0xFF) << 8) | ((word >> 8) & 0xFF);
}

uint16_t mix_columns(uint16_t state) {
    uint8_t a = (state >> 8) & 0xFF;
    uint8_t b = state & 0xFF;
    uint8_t a_new = (a * 0x02) ^ (b * 0x03);
    uint8_t b_new = (a * 0x03) ^ (b * 0x02);
    return (a_new << 8) | b_new;
}

uint16_t inv_mix_columns(uint16_t state) {
    uint8_t a = (state >> 8) & 0xFF;
    uint8_t b = state & 0xFF;
    uint8_t a_new = (a * 0x0E) ^ (b * 0x0B);
    uint8_t b_new = (a * 0x0B) ^ (b * 0x0E);
    return (a_new << 8) | b_new;
}
