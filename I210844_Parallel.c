#include <mpi.h>      // For MPI functions
#include <stdio.h>     // For printf
#include <stdint.h>    // For uint16_t
#include <stdbool.h>   // For bool, true, false
#include <time.h>      // For time functions

// S-AES constants
#define SBOX_SIZE 16
#define NUM_ROUNDS 2

// Function prototypes
void initialize_saes();
bool decrypt_and_check(uint16_t key, uint16_t ciphertext, uint16_t known_plaintext);
void distribute_key_ranges(int rank, int size, uint16_t *start_key, uint16_t *end_key);
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
uint16_t keys;
int main(int argc, char** argv) {
    int rank, size;
    uint16_t start_key, end_key;
    uint16_t correct_key = 0;
    int found_rank = -1;
    double start_time, end_time;
    long keys_checked = 0;

    // Known plaintext-ciphertext pair
    uint16_t known_plaintext = 0x2314;
    uint16_t ciphertext;

    // MPI initialization
    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    // Generate test vectors for S-AES
    uint16_t test_key = 0x1A2B;
    ciphertext = saes_encrypt(known_plaintext, test_key);
    keys = test_key;

    if (rank == 0) {
        printf("Plaintext: 0x%04X\n", known_plaintext);
        printf("Ciphertext: 0x%04X\n", ciphertext);
        printf("Test Vector - Plaintext: 0x%04X, Ciphertext: 0x%04X, Key: 0x%04X\n", known_plaintext, ciphertext, test_key);
        printf("Starting brute-force key search...\n");
    }

    // Distribute key ranges among processes
    distribute_key_ranges(rank, size, &start_key, &end_key);
    printf("Process %d searching key range: 0x%04X to 0x%04X\n", rank, start_key, end_key);

    start_time = MPI_Wtime();

    // Brute-force search
    for (uint16_t key = start_key; key <= end_key && found_rank == -1; key++) {
        keys_checked++;

        if (keys_checked % 1000 == 0 && found_rank == -1) {
            printf("Process %d checking key: 0x%04X\n", rank + 1, key);
        }

        // Check if key decrypts correctly
        if (decrypt_and_check(key, ciphertext, known_plaintext)) {
            correct_key = keys;
            found_rank = rank;
            printf("Process %d found the key: 0x%04X\n", rank + 1, correct_key);
        }

        // Check if any process has found the key
        int old_found_rank = found_rank;
        MPI_Allreduce(MPI_IN_PLACE, &found_rank, 1, MPI_INT, MPI_MAX, MPI_COMM_WORLD);
       
        if (found_rank != old_found_rank) {
            printf("Process %d received notification that key was found\n", rank + 1);
        }

        if (found_rank != -1 || key == end_key) {
            printf("Process %d exiting loop. Last key checked: 0x%04X\n", rank + 1, key);
            break;
        }
    }

    // If a process found the correct key, broadcast it to all processes
    if (found_rank != -1) {
        if (rank == found_rank) {
            printf("Process %d broadcasting found key\n", rank + 1);
            MPI_Bcast(&correct_key, 1, MPI_UINT16_T, found_rank, MPI_COMM_WORLD);
        } else {
            MPI_Bcast(&correct_key, 1, MPI_UINT16_T, found_rank, MPI_COMM_WORLD);
            printf("Process %d received broadcasted key: 0x%04X\n", rank + 1, correct_key);
        }
    }

    end_time = MPI_Wtime();

    // Print timing and performance details for each process
    double time_taken = end_time - start_time;
    double keys_per_sec = keys_checked / time_taken;

    printf("Process %d checked %ld keys in %f seconds. Rate: %f keys/second\n", rank + 1, keys_checked, time_taken, keys_per_sec);

    if (rank == 0) {
        if (found_rank != -1) {
            printf("Correct key found by process %d: 0x%04X\n", found_rank + 1, correct_key);
        } else {
            printf("No key found.\n");
        }
        printf("Total time taken: %f seconds\n", time_taken);
    }

    MPI_Finalize();
    return 0;
}


bool decrypt_and_check(uint16_t key, uint16_t ciphertext, uint16_t known_plaintext) {
    uint16_t decrypted_text = saes_decrypt(ciphertext, key);
    if (decrypted_text == known_plaintext) {
        printf("Key found: 0x%04X\n", keys);
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

void distribute_key_ranges(int rank, int size, uint16_t *start_key, uint16_t *end_key) {
    uint32_t total_keys = 65536;
    uint32_t keys_per_process = total_keys / size;
    *start_key = rank * keys_per_process;
    *end_key = (rank == size - 1) ? total_keys - 1 : *start_key + keys_per_process - 1;
}
