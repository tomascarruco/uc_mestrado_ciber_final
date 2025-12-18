#include <Arduino.h>

#include <ChaCha.h>
#include <Crypto.h>
#include <cstddef>
#include <cstdint>
#include <string.h>

#define MEASURMENT_PIN 11

// Benchmark configuration
#define PAYLOAD_START 500
#define PAYLOAD_INCREMENT 255
#define PAYLOAD_MAX 4500
#define ITERATIONS_PER_SIZE 20

// CPU frequency for cycle calculation (SAMD21 runs at 48MHz)
#define CPU_FREQ_MHZ 48

// ChaCha uses a 256-bit (32-byte) key exclusively
// Unlike AES, there's only one key size for ChaCha
#define CHACHA_KEY_SIZE 32

// ChaCha20 typically uses a 96-bit (12-byte) nonce and 32-bit (4-byte) counter
// The IV in the library includes both the nonce and counter
#define CHACHA_IV_SIZE 16 // 12 bytes nonce + 4 bytes counter (in some implementations)

// Function declarations
void             encryptDataChaCha (const byte *data, int data_size, byte *out);
void             decryptDataChaCha (const byte *data, int data_size, byte *out);
void             runBenchmarks ();
void             fillSequentialPattern (byte *buffer, int size);
int              freeMemory ();
extern "C" char *sbrk (int incr);

// ChaCha cipher object - performs 20 rounds of mixing for strong security
// ChaCha was designed by Daniel J. Bernstein as an alternative to AES
// It uses simple operations (add, rotate, XOR) that are fast on all processors
ChaCha chacha;

// ChaCha uses a 256-bit (32-byte) key
// This provides strong security equivalent to AES256
byte key[CHACHA_KEY_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                              0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                              0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };

// Initialization Vector for ChaCha
// Contains the nonce (must be unique per message) and counter
// For benchmarking, we use a fixed IV for consistent measurements
byte iv[CHACHA_IV_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

// Maximum payload size - ChaCha is a stream cipher so no padding needed
#define MAX_PAYLOAD 4325

// Global buffers to avoid stack overflow
// ChaCha operates on data of any size without padding overhead
byte plaintext[MAX_PAYLOAD];
byte ciphertext[MAX_PAYLOAD]; // Same size as plaintext
byte decrypted[MAX_PAYLOAD];

void
setup ()
{
    Serial.begin (115200);
    while (!Serial) {
        ; // wait for serial port to connect
    }

    // Initialize ChaCha with 256-bit key
    // ChaCha performs 20 rounds of mixing operations
    chacha.setKey (key, CHACHA_KEY_SIZE);

    // Configure measurement pin
    pinMode (LED_BUILTIN, OUTPUT);
    pinMode (MEASURMENT_PIN, OUTPUT);
    digitalWrite (MEASURMENT_PIN, LOW);

    Serial.println ("=== ChaCha20 Encryption/Decryption Benchmark ===");
    Serial.println ("SAMD21 Cortex-M0+ @ 48MHz");
    Serial.println ("Cipher: ChaCha20 - Stream Cipher (20 rounds)");
    Serial.println ("Designer: Daniel J. Bernstein");
    Serial.print ("Free SRAM at start: ");
    Serial.print (freeMemory ());
    Serial.println (" b");
    Serial.print ("Static buffer allocation: ");
    Serial.print (MAX_PAYLOAD * 3);
    Serial.println (" b");
    Serial.println ();
    Serial.println ("Starting benchmark...");
    Serial.println ();

    // Small delay to ensure serial is ready
    delay (1000);

    // Run the benchmarks
    runBenchmarks ();

    Serial.println ();
    Serial.println ("=== Benchmark Complete ===");
}

void
loop ()
{
    // Benchmark runs once in setup, loop does nothing
    digitalWrite (LED_BUILTIN, HIGH);
    delay (500);
    digitalWrite (LED_BUILTIN, LOW);
    delay (500);
}

void
runBenchmarks ()
{
    // Print CSV header
    Serial.println ("operation iteration payload_size cpu_cycles cpu_time");
    Serial.println ();

    // Calculate how many payload sizes we'll test
    int payload_size = PAYLOAD_START;

    while (payload_size <= PAYLOAD_MAX) {
        // Fill plaintext with sequential pattern
        fillSequentialPattern (plaintext, payload_size);

        // === ENCRYPTION BENCHMARK ===
        for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
            // Reset IV for each encryption
            // In ChaCha, the IV contains both the nonce and the initial counter value
            // The nonce must be unique for each message with the same key
            chacha.setIV (iv, CHACHA_IV_SIZE);

            // Toggle measurement pin HIGH
            digitalWrite (MEASURMENT_PIN, HIGH);

            // Start timing
            unsigned long start_time = micros ();

            // Perform encryption using ChaCha20
            // ChaCha generates a keystream by mixing the key, nonce, and counter
            // then XORs this keystream with the plaintext
            encryptDataChaCha (plaintext, payload_size, ciphertext);

            // End timing
            unsigned long end_time = micros ();

            // Toggle measurement pin LOW
            digitalWrite (MEASURMENT_PIN, LOW);

            // Calculate metrics
            unsigned long elapsed_us = end_time - start_time;
            unsigned long cpu_cycles = elapsed_us * CPU_FREQ_MHZ;

            // Output: operation iteration payload_size cpu_cycles cpu_time
            Serial.print ("encrypt ");
            Serial.print (iter);
            Serial.print (" ");
            Serial.print (payload_size);
            Serial.print (" ");
            Serial.print (cpu_cycles);
            Serial.print (" ");
            Serial.print (elapsed_us);
            Serial.println (" us");

            // Small delay between operations
            delayMicroseconds (100);
        }

        // === DECRYPTION BENCHMARK ===
        for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
            // Reset IV for decryption - must match encryption IV
            chacha.setIV (iv, CHACHA_IV_SIZE);

            // Toggle measurement pin HIGH
            digitalWrite (MEASURMENT_PIN, HIGH);

            // Start timing
            unsigned long start_time = micros ();

            // Perform decryption using ChaCha20
            // In stream ciphers like ChaCha, decryption is identical to encryption
            // We generate the same keystream and XOR it with the ciphertext
            // Since XOR is its own inverse: (plaintext XOR keystream) XOR keystream = plaintext
            decryptDataChaCha (ciphertext, payload_size, decrypted);

            // End timing
            unsigned long end_time = micros ();

            // Toggle measurement pin LOW
            digitalWrite (MEASURMENT_PIN, LOW);

            // Calculate metrics
            unsigned long elapsed_us = end_time - start_time;
            unsigned long cpu_cycles = elapsed_us * CPU_FREQ_MHZ;

            // Output: operation iteration payload_size cpu_cycles cpu_time
            Serial.print ("decrypt ");
            Serial.print (iter);
            Serial.print (" ");
            Serial.print (payload_size);
            Serial.print (" ");
            Serial.print (cpu_cycles);
            Serial.print (" ");
            Serial.print (elapsed_us);
            Serial.println (" us");

            // Small delay between operations
            delayMicroseconds (100);
        }

        // Move to next payload size
        payload_size += PAYLOAD_INCREMENT;

        // Brief pause between payload sizes
        delay (10);
    }
}

void
fillSequentialPattern (byte *buffer, int size)
{
    // Fill buffer with sequential byte pattern: 0x00, 0x01, 0x02, ..., 0xFF, 0x00, ...
    // This provides a predictable test pattern while avoiding the weakness
    // of using all zeros or all ones
    for (int i = 0; i < size; i++) {
        buffer[i] = i % 256;
    }
}

int
freeMemory ()
{
    // Calculate free memory between heap and stack
    // This gives us insight into available RAM on the resource-constrained SAMD21
    char stack_dummy = 0;
    return &stack_dummy - sbrk (0);
}

void
encryptDataChaCha (const byte *data, int data_size, byte *out)
{
    // ChaCha encryption is straightforward - just one call
    // The ChaCha class handles all the round operations internally
    // Each round consists of four "quarter round" operations that mix the state
    // After 20 rounds, the final state is XORed with the original to produce keystream
    // This keystream is then XORed with the plaintext to produce ciphertext
    chacha.encrypt (out, data, data_size);
}

void
decryptDataChaCha (const byte *data, int data_size, byte *out)
{
    // ChaCha decryption is computationally identical to encryption
    // Both operations generate the same keystream and XOR it with the input
    // This symmetric property is characteristic of stream ciphers
    // It means encryption and decryption will have identical performance
    chacha.decrypt (out, data, data_size);
}
