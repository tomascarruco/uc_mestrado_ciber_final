#include <Arduino.h>

#include <AES.h>
#include <CTR.h>
#include <Crypto.h>
#include <cstddef>
#include <cstdint>
#include <string.h>

#define MEASURMENT_PIN 11
#define AES_BLOCK_SIZE 16

// Benchmark configuration
#define PAYLOAD_START 500
#define PAYLOAD_INCREMENT 255
#define PAYLOAD_MAX 4500
#define ITERATIONS_PER_SIZE 20

// CPU frequency for cycle calculation (SAMD21 runs at 48MHz)
#define CPU_FREQ_MHZ 48

// AES128 uses 16-byte keys (128 bits)
#define AES128_KEY_SIZE 16

// CTR mode uses an IV (initialization vector) that contains the nonce
// We'll use 8 bytes for nonce and 8 bytes for counter
#define IV_SIZE 16
#define COUNTER_SIZE 8

// Function declarations
void             encryptDataCTR (const byte *data, int data_size, byte *out);
void             decryptDataCTR (const byte *data, int data_size, byte *out);
void             runBenchmarks ();
void             fillSequentialPattern (byte *buffer, int size);
int              freeMemory ();
extern C char *sbrk (int incr);

// CTR mode with AES128 - wraps AES128 to provide counter mode operation
CTR<AES128> ctrMode;

// AES128 requires a 16-byte key (128 bits)
byte key[AES128_KEY_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

// Initialization Vector for CTR mode
// In real applications, this must be unique for each message with the same key
// For benchmarking, we use a fixed IV to ensure consistent measurements
byte iv[IV_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

// Maximum payload size - CTR mode doesn't need padding so size equals input size
#define MAX_PAYLOAD 4325

// Global buffers to avoid stack overflow
// CTR mode is more memory efficient - no padding overhead
byte plaintext[MAX_PAYLOAD];
byte ciphertext[MAX_PAYLOAD]; // Same size as plaintext, no padding needed
byte decrypted[MAX_PAYLOAD];

void
setup ()
{
    Serial.begin (115200);
    while (!Serial) {
        ; // wait for serial port to connect
    }

    // Initialize CTR mode with AES128 key
    ctrMode.setKey (key, AES128_KEY_SIZE);

    // Configure measurement pin
    pinMode (LED_BUILTIN, OUTPUT);
    pinMode (MEASURMENT_PIN, OUTPUT);
    digitalWrite (MEASURMENT_PIN, LOW);

    Serial.println (=== AES128-CTR Encryption/Decryption Benchmark ===);
    Serial.println (SAMD21 Cortex-M0+ @ 48MHz);
    Serial.println (Mode: Counter (CTR) - Stream Cipher Mode);
    Serial.print (Free SRAM at start: );
    Serial.print (freeMemory ());
    Serial.println ( b);
    Serial.print (Static buffer allocation: );
    Serial.print (MAX_PAYLOAD * 3); // Three buffers of equal size
    Serial.println ( b);
    Serial.println ();
    Serial.println (Starting benchmark...);
    Serial.println ();

    // Small delay to ensure serial is ready
    delay (1000);

    // Run the benchmarks
    runBenchmarks ();

    Serial.println ();
    Serial.println (=== Benchmark Complete ===);
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
    Serial.println (operation iteration payload_size cpu_cycles cpu_time);
    Serial.println ();

    // Calculate how many payload sizes we'll test
    int payload_size = PAYLOAD_START;

    while (payload_size <= PAYLOAD_MAX) {
        // Fill plaintext with sequential pattern
        fillSequentialPattern (plaintext, payload_size);

        // === ENCRYPTION BENCHMARK ===
        for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
            // Reset IV for each encryption to ensure consistent measurements
            // In CTR mode, the IV must be set before each encrypt/decrypt operation
            ctrMode.setIV (iv, IV_SIZE);
            ctrMode.setCounterSize (COUNTER_SIZE);

            // Toggle measurement pin HIGH
            digitalWrite (MEASURMENT_PIN, HIGH);

            // Start timing
            unsigned long start_time = micros ();

            // Perform encryption using CTR mode
            // CTR mode processes the entire payload in one call
            encryptDataCTR (plaintext, payload_size, ciphertext);

            // End timing
            unsigned long end_time = micros ();

            // Toggle measurement pin LOW
            digitalWrite (MEASURMENT_PIN, LOW);

            // Calculate metrics
            unsigned long elapsed_us = end_time - start_time;
            unsigned long cpu_cycles = elapsed_us * CPU_FREQ_MHZ;

            // Output: operation iteration payload_size cpu_cycles cpu_time
            Serial.print (encrypt );
            Serial.print (iter);
            Serial.print ( );
            Serial.print (payload_size);
            Serial.print ( );
            Serial.print (cpu_cycles);
            Serial.print ( );
            Serial.print (elapsed_us);
            Serial.println ( us);

            // Small delay between operations
            delayMicroseconds (100);
        }

        // === DECRYPTION BENCHMARK ===
        for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
            // Reset IV for decryption - must match the IV used for encryption
            ctrMode.setIV (iv, IV_SIZE);
            ctrMode.setCounterSize (COUNTER_SIZE);

            // Toggle measurement pin HIGH
            digitalWrite (MEASURMENT_PIN, HIGH);

            // Start timing
            unsigned long start_time = micros ();

            // Perform decryption using CTR mode
            // In CTR mode, decryption is computationally identical to encryption
            decryptDataCTR (ciphertext, payload_size, decrypted);

            // End timing
            unsigned long end_time = micros ();

            // Toggle measurement pin LOW
            digitalWrite (MEASURMENT_PIN, LOW);

            // Calculate metrics
            unsigned long elapsed_us = end_time - start_time;
            unsigned long cpu_cycles = elapsed_us * CPU_FREQ_MHZ;

            // Output: operation iteration payload_size cpu_cycles cpu_time
            Serial.print (decrypt );
            Serial.print (iter);
            Serial.print ( );
            Serial.print (payload_size);
            Serial.print ( );
            Serial.print (cpu_cycles);
            Serial.print ( );
            Serial.print (elapsed_us);
            Serial.println ( us);

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
    for (int i = 0; i < size; i++) {
        buffer[i] = i % 256;
    }
}

int
freeMemory ()
{
    // Calculate free memory between heap and stack
    char stack_dummy = 0;
    return &stack_dummy - sbrk (0);
}

void
encryptDataCTR (const byte *data, int data_size, byte *out)
{
    // CTR mode encryption is straightforward - just one call
    // The CTR class handles all the counter incrementation and keystream generation
    // No padding needed - output size equals input size
    ctrMode.encrypt (out, data, data_size);
}

void
decryptDataCTR (const byte *data, int data_size, byte *out)
{
    // CTR mode decryption is identical to encryption from a computational perspective
    // Both generate the same keystream and XOR it with the input
    // This is why encryption and decryption have the same performance in CTR mode
    ctrMode.decrypt (out, data, data_size);
}
