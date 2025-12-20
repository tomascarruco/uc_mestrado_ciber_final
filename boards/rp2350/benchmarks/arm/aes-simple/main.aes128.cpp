#include <Arduino.h>

#include <AES.h>
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

// Helper macro to calculate encrypted size
#define ENCRYPTED_SIZE(n) (((n) + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE * AES_BLOCK_SIZE)

// Function declarations
void             encryptDataAES (const byte *data, int data_size, byte *out);
void             decryptDataAES (const byte *data, int data_size, byte *out);
void             runBenchmarks ();
void             fillSequentialPattern (byte *buffer, int size);
int              freeMemory ();
extern C char *sbrk (int incr);

// AES globals
AES128 aes128;
byte   key[AES_BLOCK_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                               0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

// Maximum payload size we'll test (with padding)
// With PAYLOAD_MAX = 4500, the actual max reached is 4325 bytes
// 4325 rounded up to nearest 16-byte block = 4336 bytes encrypted
#define MAX_PAYLOAD 4325
#define MAX_ENCRYPTED ENCRYPTED_SIZE (MAX_PAYLOAD)

// Global buffers to avoid stack overflow
// These use approximately 13KB of the SAMD21's 32KB SRAM
byte plaintext[MAX_PAYLOAD];
byte ciphertext[MAX_ENCRYPTED];
byte decrypted[MAX_ENCRYPTED];

void
setup ()
{
    Serial.begin (115200);
    while (!Serial) {
        ; // wait for serial port to connect
    }

    // Initialize AES with key
    aes128.setKey (key, 16);

    // Configure measurement pin
    pinMode (LED_BUILTIN, OUTPUT);
    pinMode (MEASURMENT_PIN, OUTPUT);
    digitalWrite (MEASURMENT_PIN, LOW);

    Serial.println (=== AES128 Encryption/Decryption Benchmark ===);
    Serial.println (SAMD21 Cortex-M0+ @ 48MHz);
    Serial.print (Free SRAM at start: );
    Serial.print (freeMemory ());
    Serial.println ( b);
    Serial.print (Static buffer allocation: );
    Serial.print (MAX_PAYLOAD + MAX_ENCRYPTED + MAX_ENCRYPTED);
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
        // Calculate encrypted size for this payload
        int encrypted_size = ENCRYPTED_SIZE (payload_size);

        // Fill plaintext with sequential pattern
        fillSequentialPattern (plaintext, payload_size);

        // === ENCRYPTION BENCHMARK ===
        for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
            // Toggle measurement pin HIGH
            digitalWrite (MEASURMENT_PIN, HIGH);

            // Start timing
            unsigned long start_time = micros ();

            // Perform encryption
            encryptDataAES (plaintext, payload_size, ciphertext);

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
            // Toggle measurement pin HIGH
            digitalWrite (MEASURMENT_PIN, HIGH);

            // Start timing
            unsigned long start_time = micros ();

            // Perform decryption
            decryptDataAES (ciphertext, encrypted_size, decrypted);

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
encryptDataAES (const byte *data, int data_size, byte *out)
{
    // Calculate number of blocks (round up)
    int  block_count   = (data_size + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
    int  padded_size   = block_count * AES_BLOCK_SIZE;
    byte padding_value = padded_size - data_size;

    byte cypher_buff[AES_BLOCK_SIZE];

    for (int i = 0; i < block_count; ++i) {
        int offset    = i * AES_BLOCK_SIZE;
        int remaining = data_size - offset;

        if (remaining >= AES_BLOCK_SIZE) {
            // Full block - encrypt directly
            aes128.encryptBlock (cypher_buff, data + offset);
        } else {
            // Partial block - need padding
            memcpy (cypher_buff, data + offset, remaining);
            // PKCS#7 padding: fill with padding_value
            memset (cypher_buff + remaining, padding_value, padding_value);
            aes128.encryptBlock (cypher_buff, cypher_buff);
        }

        memcpy (out + offset, cypher_buff, AES_BLOCK_SIZE);
    }
}

void
decryptDataAES (const byte *data, int data_size, byte *out)
{
    // data_size must be multiple of AES_BLOCK_SIZE
    if (data_size % AES_BLOCK_SIZE != 0) {
        return;
    }

    int  block_count = data_size / AES_BLOCK_SIZE;
    byte plain_buff[AES_BLOCK_SIZE];

    for (int i = 0; i < block_count; ++i) {
        int offset = i * AES_BLOCK_SIZE;
        aes128.decryptBlock (plain_buff, data + offset);
        memcpy (out + offset, plain_buff, AES_BLOCK_SIZE);
    }

    // Remove PKCS#7 padding from last block
    byte padding_value = out[data_size - 1];

    // Validate and remove padding
    if (padding_value > 0 && padding_value <= AES_BLOCK_SIZE) {
        bool valid_padding = true;
        for (int i = 0; i < padding_value; i++) {
            if (out[data_size - 1 - i] != padding_value) {
                valid_padding = false;
                break;
            }
        }

        if (valid_padding) {
            // Zero out padding bytes
            memset (out + data_size - padding_value, 0, padding_value);
        }
    }
}
