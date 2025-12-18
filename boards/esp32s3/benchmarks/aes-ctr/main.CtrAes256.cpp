#include <Arduino.h>
#include <SPI.h>
#include <WiFiNINA.h>

#include "WiFi.h"
#include "WiFiClient.h"
#include "api/Common.h"
#include "api/IPAddress.h"

#include "avr/pgmspace.h"
#include "variant.h"

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

// AES256 uses 32-byte keys (256 bits) - maximum AES security
#define AES256_KEY_SIZE 32

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
extern "C" char *sbrk (int incr);

// CTR mode with AES256 - provides counter mode with 14 encryption rounds
CTR<AES256> ctrMode;

// AES256 requires a 32-byte key (256 bits)
byte key[AES256_KEY_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                              0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                              0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };

// Initialization Vector for CTR mode
byte iv[IV_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

// Maximum payload size - CTR mode doesn't need padding
#define MAX_PAYLOAD 4325

// Global buffers to avoid stack overflow
byte plaintext[MAX_PAYLOAD];
byte ciphertext[MAX_PAYLOAD];
byte decrypted[MAX_PAYLOAD];

void
setup ()
{
    Serial.begin (115200);
    while (!Serial) {
        ; // wait for serial port to connect
    }

    // Initialize CTR mode with AES256 key
    ctrMode.setKey (key, AES256_KEY_SIZE);

    // Configure measurement pin
    pinMode (LED_BUILTIN, OUTPUT);
    pinMode (MEASURMENT_PIN, OUTPUT);
    digitalWrite (MEASURMENT_PIN, LOW);

    Serial.println ("=== AES256-CTR Encryption/Decryption Benchmark ===");
    Serial.println ("SAMD21 Cortex-M0+ @ 48MHz");
    Serial.println ("Mode: Counter (CTR) - Stream Cipher Mode");
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
            ctrMode.setIV (iv, IV_SIZE);
            ctrMode.setCounterSize (COUNTER_SIZE);

            // Toggle measurement pin HIGH
            digitalWrite (MEASURMENT_PIN, HIGH);

            // Start timing
            unsigned long start_time = micros ();

            // Perform encryption using AES256-CTR (14 rounds)
            encryptDataCTR (plaintext, payload_size, ciphertext);

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
            // Reset IV for decryption
            ctrMode.setIV (iv, IV_SIZE);
            ctrMode.setCounterSize (COUNTER_SIZE);

            // Toggle measurement pin HIGH
            digitalWrite (MEASURMENT_PIN, HIGH);

            // Start timing
            unsigned long start_time = micros ();

            // Perform decryption using AES256-CTR (14 rounds)
            decryptDataCTR (ciphertext, payload_size, decrypted);

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
    // Fill buffer with sequential byte pattern
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
    // CTR mode encryption with AES256 (14 rounds)
    ctrMode.encrypt (out, data, data_size);
}

void
decryptDataCTR (const byte *data, int data_size, byte *out)
{
    // CTR mode decryption with AES256 (14 rounds)
    ctrMode.decrypt (out, data, data_size);
}
