#include <Arduino.h>

#include <AES.h>
#include <Crypto.h>
#include <GCM.h>
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

// AES128-GCM uses a 128-bit (16-byte) key
#define AES128_KEY_SIZE 16

// GCM typically uses a 96-bit (12-byte) nonce/IV
// This is the recommended size for GCM
#define GCM_IV_SIZE 12

// GCM produces a 16-byte authentication tag (128 bits)
// This can be truncated to smaller sizes, but 16 bytes is standard
#define GCM_TAG_SIZE 16

// Function declarations
void             encryptDataGCM (const byte *data, int data_size, byte *out, byte *tag);
bool             decryptDataGCM (const byte *data, int data_size, const byte *tag, byte *out);
void             runBenchmarks ();
void             fillSequentialPattern (byte *buffer, int size);
int              freeMemory ();
extern C char *sbrk (int incr);

// AES128-GCM authenticated encryption
// Combines AES128 in CTR mode with GMAC authentication
// GCM = Galois/Counter Mode
GCM<AES128> gcm;

// AES128 requires a 128-bit (16-byte) key
byte key[AES128_KEY_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

// Initialization Vector (nonce) for GCM
// Must be unique for each message with the same key
// 96 bits (12 bytes) is the standard and recommended size for GCM
byte iv[GCM_IV_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B };

// Maximum payload size - GCM is a stream mode so no padding needed
#define MAX_PAYLOAD 4325

// Global buffers to avoid stack overflow
byte plaintext[MAX_PAYLOAD];
byte ciphertext[MAX_PAYLOAD];
byte decrypted[MAX_PAYLOAD];
byte authTag[GCM_TAG_SIZE]; // 16-byte authentication tag

void
setup ()
{
    Serial.begin (115200);
    while (!Serial) {
        ; // wait for serial port to connect
    }

    // Initialize GCM with AES128 key
    gcm.setKey (key, AES128_KEY_SIZE);

    // Configure measurement pin
    pinMode (LED_BUILTIN, OUTPUT);
    pinMode (MEASURMENT_PIN, OUTPUT);
    digitalWrite (MEASURMENT_PIN, LOW);

    Serial.println (=== AES128-GCM Authenticated Encryption Benchmark ===);
    Serial.println (SAMD21 Cortex-M0+ @ 48MHz);
    Serial.println (Mode: Galois/Counter Mode (GCM) AEAD);
    Serial.println (Encryption: AES128 in CTR mode (10 rounds));
    Serial.println (Authentication: GMAC using Galois field arithmetic);
    Serial.print (Free SRAM at start: );
    Serial.print (freeMemory ());
    Serial.println ( b);
    Serial.print (Static buffer allocation: );
    Serial.print ((MAX_PAYLOAD * 3) + GCM_TAG_SIZE);
    Serial.println ( b);
    Serial.println ();
    Serial.println (Note: Encryption includes GMAC computation, Decryption includes verification);
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

        // === AUTHENTICATED ENCRYPTION BENCHMARK ===
        for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
            // Set the IV (nonce) for this encryption operation
            // The IV must be unique for each message with the same key
            // Never reuse an IV with GCM - this completely breaks security
            gcm.setIV (iv, GCM_IV_SIZE);

            // Toggle measurement pin HIGH
            digitalWrite (MEASURMENT_PIN, HIGH);

            // Start timing
            unsigned long start_time = micros ();

            // Perform authenticated encryption with GCM
            // This operation does three things:
            // 1. Uses AES128 to encrypt counter values, generating keystream (CTR mode)
            // 2. XORs keystream with plaintext to produce ciphertext
            // 3. Computes GMAC authentication tag over ciphertext using Galois field multiplication
            encryptDataGCM (plaintext, payload_size, ciphertext, authTag);

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

        // === AUTHENTICATED DECRYPTION BENCHMARK ===
        for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
            // Set the same IV used for encryption
            gcm.setIV (iv, GCM_IV_SIZE);

            // Toggle measurement pin HIGH
            digitalWrite (MEASURMENT_PIN, HIGH);

            // Start timing
            unsigned long start_time = micros ();

            // Perform authenticated decryption with GCM
            // This operation verifies authenticity BEFORE decrypting:
            // 1. Recomputes GMAC tag over received ciphertext
            // 2. Compares computed tag with received tag (constant-time comparison)
            // 3. Only if tags match, proceeds with decryption
            // 4. Generates same keystream using AES128-CTR
            // 5. XORs keystream with ciphertext to recover plaintext
            bool verified = decryptDataGCM (ciphertext, payload_size, authTag, decrypted);

            // End timing
            unsigned long end_time = micros ();

            // Toggle measurement pin LOW
            digitalWrite (MEASURMENT_PIN, LOW);

            // Calculate metrics
            unsigned long elapsed_us = end_time - start_time;
            unsigned long cpu_cycles = elapsed_us * CPU_FREQ_MHZ;

            // Verification should always succeed in our benchmark
            // In real applications, failed verification indicates tampering or corruption
            if (!verified) {
                Serial.println (ERROR: GCM authentication verification failed!);
            }

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
encryptDataGCM (const byte *data, int data_size, byte *out, byte *tag)
{
    // Clear the GCM state to prepare for encryption
    gcm.clear ();

    // Optional: Add additional authenticated data (AAD)
    // AAD is data that should be authenticated but NOT encrypted
    // Examples: packet headers, protocol metadata, sequence numbers
    // For this benchmark we're not using AAD, but here's the syntax:
    // gcm.addAuthData(aad, aad_length);

    // Encrypt the data using AES128 in CTR mode
    // GCM internally:
    // 1. Encrypts counter blocks with AES128 to generate keystream
    // 2. XORs keystream with plaintext to produce ciphertext
    // 3. Simultaneously prepares data for GMAC authentication
    gcm.encrypt (out, data, data_size);

    // Compute and retrieve the GMAC authentication tag
    // GMAC uses Galois field (GF(2^128)) multiplication to compute
    // a polynomial hash of the ciphertext and AAD
    // The result is a 128-bit (16-byte) tag that authenticates all data
    // This tag allows the recipient to detect any tampering
    gcm.computeTag (tag, GCM_TAG_SIZE);

    // Now 'out' contains ciphertext and 'tag' contains the authentication tag
    // Both must be transmitted to the recipient for decryption and verification
}

bool
decryptDataGCM (const byte *data, int data_size, const byte *tag, byte *out)
{
    // Clear the GCM state to prepare for decryption
    gcm.clear ();

    // If AAD was used during encryption, provide the SAME AAD here
    // Authentication will fail if AAD doesn't match exactly
    // gcm.addAuthData(aad, aad_length);

    // Decrypt the data
    // Even though we call decrypt here, we should only USE the decrypted
    // data if authentication succeeds
    // GCM internally generates the same keystream and XORs with ciphertext
    gcm.decrypt (out, data, data_size);

    // Verify the authentication tag
    // This recomputes the GMAC tag over the received ciphertext and AAD
    // and compares it with the received tag using constant-time comparison
    // Constant-time comparison is essential to prevent timing attacks
    bool verified = gcm.checkTag (tag, GCM_TAG_SIZE);

    // CRITICAL: In production code, you MUST check this return value
    // If verified is false, you must discard the decrypted output immediately
    // Using data that failed authentication can lead to security vulnerabilities
    //
    // Common reasons for authentication failure:
    // - Ciphertext was modified in transit (attack or corruption)
    // - AAD doesn't match what was used during encryption
    // - Wrong key or IV used for decryption
    // - Tag was truncated or corrupted

    return verified;
}
