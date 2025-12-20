#include <Arduino.h>
#include <ChaCha.h>
#include <ChaChaPoly.h>
#include <Crypto.h>
#include <Poly1305.h>
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

// ChaCha20-Poly1305 uses a 256-bit (32-byte) key
#define CHACHA_KEY_SIZE 32

// ChaCha20-Poly1305 uses a 96-bit (12-byte) nonce - this is the standard size
#define CHACHA_NONCE_SIZE 12

// Poly1305 produces a 16-byte authentication tag
#define POLY1305_TAG_SIZE 16

// Function declarations
void encryptDataChaChaPoly (const byte *data, int data_size, byte *out, byte *tag);
bool decryptDataChaChaPoly (const byte *data, int data_size, const byte *tag, byte *out);
void runBenchmarks ();
void fillSequentialPattern (byte *buffer, int size);
int  freeMemory ();
extern C char *sbrk (int incr);

// ChaCha20-Poly1305 AEAD cipher
// Combines ChaCha20 stream cipher with Poly1305 MAC for authenticated encryption
// This provides both confidentiality (encryption) and integrity/authenticity (MAC)
ChaChaPoly chachaPoly;

// ChaCha20-Poly1305 uses a 256-bit key
byte key[CHACHA_KEY_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                              0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                              0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };

// Nonce for ChaCha20-Poly1305
// Must be unique for each message with the same key
// 96 bits (12 bytes) is the standard nonce size for ChaCha20-Poly1305
byte nonce[CHACHA_NONCE_SIZE]
    = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B };

// Maximum payload size - no padding needed for stream cipher
#define MAX_PAYLOAD 4325

// Global buffers to avoid stack overflow
byte plaintext[MAX_PAYLOAD];
byte ciphertext[MAX_PAYLOAD]; // Same size as plaintext (no padding in stream cipher)
byte decrypted[MAX_PAYLOAD];
byte authTag[POLY1305_TAG_SIZE]; // 16-byte authentication tag

void
setup ()
{
    Serial.begin (115200);
    while (!Serial) {
        ; // wait for serial port to connect
    }

    // Initialize ChaCha20-Poly1305 with key
    chachaPoly.setKey (key, CHACHA_KEY_SIZE);

    // Configure measurement pin
    pinMode (LED_BUILTIN, OUTPUT);
    pinMode (MEASURMENT_PIN, OUTPUT);
    digitalWrite (MEASURMENT_PIN, LOW);

    Serial.println (=== ChaCha20-Poly1305 Authenticated Encryption Benchmark ===);
    Serial.println (SAMD21 Cortex-M0+ @ 48MHz);
    Serial.println (Cipher: ChaCha20-Poly1305 AEAD (RFC 8439));
    Serial.println (Encryption: ChaCha20 stream cipher (20 rounds));
    Serial.println (Authentication: Poly1305 MAC (16-byte tag));
    Serial.println (Designer: Daniel J. Bernstein);
    Serial.print (Free SRAM at start: );
    Serial.print (freeMemory ());
    Serial.println ( b);
    Serial.print (Static buffer allocation: );
    Serial.print ((MAX_PAYLOAD * 3) + POLY1305_TAG_SIZE);
    Serial.println ( b);
    Serial.println ();
    Serial.println (Note: Encryption includes MAC computation, Decryption includes verification);
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
        // This measures both encryption AND MAC computation
        for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
            // Set the nonce for this encryption operation
            // In real applications, the nonce MUST be unique for each message
            // Never reuse a nonce with the same key - this breaks security
            chachaPoly.setIV (nonce, CHACHA_NONCE_SIZE);

            // Toggle measurement pin HIGH
            digitalWrite (MEASURMENT_PIN, HIGH);

            // Start timing
            unsigned long start_time = micros ();

            // Perform authenticated encryption
            // This does TWO things:
            // 1. Encrypts the plaintext with ChaCha20 to produce ciphertext
            // 2. Computes Poly1305 MAC over ciphertext to produce authentication tag
            // The tag allows the recipient to verify the message hasn't been tampered with
            encryptDataChaChaPoly (plaintext, payload_size, ciphertext, authTag);

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
        // This measures verification AND decryption
        for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
            // Set the same nonce used for encryption
            // ChaCha20-Poly1305 requires the same nonce for decryption
            chachaPoly.setIV (nonce, CHACHA_NONCE_SIZE);

            // Toggle measurement pin HIGH
            digitalWrite (MEASURMENT_PIN, HIGH);

            // Start timing
            unsigned long start_time = micros ();

            // Perform authenticated decryption
            // This does TWO things in order:
            // 1. Recomputes Poly1305 MAC over the received ciphertext
            // 2. Compares computed tag with received tag (constant-time comparison)
            // 3. If tags match, decrypts ciphertext; if not, returns false
            // IMPORTANT: We never decrypt without verifying first - this prevents
            // processing tampered data that could exploit vulnerabilities
            bool verified = decryptDataChaChaPoly (ciphertext, payload_size, authTag, decrypted);

            // End timing
            unsigned long end_time = micros ();

            // Toggle measurement pin LOW
            digitalWrite (MEASURMENT_PIN, LOW);

            // Calculate metrics
            unsigned long elapsed_us = end_time - start_time;
            unsigned long cpu_cycles = elapsed_us * CPU_FREQ_MHZ;

            // In a real application, you would check 'verified' and reject the message if false
            // For benchmarking, we know it should always be true since we just encrypted it
            if (!verified) {
                Serial.println (ERROR: Authentication verification failed!);
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
encryptDataChaChaPoly (const byte *data, int data_size, byte *out, byte *tag)
{
    // Clear the cipher state to prepare for encryption
    chachaPoly.clear ();

    // Optional: You can add additional authenticated data (AAD) here
    // AAD is data that should be authenticated but NOT encrypted
    // For example, packet headers, protocol version numbers, etc.
    // For this benchmark, we're not using AAD, but here's how you would:
    // chachaPoly.addAuthData(aad, aad_length);

    // Encrypt the data
    // ChaCha20 generates a keystream by performing 20 rounds of mixing
    // on a state derived from the key and nonce, then XORs with plaintext
    chachaPoly.encrypt (out, data, data_size);

    // Compute and retrieve the authentication tag
    // Poly1305 evaluates a polynomial over the ciphertext (and AAD if present)
    // using a one-time key derived from the ChaCha20 keystream
    // The result is a 16-byte tag that authenticates all the encrypted data
    chachaPoly.computeTag (tag, POLY1305_TAG_SIZE);

    // At this point, 'out' contains the ciphertext and 'tag' contains the MAC
    // In a real application, you would send both to the recipient
    // The recipient needs both pieces to decrypt and verify authenticity
}

bool
decryptDataChaChaPoly (const byte *data, int data_size, const byte *tag, byte *out)
{
    // Clear the cipher state to prepare for decryption
    chachaPoly.clear ();

    // If we used AAD during encryption, we must provide the SAME AAD here
    // The authentication will fail if the AAD doesn't match exactly
    // chachaPoly.addAuthData(aad, aad_length);

    // Decrypt the data
    // In ChaCha20, decryption is identical to encryption - we generate
    // the same keystream and XOR it with the ciphertext to recover plaintext
    chachaPoly.decrypt (out, data, data_size);

    // Verify the authentication tag
    // This recomputes the Poly1305 MAC over the ciphertext (and AAD)
    // and compares it with the received tag using constant-time comparison
    // Constant-time comparison is crucial - it prevents timing attacks where
    // an attacker could learn information by measuring how long verification takes
    bool verified = chachaPoly.checkTag (tag, POLY1305_TAG_SIZE);

    // CRITICAL SECURITY NOTE:
    // In production code, you MUST check this return value
    // If verified is false, discard the decrypted data immediately
    // Never use data that failed authentication - it may be malicious
    //
    // In this benchmark, we're measuring the time to verify and decrypt
    // We know verification should succeed because we just encrypted the data
    // But in real applications, verification failures indicate attacks or corruption

    return verified;
}
