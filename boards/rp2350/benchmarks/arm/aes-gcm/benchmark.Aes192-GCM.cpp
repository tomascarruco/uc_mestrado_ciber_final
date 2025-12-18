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

// AES192-GCM uses a 192-bit (24-byte) key
#define AES192_KEY_SIZE 24

// GCM typically uses a 96-bit (12-byte) nonce/IV
#define GCM_IV_SIZE 12

// GCM produces a 16-byte authentication tag
#define GCM_TAG_SIZE 16

// Function declarations
void             encryptDataGCM (const byte *data, int data_size, byte *out, byte *tag);
bool             decryptDataGCM (const byte *data, int data_size, const byte *tag, byte *out);
void             runBenchmarks ();
void             fillSequentialPattern (byte *buffer, int size);
int              freeMemory ();
extern "C" char *sbrk (int incr);

// AES192-GCM authenticated encryption
// Uses AES with 192-bit key (12 rounds)
GCM<AES192> gcm;

// AES192 requires a 192-bit (24-byte) key
byte key[AES192_KEY_SIZE]
    = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };

// Initialization Vector for GCM
byte iv[GCM_IV_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B };

// Maximum payload size
#define MAX_PAYLOAD 4325

// Global buffers
byte plaintext[MAX_PAYLOAD];
byte ciphertext[MAX_PAYLOAD];
byte decrypted[MAX_PAYLOAD];
byte authTag[GCM_TAG_SIZE];

void
setup ()
{
    Serial.begin (115200);
    while (!Serial) {
        ;
    }

    gcm.setKey (key, AES192_KEY_SIZE);

    pinMode (LED_BUILTIN, OUTPUT);
    pinMode (MEASURMENT_PIN, OUTPUT);
    digitalWrite (MEASURMENT_PIN, LOW);

    Serial.println ("=== AES192-GCM Authenticated Encryption Benchmark ===");
    Serial.println ("SAMD21 Cortex-M0+ @ 48MHz");
    Serial.println ("Mode: Galois/Counter Mode (GCM) AEAD");
    Serial.println ("Encryption: AES192 in CTR mode (12 rounds)");
    Serial.println ("Authentication: GMAC using Galois field arithmetic");
    Serial.print ("Free SRAM at start: ");
    Serial.print (freeMemory ());
    Serial.println (" b");
    Serial.print ("Static buffer allocation: ");
    Serial.print ((MAX_PAYLOAD * 3) + GCM_TAG_SIZE);
    Serial.println (" b");
    Serial.println ();
    Serial.println ("Starting benchmark...");
    Serial.println ();

    delay (1000);
    runBenchmarks ();

    Serial.println ();
    Serial.println ("=== Benchmark Complete ===");
}

void
loop ()
{
    digitalWrite (LED_BUILTIN, HIGH);
    delay (500);
    digitalWrite (LED_BUILTIN, LOW);
    delay (500);
}

void
runBenchmarks ()
{
    Serial.println ("operation iteration payload_size cpu_cycles cpu_time");
    Serial.println ();

    int payload_size = PAYLOAD_START;

    while (payload_size <= PAYLOAD_MAX) {
        fillSequentialPattern (plaintext, payload_size);

        // === ENCRYPTION ===
        for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
            gcm.setIV (iv, GCM_IV_SIZE);

            digitalWrite (MEASURMENT_PIN, HIGH);
            unsigned long start_time = micros ();

            encryptDataGCM (plaintext, payload_size, ciphertext, authTag);

            unsigned long end_time = micros ();
            digitalWrite (MEASURMENT_PIN, LOW);

            unsigned long elapsed_us = end_time - start_time;
            unsigned long cpu_cycles = elapsed_us * CPU_FREQ_MHZ;

            Serial.print ("encrypt ");
            Serial.print (iter);
            Serial.print (" ");
            Serial.print (payload_size);
            Serial.print (" ");
            Serial.print (cpu_cycles);
            Serial.print (" ");
            Serial.print (elapsed_us);
            Serial.println (" us");

            delayMicroseconds (100);
        }

        // === DECRYPTION ===
        for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
            gcm.setIV (iv, GCM_IV_SIZE);

            digitalWrite (MEASURMENT_PIN, HIGH);
            unsigned long start_time = micros ();

            bool verified = decryptDataGCM (ciphertext, payload_size, authTag, decrypted);

            unsigned long end_time = micros ();
            digitalWrite (MEASURMENT_PIN, LOW);

            unsigned long elapsed_us = end_time - start_time;
            unsigned long cpu_cycles = elapsed_us * CPU_FREQ_MHZ;

            if (!verified) {
                Serial.println ("ERROR: Authentication failed!");
            }

            Serial.print ("decrypt ");
            Serial.print (iter);
            Serial.print (" ");
            Serial.print (payload_size);
            Serial.print (" ");
            Serial.print (cpu_cycles);
            Serial.print (" ");
            Serial.print (elapsed_us);
            Serial.println (" us");

            delayMicroseconds (100);
        }

        payload_size += PAYLOAD_INCREMENT;
        delay (10);
    }
}

void
fillSequentialPattern (byte *buffer, int size)
{
    for (int i = 0; i < size; i++) {
        buffer[i] = i % 256;
    }
}

int
freeMemory ()
{
    char stack_dummy = 0;
    return &stack_dummy - sbrk (0);
}

void
encryptDataGCM (const byte *data, int data_size, byte *out, byte *tag)
{
    gcm.clear ();
    gcm.encrypt (out, data, data_size);
    gcm.computeTag (tag, GCM_TAG_SIZE);
}

bool
decryptDataGCM (const byte *data, int data_size, const byte *tag, byte *out)
{
    gcm.clear ();
    gcm.decrypt (out, data, data_size);
    return gcm.checkTag (tag, GCM_TAG_SIZE);
}
