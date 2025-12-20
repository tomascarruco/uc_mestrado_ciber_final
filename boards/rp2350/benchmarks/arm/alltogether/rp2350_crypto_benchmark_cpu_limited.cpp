#include <Arduino.h>
#include <AES.h>
#include <GCM.h>
#include <CTR.h>
#include <ChaCha.h>
#include <ChaChaPoly.h>
#include <Crypto.h>
#include <cstddef>
#include <cstdint>
#include <string.h>
#include <hardware/clocks.h>
#include <hardware/pll.h>
#include <pico/stdlib.h>

#define MEASURMENT_PIN 11
#define AES_BLOCK_SIZE 16
#define TAG_SIZE 16
#define IV_SIZE_12 12
#define IV_SIZE_16 16

// Benchmark configuration
#define PAYLOAD_START 500
#define PAYLOAD_INCREMENT 255
#define PAYLOAD_MAX 4500
#define ITERATIONS_PER_SIZE 20

// Helper macro to calculate encrypted size for block modes
#define ENCRYPTED_SIZE(n) (((n) + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE * AES_BLOCK_SIZE)

// Maximum payload size
#define MAX_PAYLOAD 4325
#define MAX_ENCRYPTED ENCRYPTED_SIZE (MAX_PAYLOAD)
#define MAX_AEAD_CIPHERTEXT (MAX_PAYLOAD + TAG_SIZE)

// Power state definitions for RP2350
enum PowerState {
    FULL_POWER,      // 150 MHz (default)
    REDUCED_83,      // 125 MHz (83%)
    REDUCED_67,      // 100 MHz (67%)
    REDUCED_50,      // 75 MHz (50%)
    LOW_POWER        // 50 MHz (33%)
};

// Function declarations
void fillSequentialPattern (byte *buffer, int size);
void setCpuFrequency (uint32_t freq_mhz);
uint32_t getCurrentCpuFreqMhz ();
void setPowerState (PowerState state);
float estimateCurrentDraw (uint32_t freq_mhz);
int  freeMemory ();
extern "C" char *sbrk (int incr);

// Benchmark function declarations
void runAES128Benchmark ();
void runAES192Benchmark ();
void runAES256Benchmark ();
void runAESGCM128Benchmark ();
void runAESGCM192Benchmark ();
void runAESGCM256Benchmark ();
void runAESCTR128Benchmark ();
void runAESCTR192Benchmark ();
void runAESCTR256Benchmark ();
void runChaCha20Benchmark ();
void runChaCha20PolyBenchmark ();

// Keys for different key sizes
byte key128[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

byte key192[24] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };

byte key256[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };

// Fixed IVs for modes that require them
byte iv_12[IV_SIZE_12] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                           0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B };

byte iv_16[IV_SIZE_16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

// Global buffers to avoid stack overflow
byte plaintext[MAX_PAYLOAD];
byte ciphertext[MAX_AEAD_CIPHERTEXT];
byte decrypted[MAX_AEAD_CIPHERTEXT];
byte tag[TAG_SIZE];

// Current CPU frequency tracking
uint32_t current_cpu_freq_mhz = 150;

// Power states to test
PowerState power_states[] = {FULL_POWER, REDUCED_83, REDUCED_67, REDUCED_50, LOW_POWER};
int num_power_states = 5;

void
setup ()
{
    Serial.begin (115200);
    
    // Wait for serial connection with timeout
    uint32_t start_wait = millis ();
    while (!Serial && (millis () - start_wait) < 3000) {
        delay (10);
    }

    // Configure measurement pin
    pinMode (LED_BUILTIN, OUTPUT);
    pinMode (MEASURMENT_PIN, OUTPUT);
    digitalWrite (MEASURMENT_PIN, LOW);

    // Small delay to ensure serial is ready
    delay (1000);

    // Print CSV header
    Serial.println ("algorithm,operation,iteration,payload_size,ciphertext_size,cpu_freq_mhz,cpu_cycles,time_us,current_ma,energy_mj");

    // Run all benchmarks sequentially
    runAES128Benchmark ();
    runAES192Benchmark ();
    runAES256Benchmark ();
    runAESGCM128Benchmark ();
    runAESGCM192Benchmark ();
    runAESGCM256Benchmark ();
    runAESCTR128Benchmark ();
    runAESCTR192Benchmark ();
    runAESCTR256Benchmark ();
    runChaCha20Benchmark ();
    runChaCha20PolyBenchmark ();

    // Restore full speed
    setCpuFrequency (150);
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
setCpuFrequency (uint32_t freq_mhz)
{
    // RP2350 can run from 50 MHz to 300 MHz
    if (freq_mhz < 50) freq_mhz = 50;
    if (freq_mhz > 300) freq_mhz = 300;
    
    // Set system clock
    bool success = set_sys_clock_khz (freq_mhz * 1000, true);
    
    if (success) {
        current_cpu_freq_mhz = freq_mhz;
        sleep_ms (10);  // Stabilization time
    }
}

uint32_t
getCurrentCpuFreqMhz ()
{
    return clock_get_hz (clk_sys) / 1000000;
}

void
setPowerState (PowerState state)
{
    uint32_t target_freq = 150;
    
    switch (state) {
        case FULL_POWER:
            target_freq = 150;
            break;
        case REDUCED_83:
            target_freq = 125;
            break;
        case REDUCED_67:
            target_freq = 100;
            break;
        case REDUCED_50:
            target_freq = 75;
            break;
        case LOW_POWER:
            target_freq = 50;
            break;
    }
    
    setCpuFrequency (target_freq);
}

float
estimateCurrentDraw (uint32_t freq_mhz)
{
    // Rough estimation for RP2350 ARM Cortex-M33
    // At 150 MHz: ~30 mA (active processing)
    // Scales roughly linearly with frequency
    return 30.0 * (freq_mhz / 150.0);
}

// ============================================================================
// AES-128 (ECB with PKCS#7 padding)
// ============================================================================

void
encryptDataAES128 (AES128 &aes, const byte *data, int data_size, byte *out, int &out_size)
{
    int  block_count   = (data_size + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
    int  padded_size   = block_count * AES_BLOCK_SIZE;
    byte padding_value = padded_size - data_size;

    byte cypher_buff[AES_BLOCK_SIZE];

    for (int i = 0; i < block_count; ++i) {
        int offset    = i * AES_BLOCK_SIZE;
        int remaining = data_size - offset;

        if (remaining >= AES_BLOCK_SIZE) {
            aes.encryptBlock (cypher_buff, data + offset);
        } else {
            memcpy (cypher_buff, data + offset, remaining);
            memset (cypher_buff + remaining, padding_value, padding_value);
            aes.encryptBlock (cypher_buff, cypher_buff);
        }

        memcpy (out + offset, cypher_buff, AES_BLOCK_SIZE);
    }

    out_size = padded_size;
}

void
decryptDataAES128 (AES128 &aes, const byte *data, int data_size, byte *out)
{
    if (data_size % AES_BLOCK_SIZE != 0) {
        return;
    }

    int  block_count = data_size / AES_BLOCK_SIZE;
    byte plain_buff[AES_BLOCK_SIZE];

    for (int i = 0; i < block_count; ++i) {
        int offset = i * AES_BLOCK_SIZE;
        aes.decryptBlock (plain_buff, data + offset);
        memcpy (out + offset, plain_buff, AES_BLOCK_SIZE);
    }

    byte padding_value = out[data_size - 1];

    if (padding_value > 0 && padding_value <= AES_BLOCK_SIZE) {
        bool valid_padding = true;
        for (int i = 0; i < padding_value; i++) {
            if (out[data_size - 1 - i] != padding_value) {
                valid_padding = false;
                break;
            }
        }

        if (valid_padding) {
            memset (out + data_size - padding_value, 0, padding_value);
        }
    }
}

void
runAES128Benchmark ()
{
    AES128 aes128;
    aes128.setKey (key128, 16);

    int payload_size = PAYLOAD_START;

    while (payload_size <= PAYLOAD_MAX) {
        fillSequentialPattern (plaintext, payload_size);

        // Test at each power state
        for (int s = 0; s < num_power_states; s++) {
            setPowerState (power_states[s]);
            
            uint32_t cpu_freq_mhz = getCurrentCpuFreqMhz ();
            float estimated_current_ma = estimateCurrentDraw (cpu_freq_mhz);

            int ciphertext_size = 0;

            // === ENCRYPTION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                digitalWrite (MEASURMENT_PIN, HIGH);
                unsigned long start_time = micros ();

                encryptDataAES128 (aes128, plaintext, payload_size, ciphertext, ciphertext_size);

                unsigned long end_time   = micros ();
                digitalWrite (MEASURMENT_PIN, LOW);

                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                // Energy calculation
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                Serial.print ("AES128,encrypt,");
                Serial.print (iter);
                Serial.print (",");
                Serial.print (payload_size);
                Serial.print (",");
                Serial.print (ciphertext_size);
                Serial.print (",");
                Serial.print (cpu_freq_mhz);
                Serial.print (",");
                Serial.print (cpu_cycles);
                Serial.print (",");
                Serial.print (elapsed_us);
                Serial.print (",");
                Serial.print (estimated_current_ma, 1);
                Serial.print (",");
                Serial.println (energy_mj, 3);

                delayMicroseconds (100);
            }

            // === DECRYPTION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                digitalWrite (MEASURMENT_PIN, HIGH);
                unsigned long start_time = micros ();

                decryptDataAES128 (aes128, ciphertext, ciphertext_size, decrypted);

                unsigned long end_time   = micros ();
                digitalWrite (MEASURMENT_PIN, LOW);

                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                // Energy calculation
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                Serial.print ("AES128,decrypt,");
                Serial.print (iter);
                Serial.print (",");
                Serial.print (payload_size);
                Serial.print (",");
                Serial.print (ciphertext_size);
                Serial.print (",");
                Serial.print (cpu_freq_mhz);
                Serial.print (",");
                Serial.print (cpu_cycles);
                Serial.print (",");
                Serial.print (elapsed_us);
                Serial.print (",");
                Serial.print (estimated_current_ma, 1);
                Serial.print (",");
                Serial.println (energy_mj, 3);

                delayMicroseconds (100);
            }
        }

        payload_size += PAYLOAD_INCREMENT;
        delay (10);
    }
}

// ============================================================================
// AES-192 (ECB with PKCS#7 padding)
// ============================================================================

void
encryptDataAES192 (AES192 &aes, const byte *data, int data_size, byte *out, int &out_size)
{
    int  block_count   = (data_size + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
    int  padded_size   = block_count * AES_BLOCK_SIZE;
    byte padding_value = padded_size - data_size;

    byte cypher_buff[AES_BLOCK_SIZE];

    for (int i = 0; i < block_count; ++i) {
        int offset    = i * AES_BLOCK_SIZE;
        int remaining = data_size - offset;

        if (remaining >= AES_BLOCK_SIZE) {
            aes.encryptBlock (cypher_buff, data + offset);
        } else {
            memcpy (cypher_buff, data + offset, remaining);
            memset (cypher_buff + remaining, padding_value, padding_value);
            aes.encryptBlock (cypher_buff, cypher_buff);
        }

        memcpy (out + offset, cypher_buff, AES_BLOCK_SIZE);
    }

    out_size = padded_size;
}

void
decryptDataAES192 (AES192 &aes, const byte *data, int data_size, byte *out)
{
    if (data_size % AES_BLOCK_SIZE != 0) {
        return;
    }

    int  block_count = data_size / AES_BLOCK_SIZE;
    byte plain_buff[AES_BLOCK_SIZE];

    for (int i = 0; i < block_count; ++i) {
        int offset = i * AES_BLOCK_SIZE;
        aes.decryptBlock (plain_buff, data + offset);
        memcpy (out + offset, plain_buff, AES_BLOCK_SIZE);
    }

    byte padding_value = out[data_size - 1];

    if (padding_value > 0 && padding_value <= AES_BLOCK_SIZE) {
        bool valid_padding = true;
        for (int i = 0; i < padding_value; i++) {
            if (out[data_size - 1 - i] != padding_value) {
                valid_padding = false;
                break;
            }
        }

        if (valid_padding) {
            memset (out + data_size - padding_value, 0, padding_value);
        }
    }
}

void
runAES192Benchmark ()
{
    AES192 aes192;
    aes192.setKey (key192, 24);

    int payload_size = PAYLOAD_START;

    while (payload_size <= PAYLOAD_MAX) {
        fillSequentialPattern (plaintext, payload_size);

        for (int s = 0; s < num_power_states; s++) {
            setPowerState (power_states[s]);
            
            uint32_t cpu_freq_mhz = getCurrentCpuFreqMhz ();
            float estimated_current_ma = estimateCurrentDraw (cpu_freq_mhz);

            int ciphertext_size = 0;

            // === ENCRYPTION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                digitalWrite (MEASURMENT_PIN, HIGH);
                unsigned long start_time = micros ();

                encryptDataAES192 (aes192, plaintext, payload_size, ciphertext, ciphertext_size);

                unsigned long end_time   = micros ();
                digitalWrite (MEASURMENT_PIN, LOW);

                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                Serial.print ("AES192,encrypt,");
                Serial.print (iter);
                Serial.print (",");
                Serial.print (payload_size);
                Serial.print (",");
                Serial.print (ciphertext_size);
                Serial.print (",");
                Serial.print (cpu_freq_mhz);
                Serial.print (",");
                Serial.print (cpu_cycles);
                Serial.print (",");
                Serial.print (elapsed_us);
                Serial.print (",");
                Serial.print (estimated_current_ma, 1);
                Serial.print (",");
                Serial.println (energy_mj, 3);

                delayMicroseconds (100);
            }

            // === DECRYPTION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                digitalWrite (MEASURMENT_PIN, HIGH);
                unsigned long start_time = micros ();

                decryptDataAES192 (aes192, ciphertext, ciphertext_size, decrypted);

                unsigned long end_time   = micros ();
                digitalWrite (MEASURMENT_PIN, LOW);

                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                Serial.print ("AES192,decrypt,");
                Serial.print (iter);
                Serial.print (",");
                Serial.print (payload_size);
                Serial.print (",");
                Serial.print (ciphertext_size);
                Serial.print (",");
                Serial.print (cpu_freq_mhz);
                Serial.print (",");
                Serial.print (cpu_cycles);
                Serial.print (",");
                Serial.print (elapsed_us);
                Serial.print (",");
                Serial.print (estimated_current_ma, 1);
                Serial.print (",");
                Serial.println (energy_mj, 3);

                delayMicroseconds (100);
            }
        }

        payload_size += PAYLOAD_INCREMENT;
        delay (10);
    }
}

// ============================================================================
// AES-256 (ECB with PKCS#7 padding)
// ============================================================================

void
encryptDataAES256 (AES256 &aes, const byte *data, int data_size, byte *out, int &out_size)
{
    int  block_count   = (data_size + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
    int  padded_size   = block_count * AES_BLOCK_SIZE;
    byte padding_value = padded_size - data_size;

    byte cypher_buff[AES_BLOCK_SIZE];

    for (int i = 0; i < block_count; ++i) {
        int offset    = i * AES_BLOCK_SIZE;
        int remaining = data_size - offset;

        if (remaining >= AES_BLOCK_SIZE) {
            aes.encryptBlock (cypher_buff, data + offset);
        } else {
            memcpy (cypher_buff, data + offset, remaining);
            memset (cypher_buff + remaining, padding_value, padding_value);
            aes.encryptBlock (cypher_buff, cypher_buff);
        }

        memcpy (out + offset, cypher_buff, AES_BLOCK_SIZE);
    }

    out_size = padded_size;
}

void
decryptDataAES256 (AES256 &aes, const byte *data, int data_size, byte *out)
{
    if (data_size % AES_BLOCK_SIZE != 0) {
        return;
    }

    int  block_count = data_size / AES_BLOCK_SIZE;
    byte plain_buff[AES_BLOCK_SIZE];

    for (int i = 0; i < block_count; ++i) {
        int offset = i * AES_BLOCK_SIZE;
        aes.decryptBlock (plain_buff, data + offset);
        memcpy (out + offset, plain_buff, AES_BLOCK_SIZE);
    }

    byte padding_value = out[data_size - 1];

    if (padding_value > 0 && padding_value <= AES_BLOCK_SIZE) {
        bool valid_padding = true;
        for (int i = 0; i < padding_value; i++) {
            if (out[data_size - 1 - i] != padding_value) {
                valid_padding = false;
                break;
            }
        }

        if (valid_padding) {
            memset (out + data_size - padding_value, 0, padding_value);
        }
    }
}

void
runAES256Benchmark ()
{
    AES256 aes256;
    aes256.setKey (key256, 32);

    int payload_size = PAYLOAD_START;

    while (payload_size <= PAYLOAD_MAX) {
        fillSequentialPattern (plaintext, payload_size);

        for (int s = 0; s < num_power_states; s++) {
            setPowerState (power_states[s]);
            
            uint32_t cpu_freq_mhz = getCurrentCpuFreqMhz ();
            float estimated_current_ma = estimateCurrentDraw (cpu_freq_mhz);

            int ciphertext_size = 0;

            // === ENCRYPTION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                digitalWrite (MEASURMENT_PIN, HIGH);
                unsigned long start_time = micros ();

                encryptDataAES256 (aes256, plaintext, payload_size, ciphertext, ciphertext_size);

                unsigned long end_time   = micros ();
                digitalWrite (MEASURMENT_PIN, LOW);

                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                Serial.print ("AES256,encrypt,");
                Serial.print (iter);
                Serial.print (",");
                Serial.print (payload_size);
                Serial.print (",");
                Serial.print (ciphertext_size);
                Serial.print (",");
                Serial.print (cpu_freq_mhz);
                Serial.print (",");
                Serial.print (cpu_cycles);
                Serial.print (",");
                Serial.print (elapsed_us);
                Serial.print (",");
                Serial.print (estimated_current_ma, 1);
                Serial.print (",");
                Serial.println (energy_mj, 3);

                delayMicroseconds (100);
            }

            // === DECRYPTION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                digitalWrite (MEASURMENT_PIN, HIGH);
                unsigned long start_time = micros ();

                decryptDataAES256 (aes256, ciphertext, ciphertext_size, decrypted);

                unsigned long end_time   = micros ();
                digitalWrite (MEASURMENT_PIN, LOW);

                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                Serial.print ("AES256,decrypt,");
                Serial.print (iter);
                Serial.print (",");
                Serial.print (payload_size);
                Serial.print (",");
                Serial.print (ciphertext_size);
                Serial.print (",");
                Serial.print (cpu_freq_mhz);
                Serial.print (",");
                Serial.print (cpu_cycles);
                Serial.print (",");
                Serial.print (elapsed_us);
                Serial.print (",");
                Serial.print (estimated_current_ma, 1);
                Serial.print (",");
                Serial.println (energy_mj, 3);

                delayMicroseconds (100);
            }
        }

        payload_size += PAYLOAD_INCREMENT;
        delay (10);
    }
}

// ============================================================================
// AES-GCM-128 (AEAD)
// ============================================================================

void
runAESGCM128Benchmark ()
{
    GCM<AES128> aesgcm128;
    aesgcm128.setKey (key128, 16);

    int payload_size = PAYLOAD_START;

    while (payload_size <= PAYLOAD_MAX) {
        fillSequentialPattern (plaintext, payload_size);

        for (int s = 0; s < num_power_states; s++) {
            setPowerState (power_states[s]);
            
            uint32_t cpu_freq_mhz = getCurrentCpuFreqMhz ();
            float estimated_current_ma = estimateCurrentDraw (cpu_freq_mhz);

            int ciphertext_size = payload_size + TAG_SIZE;

            // === ENCRYPTION + TAG GENERATION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                digitalWrite (MEASURMENT_PIN, HIGH);
                unsigned long start_time = micros ();

                aesgcm128.setIV (iv_12, IV_SIZE_12);
                aesgcm128.encrypt (ciphertext, plaintext, payload_size);
                aesgcm128.computeTag (tag, TAG_SIZE);

                unsigned long end_time   = micros ();
                digitalWrite (MEASURMENT_PIN, LOW);

                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                Serial.print ("AES-GCM-128,encrypt,");
                Serial.print (iter);
                Serial.print (",");
                Serial.print (payload_size);
                Serial.print (",");
                Serial.print (ciphertext_size);
                Serial.print (",");
                Serial.print (cpu_freq_mhz);
                Serial.print (",");
                Serial.print (cpu_cycles);
                Serial.print (",");
                Serial.print (elapsed_us);
                Serial.print (",");
                Serial.print (estimated_current_ma, 1);
                Serial.print (",");
                Serial.println (energy_mj, 3);

                delayMicroseconds (100);
            }

            // === DECRYPTION + TAG VERIFICATION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                digitalWrite (MEASURMENT_PIN, HIGH);
                unsigned long start_time = micros ();

                aesgcm128.setIV (iv_12, IV_SIZE_12);
                aesgcm128.decrypt (decrypted, ciphertext, payload_size);
                bool verified = aesgcm128.checkTag (tag, TAG_SIZE);

                unsigned long end_time   = micros ();
                digitalWrite (MEASURMENT_PIN, LOW);

                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                Serial.print ("AES-GCM-128,decrypt,");
                Serial.print (iter);
                Serial.print (",");
                Serial.print (payload_size);
                Serial.print (",");
                Serial.print (ciphertext_size);
                Serial.print (",");
                Serial.print (cpu_freq_mhz);
                Serial.print (",");
                Serial.print (cpu_cycles);
                Serial.print (",");
                Serial.print (elapsed_us);
                Serial.print (",");
                Serial.print (estimated_current_ma, 1);
                Serial.print (",");
                Serial.println (energy_mj, 3);

                delayMicroseconds (100);
            }
        }

        payload_size += PAYLOAD_INCREMENT;
        delay (10);
    }
}

// ============================================================================
// AES-GCM-192 (AEAD)
// ============================================================================

void
runAESGCM192Benchmark ()
{
    GCM<AES192> aesgcm192;
    aesgcm192.setKey (key192, 24);

    int payload_size = PAYLOAD_START;

    while (payload_size <= PAYLOAD_MAX) {
        fillSequentialPattern (plaintext, payload_size);

        for (int s = 0; s < num_power_states; s++) {
            setPowerState (power_states[s]);
            
            uint32_t cpu_freq_mhz = getCurrentCpuFreqMhz ();
            float estimated_current_ma = estimateCurrentDraw (cpu_freq_mhz);

            int ciphertext_size = payload_size + TAG_SIZE;

            // === ENCRYPTION + TAG GENERATION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                digitalWrite (MEASURMENT_PIN, HIGH);
                unsigned long start_time = micros ();

                aesgcm192.setIV (iv_12, IV_SIZE_12);
                aesgcm192.encrypt (ciphertext, plaintext, payload_size);
                aesgcm192.computeTag (tag, TAG_SIZE);

                unsigned long end_time   = micros ();
                digitalWrite (MEASURMENT_PIN, LOW);

                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                Serial.print ("AES-GCM-192,encrypt,");
                Serial.print (iter);
                Serial.print (",");
                Serial.print (payload_size);
                Serial.print (",");
                Serial.print (ciphertext_size);
                Serial.print (",");
                Serial.print (cpu_freq_mhz);
                Serial.print (",");
                Serial.print (cpu_cycles);
                Serial.print (",");
                Serial.print (elapsed_us);
                Serial.print (",");
                Serial.print (estimated_current_ma, 1);
                Serial.print (",");
                Serial.println (energy_mj, 3);

                delayMicroseconds (100);
            }

            // === DECRYPTION + TAG VERIFICATION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                digitalWrite (MEASURMENT_PIN, HIGH);
                unsigned long start_time = micros ();

                aesgcm192.setIV (iv_12, IV_SIZE_12);
                aesgcm192.decrypt (decrypted, ciphertext, payload_size);
                bool verified = aesgcm192.checkTag (tag, TAG_SIZE);

                unsigned long end_time   = micros ();
                digitalWrite (MEASURMENT_PIN, LOW);

                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                Serial.print ("AES-GCM-192,decrypt,");
                Serial.print (iter);
                Serial.print (",");
                Serial.print (payload_size);
                Serial.print (",");
                Serial.print (ciphertext_size);
                Serial.print (",");
                Serial.print (cpu_freq_mhz);
                Serial.print (",");
                Serial.print (cpu_cycles);
                Serial.print (",");
                Serial.print (elapsed_us);
                Serial.print (",");
                Serial.print (estimated_current_ma, 1);
                Serial.print (",");
                Serial.println (energy_mj, 3);

                delayMicroseconds (100);
            }
        }

        payload_size += PAYLOAD_INCREMENT;
        delay (10);
    }
}

// ============================================================================
// AES-GCM-256 (AEAD)
// ============================================================================

void
runAESGCM256Benchmark ()
{
    GCM<AES256> aesgcm256;
    aesgcm256.setKey (key256, 32);

    int payload_size = PAYLOAD_START;

    while (payload_size <= PAYLOAD_MAX) {
        fillSequentialPattern (plaintext, payload_size);

        for (int s = 0; s < num_power_states; s++) {
            setPowerState (power_states[s]);
            
            uint32_t cpu_freq_mhz = getCurrentCpuFreqMhz ();
            float estimated_current_ma = estimateCurrentDraw (cpu_freq_mhz);

            int ciphertext_size = payload_size + TAG_SIZE;

            // === ENCRYPTION + TAG GENERATION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                digitalWrite (MEASURMENT_PIN, HIGH);
                unsigned long start_time = micros ();

                aesgcm256.setIV (iv_12, IV_SIZE_12);
                aesgcm256.encrypt (ciphertext, plaintext, payload_size);
                aesgcm256.computeTag (tag, TAG_SIZE);

                unsigned long end_time   = micros ();
                digitalWrite (MEASURMENT_PIN, LOW);

                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                Serial.print ("AES-GCM-256,encrypt,");
                Serial.print (iter);
                Serial.print (",");
                Serial.print (payload_size);
                Serial.print (",");
                Serial.print (ciphertext_size);
                Serial.print (",");
                Serial.print (cpu_freq_mhz);
                Serial.print (",");
                Serial.print (cpu_cycles);
                Serial.print (",");
                Serial.print (elapsed_us);
                Serial.print (",");
                Serial.print (estimated_current_ma, 1);
                Serial.print (",");
                Serial.println (energy_mj, 3);

                delayMicroseconds (100);
            }

            // === DECRYPTION + TAG VERIFICATION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                digitalWrite (MEASURMENT_PIN, HIGH);
                unsigned long start_time = micros ();

                aesgcm256.setIV (iv_12, IV_SIZE_12);
                aesgcm256.decrypt (decrypted, ciphertext, payload_size);
                bool verified = aesgcm256.checkTag (tag, TAG_SIZE);

                unsigned long end_time   = micros ();
                digitalWrite (MEASURMENT_PIN, LOW);

                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                Serial.print ("AES-GCM-256,decrypt,");
                Serial.print (iter);
                Serial.print (",");
                Serial.print (payload_size);
                Serial.print (",");
                Serial.print (ciphertext_size);
                Serial.print (",");
                Serial.print (cpu_freq_mhz);
                Serial.print (",");
                Serial.print (cpu_cycles);
                Serial.print (",");
                Serial.print (elapsed_us);
                Serial.print (",");
                Serial.print (estimated_current_ma, 1);
                Serial.print (",");
                Serial.println (energy_mj, 3);

                delayMicroseconds (100);
            }
        }

        payload_size += PAYLOAD_INCREMENT;
        delay (10);
    }
}

// ============================================================================
// AES-CTR-128 (Stream cipher mode)
// ============================================================================

void
runAESCTR128Benchmark ()
{
    CTR<AES128> aesctr128;
    aesctr128.setKey (key128, 16);

    int payload_size = PAYLOAD_START;

    while (payload_size <= PAYLOAD_MAX) {
        fillSequentialPattern (plaintext, payload_size);

        for (int s = 0; s < num_power_states; s++) {
            setPowerState (power_states[s]);
            
            uint32_t cpu_freq_mhz = getCurrentCpuFreqMhz ();
            float estimated_current_ma = estimateCurrentDraw (cpu_freq_mhz);

            int ciphertext_size = payload_size;

            // === ENCRYPTION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                digitalWrite (MEASURMENT_PIN, HIGH);
                unsigned long start_time = micros ();

                aesctr128.setIV (iv_16, IV_SIZE_16);
                aesctr128.setCounterSize (4);
                aesctr128.encrypt (ciphertext, plaintext, payload_size);

                unsigned long end_time   = micros ();
                digitalWrite (MEASURMENT_PIN, LOW);

                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                Serial.print ("AES-CTR-128,encrypt,");
                Serial.print (iter);
                Serial.print (",");
                Serial.print (payload_size);
                Serial.print (",");
                Serial.print (ciphertext_size);
                Serial.print (",");
                Serial.print (cpu_freq_mhz);
                Serial.print (",");
                Serial.print (cpu_cycles);
                Serial.print (",");
                Serial.print (elapsed_us);
                Serial.print (",");
                Serial.print (estimated_current_ma, 1);
                Serial.print (",");
                Serial.println (energy_mj, 3);

                delayMicroseconds (100);
            }

            // === DECRYPTION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                digitalWrite (MEASURMENT_PIN, HIGH);
                unsigned long start_time = micros ();

                aesctr128.setIV (iv_16, IV_SIZE_16);
                aesctr128.setCounterSize (4);
                aesctr128.decrypt (decrypted, ciphertext, payload_size);

                unsigned long end_time   = micros ();
                digitalWrite (MEASURMENT_PIN, LOW);

                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                Serial.print ("AES-CTR-128,decrypt,");
                Serial.print (iter);
                Serial.print (",");
                Serial.print (payload_size);
                Serial.print (",");
                Serial.print (ciphertext_size);
                Serial.print (",");
                Serial.print (cpu_freq_mhz);
                Serial.print (",");
                Serial.print (cpu_cycles);
                Serial.print (",");
                Serial.print (elapsed_us);
                Serial.print (",");
                Serial.print (estimated_current_ma, 1);
                Serial.print (",");
                Serial.println (energy_mj, 3);

                delayMicroseconds (100);
            }
        }

        payload_size += PAYLOAD_INCREMENT;
        delay (10);
    }
}

// ============================================================================
// AES-CTR-192 (Stream cipher mode)
// ============================================================================

void
runAESCTR192Benchmark ()
{
    CTR<AES192> aesctr192;
    aesctr192.setKey (key192, 24);

    int payload_size = PAYLOAD_START;

    while (payload_size <= PAYLOAD_MAX) {
        fillSequentialPattern (plaintext, payload_size);

        for (int s = 0; s < num_power_states; s++) {
            setPowerState (power_states[s]);
            
            uint32_t cpu_freq_mhz = getCurrentCpuFreqMhz ();
            float estimated_current_ma = estimateCurrentDraw (cpu_freq_mhz);

            int ciphertext_size = payload_size;

            // === ENCRYPTION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                digitalWrite (MEASURMENT_PIN, HIGH);
                unsigned long start_time = micros ();

                aesctr192.setIV (iv_16, IV_SIZE_16);
                aesctr192.setCounterSize (4);
                aesctr192.encrypt (ciphertext, plaintext, payload_size);

                unsigned long end_time   = micros ();
                digitalWrite (MEASURMENT_PIN, LOW);

                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                Serial.print ("AES-CTR-192,encrypt,");
                Serial.print (iter);
                Serial.print (",");
                Serial.print (payload_size);
                Serial.print (",");
                Serial.print (ciphertext_size);
                Serial.print (",");
                Serial.print (cpu_freq_mhz);
                Serial.print (",");
                Serial.print (cpu_cycles);
                Serial.print (",");
                Serial.print (elapsed_us);
                Serial.print (",");
                Serial.print (estimated_current_ma, 1);
                Serial.print (",");
                Serial.println (energy_mj, 3);

                delayMicroseconds (100);
            }

            // === DECRYPTION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                digitalWrite (MEASURMENT_PIN, HIGH);
                unsigned long start_time = micros ();

                aesctr192.setIV (iv_16, IV_SIZE_16);
                aesctr192.setCounterSize (4);
                aesctr192.decrypt (decrypted, ciphertext, payload_size);

                unsigned long end_time   = micros ();
                digitalWrite (MEASURMENT_PIN, LOW);

                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                Serial.print ("AES-CTR-192,decrypt,");
                Serial.print (iter);
                Serial.print (",");
                Serial.print (payload_size);
                Serial.print (",");
                Serial.print (ciphertext_size);
                Serial.print (",");
                Serial.print (cpu_freq_mhz);
                Serial.print (",");
                Serial.print (cpu_cycles);
                Serial.print (",");
                Serial.print (elapsed_us);
                Serial.print (",");
                Serial.print (estimated_current_ma, 1);
                Serial.print (",");
                Serial.println (energy_mj, 3);

                delayMicroseconds (100);
            }
        }

        payload_size += PAYLOAD_INCREMENT;
        delay (10);
    }
}

// ============================================================================
// AES-CTR-256 (Stream cipher mode)
// ============================================================================

void
runAESCTR256Benchmark ()
{
    CTR<AES256> aesctr256;
    aesctr256.setKey (key256, 32);

    int payload_size = PAYLOAD_START;

    while (payload_size <= PAYLOAD_MAX) {
        fillSequentialPattern (plaintext, payload_size);

        for (int s = 0; s < num_power_states; s++) {
            setPowerState (power_states[s]);
            
            uint32_t cpu_freq_mhz = getCurrentCpuFreqMhz ();
            float estimated_current_ma = estimateCurrentDraw (cpu_freq_mhz);

            int ciphertext_size = payload_size;

            // === ENCRYPTION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                digitalWrite (MEASURMENT_PIN, HIGH);
                unsigned long start_time = micros ();

                aesctr256.setIV (iv_16, IV_SIZE_16);
                aesctr256.setCounterSize (4);
                aesctr256.encrypt (ciphertext, plaintext, payload_size);

                unsigned long end_time   = micros ();
                digitalWrite (MEASURMENT_PIN, LOW);

                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                Serial.print ("AES-CTR-256,encrypt,");
                Serial.print (iter);
                Serial.print (",");
                Serial.print (payload_size);
                Serial.print (",");
                Serial.print (ciphertext_size);
                Serial.print (",");
                Serial.print (cpu_freq_mhz);
                Serial.print (",");
                Serial.print (cpu_cycles);
                Serial.print (",");
                Serial.print (elapsed_us);
                Serial.print (",");
                Serial.print (estimated_current_ma, 1);
                Serial.print (",");
                Serial.println (energy_mj, 3);

                delayMicroseconds (100);
            }

            // === DECRYPTION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                digitalWrite (MEASURMENT_PIN, HIGH);
                unsigned long start_time = micros ();

                aesctr256.setIV (iv_16, IV_SIZE_16);
                aesctr256.setCounterSize (4);
                aesctr256.decrypt (decrypted, ciphertext, payload_size);

                unsigned long end_time   = micros ();
                digitalWrite (MEASURMENT_PIN, LOW);

                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                Serial.print ("AES-CTR-256,decrypt,");
                Serial.print (iter);
                Serial.print (",");
                Serial.print (payload_size);
                Serial.print (",");
                Serial.print (ciphertext_size);
                Serial.print (",");
                Serial.print (cpu_freq_mhz);
                Serial.print (",");
                Serial.print (cpu_cycles);
                Serial.print (",");
                Serial.print (elapsed_us);
                Serial.print (",");
                Serial.print (estimated_current_ma, 1);
                Serial.print (",");
                Serial.println (energy_mj, 3);

                delayMicroseconds (100);
            }
        }

        payload_size += PAYLOAD_INCREMENT;
        delay (10);
    }
}

// ============================================================================
// ChaCha20 (Stream cipher)
// ============================================================================

void
runChaCha20Benchmark ()
{
    ChaCha chacha20;
    chacha20.setKey (key256, 32);

    int payload_size = PAYLOAD_START;

    while (payload_size <= PAYLOAD_MAX) {
        fillSequentialPattern (plaintext, payload_size);

        for (int s = 0; s < num_power_states; s++) {
            setPowerState (power_states[s]);
            
            uint32_t cpu_freq_mhz = getCurrentCpuFreqMhz ();
            float estimated_current_ma = estimateCurrentDraw (cpu_freq_mhz);

            int ciphertext_size = payload_size;

            // === ENCRYPTION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                digitalWrite (MEASURMENT_PIN, HIGH);
                unsigned long start_time = micros ();

                chacha20.setIV (iv_12, IV_SIZE_12);
                chacha20.setCounter (0);
                chacha20.encrypt (ciphertext, plaintext, payload_size);

                unsigned long end_time   = micros ();
                digitalWrite (MEASURMENT_PIN, LOW);

                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                Serial.print ("ChaCha20,encrypt,");
                Serial.print (iter);
                Serial.print (",");
                Serial.print (payload_size);
                Serial.print (",");
                Serial.print (ciphertext_size);
                Serial.print (",");
                Serial.print (cpu_freq_mhz);
                Serial.print (",");
                Serial.print (cpu_cycles);
                Serial.print (",");
                Serial.print (elapsed_us);
                Serial.print (",");
                Serial.print (estimated_current_ma, 1);
                Serial.print (",");
                Serial.println (energy_mj, 3);

                delayMicroseconds (100);
            }

            // === DECRYPTION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                digitalWrite (MEASURMENT_PIN, HIGH);
                unsigned long start_time = micros ();

                chacha20.setIV (iv_12, IV_SIZE_12);
                chacha20.setCounter (0);
                chacha20.decrypt (decrypted, ciphertext, payload_size);

                unsigned long end_time   = micros ();
                digitalWrite (MEASURMENT_PIN, LOW);

                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                Serial.print ("ChaCha20,decrypt,");
                Serial.print (iter);
                Serial.print (",");
                Serial.print (payload_size);
                Serial.print (",");
                Serial.print (ciphertext_size);
                Serial.print (",");
                Serial.print (cpu_freq_mhz);
                Serial.print (",");
                Serial.print (cpu_cycles);
                Serial.print (",");
                Serial.print (elapsed_us);
                Serial.print (",");
                Serial.print (estimated_current_ma, 1);
                Serial.print (",");
                Serial.println (energy_mj, 3);

                delayMicroseconds (100);
            }
        }

        payload_size += PAYLOAD_INCREMENT;
        delay (10);
    }
}

// ============================================================================
// ChaCha20-Poly1305 (AEAD)
// ============================================================================

void
runChaCha20PolyBenchmark ()
{
    ChaChaPoly chachapoly;
    chachapoly.setKey (key256, 32);

    int payload_size = PAYLOAD_START;

    while (payload_size <= PAYLOAD_MAX) {
        fillSequentialPattern (plaintext, payload_size);

        for (int s = 0; s < num_power_states; s++) {
            setPowerState (power_states[s]);
            
            uint32_t cpu_freq_mhz = getCurrentCpuFreqMhz ();
            float estimated_current_ma = estimateCurrentDraw (cpu_freq_mhz);

            int ciphertext_size = payload_size + TAG_SIZE;

            // === ENCRYPTION + TAG GENERATION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                digitalWrite (MEASURMENT_PIN, HIGH);
                unsigned long start_time = micros ();

                chachapoly.setIV (iv_12, IV_SIZE_12);
                chachapoly.encrypt (ciphertext, plaintext, payload_size);
                chachapoly.computeTag (tag, TAG_SIZE);

                unsigned long end_time   = micros ();
                digitalWrite (MEASURMENT_PIN, LOW);

                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                Serial.print ("ChaCha20-Poly1305,encrypt,");
                Serial.print (iter);
                Serial.print (",");
                Serial.print (payload_size);
                Serial.print (",");
                Serial.print (ciphertext_size);
                Serial.print (",");
                Serial.print (cpu_freq_mhz);
                Serial.print (",");
                Serial.print (cpu_cycles);
                Serial.print (",");
                Serial.print (elapsed_us);
                Serial.print (",");
                Serial.print (estimated_current_ma, 1);
                Serial.print (",");
                Serial.println (energy_mj, 3);

                delayMicroseconds (100);
            }

            // === DECRYPTION + TAG VERIFICATION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                digitalWrite (MEASURMENT_PIN, HIGH);
                unsigned long start_time = micros ();

                chachapoly.setIV (iv_12, IV_SIZE_12);
                chachapoly.decrypt (decrypted, ciphertext, payload_size);
                bool verified = chachapoly.checkTag (tag, TAG_SIZE);

                unsigned long end_time   = micros ();
                digitalWrite (MEASURMENT_PIN, LOW);

                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                Serial.print ("ChaCha20-Poly1305,decrypt,");
                Serial.print (iter);
                Serial.print (",");
                Serial.print (payload_size);
                Serial.print (",");
                Serial.print (ciphertext_size);
                Serial.print (",");
                Serial.print (cpu_freq_mhz);
                Serial.print (",");
                Serial.print (cpu_cycles);
                Serial.print (",");
                Serial.print (elapsed_us);
                Serial.print (",");
                Serial.print (estimated_current_ma, 1);
                Serial.print (",");
                Serial.println (energy_mj, 3);

                delayMicroseconds (100);
            }
        }

        payload_size += PAYLOAD_INCREMENT;
        delay (10);
    }
}
