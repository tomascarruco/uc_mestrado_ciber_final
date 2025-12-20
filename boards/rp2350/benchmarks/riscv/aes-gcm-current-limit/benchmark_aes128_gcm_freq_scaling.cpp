#include <Arduino.h>
#include <AES.h>
#include <Crypto.h>
#include <GCM.h>
#include <cstddef>
#include <cstdint>
#include <string.h>
#include <hardware/clocks.h>
#include <hardware/pll.h>
#include <pico/stdlib.h>

#define MEASURMENT_PIN 11

// Benchmark configuration
#define PAYLOAD_START 500
#define PAYLOAD_INCREMENT 255
#define PAYLOAD_MAX 4500
#define ITERATIONS_PER_SIZE 20

// AES128-GCM uses a 128-bit (16-byte) key
#define AES128_KEY_SIZE 16

// GCM typically uses a 96-bit (12-byte) nonce/IV
#define GCM_IV_SIZE 12

// GCM produces a 16-byte authentication tag (128 bits)
#define GCM_TAG_SIZE 16

// Power state definitions for RP2350
enum PowerState {
    FULL_POWER,      // 150 MHz (default)
    REDUCED_83,      // 125 MHz (83%)
    REDUCED_67,      // 100 MHz (67%)
    REDUCED_50,      // 75 MHz (50%)
    LOW_POWER        // 50 MHz (33%)
};

// Function declarations
void             encryptDataGCM (const byte *data, int data_size, byte *out, byte *tag);
bool             decryptDataGCM (const byte *data, int data_size, const byte *tag, byte *out);
void             runBenchmarks ();
void             fillSequentialPattern (byte *buffer, int size);
void             setCpuFrequency (uint32_t freq_mhz);
uint32_t         getCurrentCpuFreqMhz ();
void             setPowerState (PowerState state);
float            estimateCurrentDraw (uint32_t freq_mhz);
int              freeMemory ();
extern C char *sbrk (int incr);

// AES128-GCM authenticated encryption
// Combines AES128 in CTR mode with GMAC authentication
GCM<AES128> gcm;

// AES128 requires a 128-bit (16-byte) key
byte key[AES128_KEY_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

// Initialization Vector (nonce) for GCM
byte iv[GCM_IV_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B };

// Maximum payload size
#define MAX_PAYLOAD 4325

// Global buffers to avoid stack overflow
byte plaintext[MAX_PAYLOAD];
byte ciphertext[MAX_PAYLOAD];
byte decrypted[MAX_PAYLOAD];
byte authTag[GCM_TAG_SIZE];

// Current CPU frequency tracking
uint32_t current_cpu_freq_mhz = 150;

void
setup ()
{
    Serial.begin (115200);
    
    // Wait for serial connection with timeout
    uint32_t start_wait = millis ();
    while (!Serial && (millis () - start_wait) < 3000) {
        delay (10);
    }
    
    delay (1000);

    // Initialize GCM with AES128 key
    gcm.setKey (key, AES128_KEY_SIZE);

    // Configure measurement pin
    pinMode (LED_BUILTIN, OUTPUT);
    pinMode (MEASURMENT_PIN, OUTPUT);
    digitalWrite (MEASURMENT_PIN, LOW);

    Serial.println (=== AES128-GCM Authenticated Encryption Benchmark ===);
    Serial.println (=== Raspberry Pi Pico 2W (RP2350) ===);
    
    // Print chip information
    Serial.print (Architecture: );
    #ifdef PICO_RISCV
        Serial.println (RISC-V Hazard3);
    #else
        Serial.println (ARM Cortex-M33);
    #endif
    
    Serial.print (Starting CPU Frequency: );
    Serial.print (getCurrentCpuFreqMhz ());
    Serial.println ( MHz);
    
    Serial.println (Mode: Galois/Counter Mode (GCM) AEAD);
    Serial.println (Encryption: AES128 in CTR mode (10 rounds));
    Serial.println (Authentication: GMAC using Galois field arithmetic);
    
    Serial.print (Free SRAM at start: );
    Serial.print (freeMemory ());
    Serial.println ( bytes);
    
    Serial.print (Static buffer allocation: );
    Serial.print ((MAX_PAYLOAD * 3) + GCM_TAG_SIZE);
    Serial.println ( bytes);
    
    Serial.println ();
    Serial.println (Note: Encryption includes GMAC computation, Decryption includes verification);
    Serial.println ();
    Serial.println (Testing at multiple CPU frequencies...);
    Serial.println ();
    Serial.println (Starting benchmark...);
    Serial.println ();

    // Small delay to ensure serial is ready
    delay (1000);

    // Run the benchmarks
    runBenchmarks ();

    // Restore full speed
    setCpuFrequency (150);
    
    Serial.println ();
    Serial.println (=== Benchmark Complete ===);
    Serial.print (Final CPU Frequency: );
    Serial.print (getCurrentCpuFreqMhz ());
    Serial.println ( MHz);
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
    // Print CSV header with power metrics
    Serial.println (operation iteration payload_size cpu_freq_mhz cpu_cycles time_us current_ma energy_mj);
    Serial.println ();

    // Power states to test
    PowerState states[] = {FULL_POWER, REDUCED_83, REDUCED_67, REDUCED_50, LOW_POWER};
    int num_states = 5;

    // Calculate how many payload sizes we'll test
    int payload_size = PAYLOAD_START;

    while (payload_size <= PAYLOAD_MAX) {
        // Fill plaintext with sequential pattern
        fillSequentialPattern (plaintext, payload_size);

        // Test at each power state
        for (int s = 0; s < num_states; s++) {
            setPowerState (states[s]);
            
            uint32_t cpu_freq_mhz = getCurrentCpuFreqMhz ();
            float estimated_current_ma = estimateCurrentDraw (cpu_freq_mhz);

            // === AUTHENTICATED ENCRYPTION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                // Set the IV (nonce) for this encryption operation
                gcm.setIV (iv, GCM_IV_SIZE);

                // Toggle measurement pin HIGH
                digitalWrite (MEASURMENT_PIN, HIGH);

                // Start timing
                unsigned long start_time = micros ();

                // Perform authenticated encryption with GCM
                encryptDataGCM (plaintext, payload_size, ciphertext, authTag);

                // End timing
                unsigned long end_time = micros ();

                // Toggle measurement pin LOW
                digitalWrite (MEASURMENT_PIN, LOW);

                // Calculate metrics
                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                // Energy calculation
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                // Output: operation iteration payload_size cpu_freq_mhz cpu_cycles time_us current_ma energy_mj
                Serial.print (encrypt );
                Serial.print (iter);
                Serial.print ( );
                Serial.print (payload_size);
                Serial.print ( );
                Serial.print (cpu_freq_mhz);
                Serial.print ( );
                Serial.print (cpu_cycles);
                Serial.print ( );
                Serial.print (elapsed_us);
                Serial.print ( );
                Serial.print (estimated_current_ma, 1);
                Serial.print ( );
                Serial.print (energy_mj, 3);
                Serial.println ();

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
                bool verified = decryptDataGCM (ciphertext, payload_size, authTag, decrypted);

                // End timing
                unsigned long end_time = micros ();

                // Toggle measurement pin LOW
                digitalWrite (MEASURMENT_PIN, LOW);

                // Calculate metrics
                unsigned long elapsed_us = end_time - start_time;
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                // Energy calculation
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

                // Verification should always succeed
                if (!verified) {
                    Serial.println (ERROR: GCM authentication verification failed!);
                }

                // Output: operation iteration payload_size cpu_freq_mhz cpu_cycles time_us current_ma energy_mj
                Serial.print (decrypt );
                Serial.print (iter);
                Serial.print ( );
                Serial.print (payload_size);
                Serial.print ( );
                Serial.print (cpu_freq_mhz);
                Serial.print ( );
                Serial.print (cpu_cycles);
                Serial.print ( );
                Serial.print (elapsed_us);
                Serial.print ( );
                Serial.print (estimated_current_ma, 1);
                Serial.print ( );
                Serial.print (energy_mj, 3);
                Serial.println ();

                // Small delay between operations
                delayMicroseconds (100);
            }
        }

        // Move to next payload size
        payload_size += PAYLOAD_INCREMENT;

        // Brief pause between payload sizes
        Serial.println ();
        delay (100);
    }
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
    } else {
        Serial.println (ERROR: Failed to set clock frequency!);
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

    // Encrypt the data using AES128 in CTR mode
    // GCM internally:
    // 1. Encrypts counter blocks with AES128 to generate keystream
    // 2. XORs keystream with plaintext to produce ciphertext
    // 3. Simultaneously prepares data for GMAC authentication
    gcm.encrypt (out, data, data_size);

    // Compute and retrieve the GMAC authentication tag
    // GMAC uses Galois field (GF(2^128)) multiplication
    gcm.computeTag (tag, GCM_TAG_SIZE);
}

bool
decryptDataGCM (const byte *data, int data_size, const byte *tag, byte *out)
{
    // Clear the GCM state to prepare for decryption
    gcm.clear ();

    // Decrypt the data
    gcm.decrypt (out, data, data_size);

    // Verify the authentication tag
    // This recomputes the GMAC tag and compares using constant-time comparison
    bool verified = gcm.checkTag (tag, GCM_TAG_SIZE);

    return verified;
}
