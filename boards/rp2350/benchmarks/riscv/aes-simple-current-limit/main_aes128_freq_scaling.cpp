#include <Arduino.h>
#include <AES.h>
#include <Crypto.h>
#include <cstddef>
#include <cstdint>
#include <string.h>
#include <hardware/clocks.h>
#include <hardware/pll.h>
#include <pico/stdlib.h>

#define MEASURMENT_PIN 11
#define AES_BLOCK_SIZE 16

// Benchmark configuration
#define PAYLOAD_START 500
#define PAYLOAD_INCREMENT 255
#define PAYLOAD_MAX 4500
#define ITERATIONS_PER_SIZE 20

// Helper macro to calculate encrypted size
#define ENCRYPTED_SIZE(n) (((n) + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE * AES_BLOCK_SIZE)

// Power state definitions for RP2350
enum PowerState {
    FULL_POWER,      // 150 MHz (default)
    REDUCED_83,      // 125 MHz (83%)
    REDUCED_67,      // 100 MHz (67%)
    REDUCED_50,      // 75 MHz (50%)
    LOW_POWER        // 50 MHz (33%)
};

// Function declarations
void             encryptDataAES (const byte *data, int data_size, byte *out);
void             decryptDataAES (const byte *data, int data_size, byte *out);
void             runBenchmarks ();
void             fillSequentialPattern (byte *buffer, int size);
void             setCpuFrequency (uint32_t freq_mhz);
uint32_t         getCurrentCpuFreqMhz ();
void             setPowerState (PowerState state);
float            estimateCurrentDraw (uint32_t freq_mhz);
int              freeMemory ();
extern C char *sbrk (int incr);

// AES globals
AES128 aes128;
byte   key[AES_BLOCK_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                               0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

// Maximum payload size we'll test (with padding)
#define MAX_PAYLOAD 4325
#define MAX_ENCRYPTED ENCRYPTED_SIZE (MAX_PAYLOAD)

// Global buffers to avoid stack overflow
byte plaintext[MAX_PAYLOAD];
byte ciphertext[MAX_ENCRYPTED];
byte decrypted[MAX_ENCRYPTED];

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

    // Initialize AES with key
    aes128.setKey (key, 16);

    // Configure measurement pin
    pinMode (LED_BUILTIN, OUTPUT);
    pinMode (MEASURMENT_PIN, OUTPUT);
    digitalWrite (MEASURMENT_PIN, LOW);

    Serial.println (=== AES128 Encryption/Decryption Benchmark ===);
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
    
    Serial.print (Free SRAM at start: );
    Serial.print (freeMemory ());
    Serial.println ( bytes);
    
    Serial.print (Static buffer allocation: );
    Serial.print (MAX_PAYLOAD + MAX_ENCRYPTED + MAX_ENCRYPTED);
    Serial.println ( bytes);
    
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
    // Print CSV header with additional power metrics
    Serial.println (operation iteration payload_size cpu_freq_mhz cpu_cycles time_us current_ma energy_mj);
    Serial.println ();

    // Power states to test
    PowerState states[] = {FULL_POWER, REDUCED_83, REDUCED_67, REDUCED_50, LOW_POWER};
    int num_states = 5;

    // Calculate how many payload sizes we'll test
    int payload_size = PAYLOAD_START;

    while (payload_size <= PAYLOAD_MAX) {
        // Calculate encrypted size for this payload
        int encrypted_size = ENCRYPTED_SIZE (payload_size);

        // Fill plaintext with sequential pattern
        fillSequentialPattern (plaintext, payload_size);

        // Test at each power state
        for (int s = 0; s < num_states; s++) {
            setPowerState (states[s]);
            
            uint32_t cpu_freq_mhz = getCurrentCpuFreqMhz ();
            float estimated_current_ma = estimateCurrentDraw (cpu_freq_mhz);

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
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                // Energy calculation: Energy (mJ) = Voltage × Current (A) × Time (s) × 1000
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
                unsigned long cpu_cycles = (unsigned long)elapsed_us * cpu_freq_mhz;
                
                // Energy calculation
                float voltage = 3.3;
                float current_a = estimated_current_ma / 1000.0;
                float time_s = elapsed_us / 1000000.0;
                float energy_mj = voltage * current_a * time_s * 1000.0;

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
    // Default is 150 MHz
    
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
