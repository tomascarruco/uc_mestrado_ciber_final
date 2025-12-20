#include <Arduino.h>
#include <ChaCha.h>
#include <Crypto.h>
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

// ChaCha uses a 256-bit (32-byte) key exclusively
#define CHACHA_KEY_SIZE 32

// ChaCha20 typically uses a 96-bit (12-byte) nonce and 32-bit (4-byte) counter
#define CHACHA_IV_SIZE 16 // 12 bytes nonce + 4 bytes counter

// Power state definitions for RP2350
enum PowerState {
    FULL_POWER,      // 150 MHz (default)
    REDUCED_83,      // 125 MHz (83%)
    REDUCED_67,      // 100 MHz (67%)
    REDUCED_50,      // 75 MHz (50%)
    LOW_POWER        // 50 MHz (33%)
};

// Function declarations
void             encryptDataChaCha (const byte *data, int data_size, byte *out);
void             decryptDataChaCha (const byte *data, int data_size, byte *out);
void             runBenchmarks ();
void             fillSequentialPattern (byte *buffer, int size);
void             setCpuFrequency (uint32_t freq_mhz);
uint32_t         getCurrentCpuFreqMhz ();
void             setPowerState (PowerState state);
float            estimateCurrentDraw (uint32_t freq_mhz);
int              freeMemory ();
extern C char *sbrk (int incr);

// ChaCha cipher object - performs 20 rounds of mixing for strong security
ChaCha chacha;

// ChaCha uses a 256-bit (32-byte) key
byte key[CHACHA_KEY_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                              0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                              0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };

// Initialization Vector for ChaCha
byte iv[CHACHA_IV_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

// Maximum payload size - ChaCha is a stream cipher so no padding needed
#define MAX_PAYLOAD 4325

// Global buffers to avoid stack overflow
byte plaintext[MAX_PAYLOAD];
byte ciphertext[MAX_PAYLOAD];
byte decrypted[MAX_PAYLOAD];

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

    // Initialize ChaCha with 256-bit key
    chacha.setKey (key, CHACHA_KEY_SIZE);

    // Configure measurement pin
    pinMode (LED_BUILTIN, OUTPUT);
    pinMode (MEASURMENT_PIN, OUTPUT);
    digitalWrite (MEASURMENT_PIN, LOW);

    Serial.println (=== ChaCha20 Encryption/Decryption Benchmark ===);
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
    
    Serial.println (Cipher: ChaCha20 - Stream Cipher (20 rounds));
    Serial.println (Designer: Daniel J. Bernstein);
    
    Serial.print (Free SRAM at start: );
    Serial.print (freeMemory ());
    Serial.println ( bytes);
    
    Serial.print (Static buffer allocation: );
    Serial.print (MAX_PAYLOAD * 3);
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

            // === ENCRYPTION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                // Reset IV for each encryption
                chacha.setIV (iv, CHACHA_IV_SIZE);

                // Toggle measurement pin HIGH
                digitalWrite (MEASURMENT_PIN, HIGH);

                // Start timing
                unsigned long start_time = micros ();

                // Perform encryption using ChaCha20
                encryptDataChaCha (plaintext, payload_size, ciphertext);

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

            // === DECRYPTION BENCHMARK ===
            for (int iter = 1; iter <= ITERATIONS_PER_SIZE; iter++) {
                // Reset IV for decryption
                chacha.setIV (iv, CHACHA_IV_SIZE);

                // Toggle measurement pin HIGH
                digitalWrite (MEASURMENT_PIN, HIGH);

                // Start timing
                unsigned long start_time = micros ();

                // Perform decryption using ChaCha20
                decryptDataChaCha (ciphertext, payload_size, decrypted);

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
encryptDataChaCha (const byte *data, int data_size, byte *out)
{
    // ChaCha encryption - straightforward single call
    // Handles all 20 rounds of mixing internally
    chacha.encrypt (out, data, data_size);
}

void
decryptDataChaCha (const byte *data, int data_size, byte *out)
{
    // ChaCha decryption is computationally identical to encryption
    // Both operations generate the same keystream and XOR it with the input
    chacha.decrypt (out, data, data_size);
}
