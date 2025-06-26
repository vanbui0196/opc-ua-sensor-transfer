#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <string.h>

// Multithread handler library
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <atomic>

// Utility library
#include <span>
#include <chrono>
#include <iostream>
#include <sstream>
#include <iomanip>
#include "opcua_i2c.h"
#include <functional>
#include "mldsa.h"
#include "key_parser.h"
#include "cert_parser.h"

extern "C" {
    #include "fips202.h"
}
#include <boost/algorithm/clamp.hpp>

using namespace std::literals; // Geting the name more essy of chrono

#define OPCUA_SERVER_RAW_DATA_SIZE          10         // 2 bytes length + 8 bytes of data

//----------------------------
// Global  Memory for Signing
//----------------------------
MLDSA mldsa_signer;
std::array<uint8_t, CRYPTO_SECRETKEYBYTES> OpcUa_SecretKey_array;

/********************************************************************************
 * Global data structure for sharing with OPC UA server
 ********************************************************************************/

// Global data structure for external access
I2C_SharedData_tst g_I2C_SharedData;

// Thread synchronization
std::shared_mutex g_dataMutex;
std::atomic<bool> g_running{true};
std::atomic<bool> g_i2cInitialized{false};
std::atomic<bool> debugFlag_RandomizedData_b{true};
/********************************************************************************
 * I2C Configuration Structure
 ********************************************************************************/
struct I2C_Config {
    int ts;  // sampling rate in microseconds
    int td;  // time interval in microseconds
    int i2c_fd;
};

// I2C register address
constexpr int DEV_I2C_REG_ADDR = 0x42;
/**
 * @brief Error report of the I2C module
 * 
 */
void IO_ERROR_REPORT_COND(bool cond, std::string message, std::function<void(void)> err_handler_callback) {
    if(true == cond) {
        // Printout the error
        std::cerr << message << std::endl;

        // Handler the function
        if(nullptr != err_handler_callback) {
            err_handler_callback();
        }
    }
}

/********************************************************************************
 * GPIO and I2C Functions
 ********************************************************************************/
/**
 * @brief Reset the micro controller using the giod system
 * @attention gpiod must be installed on the system: sudo apt install libgpiod-dev
 * 
 */

void gpio_reset() {
    // Reset the GPIO pin
    std::cout << "Setting up the GPIO ..." << std::endl;

    // Get the pin the chip for the
    struct gpiod_chip* gpio0_chip;
    struct gpiod_line *gpio0_pin16;

    // Temporary return value
    int retVal;

    // Open the GIPO0 chip (other chip related to other peripherals, dont' use it -> board damage)
    gpio0_chip = gpiod_chip_open("/dev/gpiochip0");

    // Print the error in case of the error
    IO_ERROR_REPORT_COND((nullptr == gpio0_chip), "Cannot open the chip", nullptr);

    // Get the line 15 and 16 for gpio
    gpio0_pin16 = gpiod_chip_get_line(gpio0_chip, 16);

    // Close the harware
    IO_ERROR_REPORT_COND(
        (nullptr == gpio0_pin16), 
        "Cannot open pin 15 or 16",
        [gpio0_chip] {
            gpiod_chip_close(gpio0_chip);
        }
    );

    // Put the status of PIN16 to LOW, but won't care the return status
   (void)gpiod_line_request_output(gpio0_pin16, "mygpio", 0);

   // Sleep for 500ms -> release the resouce holding
    std::this_thread::sleep_for(500ms);

    // Set the pinback to HIGH, then release the resource for 2s
    gpiod_line_set_value(gpio0_pin16, 1);
    std::this_thread::sleep_for(2s);

    // Set the pin16 back to LOW
    gpiod_line_set_value(gpio0_pin16, 0);

    // Don't need the GPIO anymore, then release the line + chip
    gpiod_line_release(gpio0_pin16);
    gpiod_chip_close(gpio0_chip);
}

bool configure_i2c(int file, I2C_Config& config) {

    // ===================
    // DEBUG PURPOSE ONLY
    // ===================
    if(debugFlag_RandomizedData_b == true) {
        return true;
    }
    // ===================

    std::cout << "Enter sampling rate T_S in microseconds (default 100): ";
    std::string input;
    std::getline(std::cin, input);
    if (input.empty()) {
        config.ts = 100;
    } else {
        config.ts = std::stoi(input);
    }
    
    std::cout << "Enter time interval T_D in microseconds (default 1000): ";
    std::getline(std::cin, input);
    if (input.empty()) {
        config.td = 1000;
    } else {
        config.td = std::stoi(input);
    }
    
    unsigned char ts_byte = (unsigned char)(config.ts & 0xFF);
    unsigned char td_high = (config.td >> 8) & 0xFF;
    unsigned char td_low = config.td & 0xFF;
    
    // Send T_S as single byte
    if (write(file, &ts_byte, 1) != 1) {
        std::cerr << "Failed to send T_S" << std::endl;
        return false;
    }
    
    // Send T_D as two bytes
    if (write(file, &td_high, 1) != 1) {
        std::cerr << "Failed to send T_D high byte" << std::endl;
        return false;
    }
    
    if (write(file, &td_low, 1) != 1) {
        std::cerr << "Failed to send T_D low byte" << std::endl;
        return false;
    }
    
    std::cout << "I2C configuration sent: T_S=" << config.ts 
              << " (0x" << std::hex << (int)ts_byte << "), T_D=" << std::dec << config.td 
              << " (0x" << std::hex << (int)td_high << std::hex << (int)td_low << ")" << std::dec << std::endl;
    
    return true;
}

/**
 * @brief This will read a sample of i2c
 * 
 * @param file Point to the I2C pointer
 * @return float Speed value of current
 */
float read_single_sample(int file) {

    // ===================
    // DEBUG PURPOSE ONLY
    // ===================

    // ===================
    if(true == debugFlag_RandomizedData_b) {
        static int loc_Counter = 0;
        loc_Counter = loc_Counter + 10;
        return ((float)loc_Counter * 0.073f);
    }
    
    unsigned char reg = 0x01;
    unsigned char data[2];
    int raw_data;
    
    // Write register address
    if (write(file, &reg, 1) != 1) {
        return -1;
    }
    
    // Read 2 bytes of data
    if (read(file, data, 2) != 2) {
        return -1;
    }
    
    // Combine bytes (little-endian)
    raw_data = (data[1] << 8) | data[0];
    
    // Filter out peak values
    if (raw_data >= 12000) {
        return -1;
    }
    
    // Handle negative values
    if (raw_data & 0x80) {
        raw_data &= ~(1 << 7);
        raw_data = -raw_data;
    }
    
    // Apply conversion factor
    return raw_data * 0.073f;
}

/**
 * @brief Get the median object of the I2C sensor
 * 
 * @param values Array of the float value
 * @param count Number of total sample
 * @return float 
 */
float get_median(float values[], int count) {
    if (count == 0) return -1;
    
    // Simple bubble sort
    for (int i = 0; i < count - 1; i++) {
        for (int j = i + 1; j < count; j++) {
            if (values[i] > values[j]) {
                float temp = values[i];
                values[i] = values[j];
                values[j] = temp;
            }
        }
    }
    return values[count / 2];  // Return median
}

float read_sensor_data(int file) {
    float samples[40];
    int valid_samples = 0;
    
    //std::cout << "Taking 40 samples..." << std::endl;
    
    // Take 40 samples with 25ms intervals
    for (int i = 0; i < 40 && g_running; i++) {
        float sample = read_single_sample(file);
        if (sample >= 0) {
            samples[valid_samples++] = sample;
        } else {
            // Do nothing, just filter out the value
        }

        // Sleep 25ms and waiting for next reading
        std::this_thread::sleep_for(25ms);  // 25ms delay
    }
    
    if (valid_samples > 0) {
        float result = get_median(samples, valid_samples);
        //std::cout << "Valid samples: " << valid_samples << "/40, Result: " << result << std::endl;
        std::cout << "Current speed: " << result << std::endl;
        return result;
    }
    
    return -1;
}

/********************************************************************************
 * External API Functions for OPC UA Server Integration
 ********************************************************************************/

/**
 * @brief Data for return to the reader
 * 
 * @param data 
 * @return true Data is good for reading
 * @return false Data is not good engough for reading
 */
bool I2C_GetCurrentData(I2C_SharedData_tst& data) {
    // Reading data only, no need to use the exculsive lock
    std::shared_lock<std::shared_mutex> lock(g_dataMutex);
    data = g_I2C_SharedData;
    std::cout << "[DEBUG - TO BE DELETED]: Seeed: " << g_I2C_SharedData.currentSpeed << std::endl;
    return data.dataValid_b;
}

/**
 * @brief Check if i2c sensor is initialized or not
 * 
 * @return true sensor initialization is finish
 * @return false sensor initialization is not finish
 */
// Function to check if I2C is initialized
bool I2C_IsInitialized() {
    return g_i2cInitialized;
}

// Function to stop I2C reading
void I2C_Stop() {
    g_running = false;
}

/********************************************************************************
 * I2C Reader Thread Function
 ********************************************************************************/
void i2c_reader_thread() {
    std::cout << "Starting I2C reader thread..." << std::endl;
    
    I2C_Config config;
    int i2c_fd = -1;
    // Temporary array to get the signature
    std::array<uint8_t, CRYPTO_BYTES> sigOut;
    try {
        // Step 1: GPIO Reset
        gpio_reset();
        
        // Step 2: Open I2C
        i2c_fd = open("/dev/i2c-1", O_RDWR);
        if (i2c_fd < 0) {
            std::cerr << "Failed to open I2C bus" << std::endl;
            return;
        }
        
        if (ioctl(i2c_fd, I2C_SLAVE, DEV_I2C_REG_ADDR) < 0) {
            std::cerr << "Failed to set I2C address" << std::endl;
            close(i2c_fd);
            return;
        }
        
        // Step 3: Configure I2C
        if (!configure_i2c(i2c_fd, config)) {
            std::cerr << "Failed to configure I2C" << std::endl;
            close(i2c_fd);
            return;
        }
        
        // Read the key from the .DER file and store into global array
        KeyParser keyHolder("/home/vanbu/KeyAndCertificate/OpcUA/private_key.der", "ML-DSA-44");
        CertParser certHolder("/home/vanbu/KeyAndCertificate/OpcUA/certificate.der");

        std::array<uint8_t, 1312> tempPublicKey;

        for(size_t i = 0; i < certHolder.publicKey.size(); i++) {
            tempPublicKey.at(i) = certHolder.publicKey.at(i);
        }
        // Check if the key is size if fit for the application
        if(keyHolder.privateKey.size() != OpcUa_SecretKey_array.size()) {
            std::cerr << "!!! Secret key size is not as same as  !!!\n";
        } else {
            // Copy data from key to global key array
            std::copy_n(keyHolder.privateKey.begin(), keyHolder.privateKey.size(), OpcUa_SecretKey_array.begin());
        }
        
        config.i2c_fd = i2c_fd;
        g_i2cInitialized = true;
        
        std::cout << "I2C reader thread initialized successfully" << std::endl;
        
        // Step 4: Continuous reading loop
        int reading_count = 0;
        while (g_running) {
            float speed = read_sensor_data(i2c_fd);
            time_t current_time = time(nullptr);

            // Convert the data from float to string (this is because <format> still not fully support on the GCC12 on Raspberry Pi)
            std::ostringstream string_stream;

            std::string currentTime_str = ctime(&current_time);
            currentTime_str.pop_back();
            string_stream << std::fixed << std::setprecision(2) << speed << " " << currentTime_str;
            std::string tempRawData_str =  string_stream.str();
            std::cout << "[DEBUG] Current data and length: " << tempRawData_str << ", length: " << tempRawData_str.length() << std::endl;
    
            
            // Get the data buffer from the string 
            std::span<uint8_t> dataIn(reinterpret_cast<uint8_t*>(tempRawData_str.data()), tempRawData_str.size());

            std::array<uint8_t, 128> dataHash_au8; dataHash_au8.fill(0); // hash containning array
            I2C_Sensor_Signature_Signing(dataIn, sigOut, dataHash_au8);

            // Self verification
            int verify_result = mldsa_signer.Verify(sigOut.data(), sigOut.size(), dataHash_au8.data(), dataHash_au8.size(), nullptr, 0, tempPublicKey);

            // Update global data with thread safety
            {
                std::unique_lock<std::shared_mutex> lock(g_dataMutex);
                
                if (speed >= 0) {
                    // Update data to global structure
                    g_I2C_SharedData.currentSpeed = speed;
                    g_I2C_SharedData.dataValid_b = true;
                    g_I2C_SharedData.lastUpdateTime = current_time;
                    g_I2C_SharedData.rawData_str = tempRawData_str;

                    // Fetch the signature to the global structure
                    g_I2C_SharedData.signature.at(0) = (uint8_t)(CRYPTO_BYTES >> 8);
                    g_I2C_SharedData.signature.at(1) = (uint8_t)(CRYPTO_BYTES);

                    // Copy data from local buffer into the thread protected data
                    std::copy_n(sigOut.data(), CRYPTO_BYTES, g_I2C_SharedData.signature.data() + 2);

                    std::cout << "[I2C thread] Current data: " << tempRawData_str << std::endl;

                    // Test code - to removed ============
                    std::array<uint8_t, 128> _test;
                    std::cout << "[I2C thread] Size of data: " << tempRawData_str.size() << std::endl;
                    std::span<uint8_t> _tmpStr(reinterpret_cast<uint8_t*>(tempRawData_str.data()), tempRawData_str.size());
                    shake_test(_tmpStr, _test);

                    // == Debug ==
                    // /* Get the first 2 bytes for getting the length */
                    // uint8_t firstByte = g_I2C_SharedData.signature.at(0);
                    // uint8_t scndByte = g_I2C_SharedData.signature.at(1);

                    // size_t totalBytes = static_cast<size_t>(firstByte << 8) | static_cast<size_t>(scndByte);
                    
                    // for(size_t index = 0; index < totalBytes; index++) {
                    //     std::cout <<  std::setfill('0') << std::setw(2) << std::hex << (int)g_I2C_SharedData.signature.at(index) << " ";
                    // }
                    // std::cout << std::endl;
                    std::cout << "Main hash: " << std::endl;
                    for(auto each_byte : dataHash_au8) {
                        std::cout << std::hex << static_cast<int>(each_byte);
                    }
                    std::cout << std::endl;
                    std::cout << "Signature is valid:" << std::dec << verify_result << std::endl;
                    // ===================================
                } else {
                    g_I2C_SharedData.dataValid_b = false;
                    std::cerr << "[I2C Thread] Failed to get valid reading #" << ++reading_count << std::endl;
                }
            }
            
            // Small delay to prevent CPU overload
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
    } 
    catch (std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "I2C reader thread exception: " << e.what() << std::endl;
    }
    catch(...) {
        std::cerr << "Catch unexpected error" << std::endl;
    }

    // Cleanup
    if (i2c_fd >= 0) {
        close(i2c_fd);
    }
    
    // Cleanup GPIO
    std::cout << "I2C reader thread stopped" << std::endl;
}

/********************************************************************************
 * Initialization and Cleanup Functions (for external use)
 ********************************************************************************/

/**
 * @brief Function for initializing the sensor data
 * 
 */
bool I2C_Initialize() {
    // Initialize global data
    memset(&g_I2C_SharedData, 0, sizeof(g_I2C_SharedData));
    g_running = true;
    g_i2cInitialized = false;
    
    std::cout << "I2C module initialized" << std::endl;
    return true;
}

/**
 * @brief Function for set flag of i2c running status
 * 
 */
void I2C_Cleanup() {
    g_running = false;
    std::cout << "I2C module cleanup completed" << std::endl;
}

/**
 * @brief Signing the data with Shake 256
 * 
 * @param dataIn Data for signing (sensor data)
 * @param sigOut Signature of data
 * @return true Signature is ready
 * @return false Signature is not ready
 */
void I2C_Sensor_Signature_Signing(std::span<uint8_t> dataIn, std::span<uint8_t> sigOut, std::span<uint8_t> hashOutDbg) {
    // Local value
    bool retVal_b = false; // return value if the signature is available

    size_t sigLength{0};

    // shake init state
    keccak_state state;
    shake128_init(&state);

    // shake absorb state
    shake128_absorb(&state, dataIn.data(), dataIn.size());

    // finalize the shake
    shake128_finalize(&state);

    // Get the value of the shake128 function
    shake128_squeeze(hashOutDbg.data(), 128, &state);

    std::cout << std::endl;
    // Signing the data
    mldsa_signer.Sign(
        sigOut.data(),          // Signed mesasge
        &sigLength,             // Signed data lenth
        hashOutDbg.data(),    // Message in (hash of data with shake128)
        128,                    // Use all 128 byte of the message
        nullptr, 0,             // No context message at all
        OpcUa_SecretKey_array   // The array that set the secret key
    );
}

void shake_test(std::span<uint8_t> dataIn, std::span<uint8_t> hashOut) {
    keccak_state state;

    shake128_init(&state);

    shake128_absorb(&state, dataIn.data(), dataIn.size());

    shake128_finalize(&state);

    shake128_squeeze(hashOut.data(), hashOut.size(), &state);

    std::cout << "[I2C thread] Current Hash Value: ";
    for(auto each_byte : hashOut) {
        std::cout << std::hex << static_cast<int>(each_byte);
    }
    std::cout << std::endl;
}