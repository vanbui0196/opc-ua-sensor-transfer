#ifndef I2C_READER_THREADED_H
#define I2C_READER_THREADED_H

#include <thread>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <time.h>
#include <gpiod.h>
#include "mldsa.h"
#include <span>
#define OPCUA_SERVER_RAW_DATA_SIZE          10         // 2 bytes length + 8 bytes of data

/********************************************************************************
 * I2C Shared Data Structure
 ********************************************************************************/
typedef struct {
    bool dataValid_b;        
    float currentSpeed;      // current speed value
    time_t lastUpdateTime;   // data and time
    uint8_t signature[4097]; // data which contain the signature
    std::string rawData_str;
} I2C_SharedData_tst;

/********************************************************************************
 * External API Function Declarations
 ********************************************************************************/

/**
 * @brief Initialize the I2C module
 * @return true if initialization successful, false otherwise
 */
bool I2C_Initialize();

/**
 * @brief Get current sensor data (thread-safe)
 * @param data Reference to data structure to fill
 * @return true if valid data available, false otherwise
 */
bool I2C_GetCurrentData(I2C_SharedData_tst& data);

/**
 * @brief Check if I2C is initialized and ready
 * @return true if initialized, false otherwise
 */
bool I2C_IsInitialized();

/**
 * @brief Stop I2C reading thread
 */
void I2C_Stop();

/**
 * @brief Cleanup I2C module resources
 */
void I2C_Cleanup();

/**
 * @brief Main I2C reader thread function
 * Call this in a separate thread
 */
void i2c_reader_thread();

void I2C_Sensor_Signature_Signing(std::span<uint8_t> dataIn, std::span<uint8_t> sigOut);
void shake_test(std::span<uint8_t> dataIn, std::span<uint8_t> hashOut);
/********************************************************************************
 * External Global Variables (for advanced usage)
 ********************************************************************************/
extern std::shared_mutex g_dataMutex;
extern std::atomic<bool> g_running;
extern std::atomic<bool> g_i2cInitialized;
extern I2C_SharedData_tst g_I2C_SharedData;

#endif // I2C_READER_THREADED_H