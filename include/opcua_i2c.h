#ifndef I2C_READER_THREADED_H
#define I2C_READER_THREADED_H

#include <gpiod.h>
#include <time.h>

#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <span>
#include <thread>

#include "mldsa.h"
#define OPCUA_SERVER_RAW_DATA_SIZE 10  // 2 bytes length + 8 bytes of data

/********************************************************************************
 * I2C Shared Data Structure
 ********************************************************************************/
typedef struct {
  bool is_data_valid_flg;
  float current_data;     // current speed value
  time_t last_timestamp;  // data and time
  std::string raw_data_str;
} i2c_data_structure_t;

/********************************************************************************
 * External API Function Declarations
 ********************************************************************************/

/**
 * @brief Initialize the I2C module
 * @return true if initialization successful, false otherwise
 */
bool i2c_init();

/**
 * @brief Get current sensor data (thread-safe)
 * @param data Reference to data structure to fill
 * @return true if valid data available, false otherwise
 */
bool i2c_get_current_data(i2c_data_structure_t &data);

/**
 * @brief Check if I2C is initialized and ready
 * @return true if initialized, false otherwise
 */
bool i2c_init_check();

/**
 * @brief Stop I2C reading thread
 */
void i2c_stop_handler();

/**
 * @brief Cleanup I2C module resources
 */
void i2c_cleanup_handler();

/**
 * @brief Main I2C reader thread function
 * Call this in a separate thread
 */
void i2c_reader_thread();

void i2c_sensor_signing(std::span<uint8_t> dataIn, std::span<uint8_t> sigOut);

/*********************************************
 * extern the variable in case of usage demand
 *********************************************/
extern std::shared_mutex data_mutex_shared;
extern std::atomic<bool> i2c_running_flg;
extern std::atomic<bool> i2c_init_flg;
extern i2c_data_structure_t i2c_shared_data;

#endif  // I2C_READER_THREADED_H
