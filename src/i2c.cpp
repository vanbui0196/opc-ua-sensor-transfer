#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

// Multithread handler library
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <thread>

// Utility library
#include <chrono>
#include <functional>
#include <iomanip>
#include <iostream>
#include <span>
#include <sstream>

// Additional includes for MODE processing
#include <algorithm>
#include <chrono>
#include <cmath>
#include <map>
#include <vector>

#include "cert_parser.h"
#include "key_parser.h"
#include "mldsa.h"
#include "opcua_i2c.h"

extern "C" {
#include "fips202.h"
}

using namespace std::literals;  // Geting the name more essy of chrono

/****************************
 * I2C Related configuration
 ***************************/
// Global data structure for external access
i2c_data_structure_t i2c_shared_data;

// I2C register address
constexpr int DEV_I2C_REG_ADDR = 0x42;

// Struct configuring the sensor
struct i2c_config {
  int ts;  // sampling rate in microseconds
  int td;  // time interval in microseconds
  int i2c_fd;
};

/****************************
 * Thread related data
 ***************************/
// Thread synchronization
std::shared_mutex data_mutex_shared;
std::atomic<bool> i2c_running_flg{true};
std::atomic<bool> i2c_init_flg{false};
std::atomic<int> measurement_sample_count{0};
/********************************************************************
 * Randomized data -> allowing to run without sensor on local network
 *******************************************************************/
std::atomic<bool> is_randomized{true};

/**
 * @brief I/O report function incase of error with fallback function
 *
 * @param cond condition for triggering the error report
 * @param message message reply to the console
 * @param callback_fn calback function
 */
void IO_ERROR_REPORT_COND(bool cond, std::string message,
                          std::function<void(void)> callback_fn) {
  if (true == cond) {
    // Printout the error
    std::cerr << message << std::endl;

    // Handler the function
    if (nullptr != callback_fn) {
      callback_fn();
    }
  }
}

/********************************************************************************
 * GPIO and I2C Functions
 ********************************************************************************/

/**
 * @brief Sensor are controlled by external MCU which can be reset
 * with the GPIO15 + GPIO16 -> Reset the MCU each time connect to sensor
 *
 */
void gpio_reset() {
  // Reset the GPIO pin
  std::cout << "Setting up the GPIO ..." << std::endl;

  // Get the pin the chip for the
  struct gpiod_chip *gpio0_chip;
  struct gpiod_line *gpio0_pin16;

  // Temporary return value
  int retVal;

  // Open the GIPO0 chip (other chip related to other peripherals, dont' use it
  // -> board damage)
  gpio0_chip = gpiod_chip_open("/dev/gpiochip0");

  // Print the error in case of the error
  IO_ERROR_REPORT_COND((nullptr == gpio0_chip), "Cannot open the chip",
                       nullptr);

  // Get the line 15 and 16 for gpio
  gpio0_pin16 = gpiod_chip_get_line(gpio0_chip, 16);

  // report error incase harwadware cannot open
  IO_ERROR_REPORT_COND((nullptr == gpio0_pin16), "Cannot open pin 15 or 16",
                       [gpio0_chip] { gpiod_chip_close(gpio0_chip); });

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

/**
 * @brief Configure I2C with the configuration
 *
 * @param file file of i2c in linux
 * @param config configuration
 * @return true configurue success
 * @return false consifutre failure
 */
bool configure_i2c(int file, i2c_config &config) {
  // ==============================================
  // randomized data is used -> don't need to check
  // ==============================================
  if (is_randomized == true) {
    return true;
  }

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

  std::cout << "I2C configuration sent: T_S=" << config.ts << " (0x" << std::hex
            << (int)ts_byte << "), T_D=" << std::dec << config.td << " (0x"
            << std::hex << (int)td_high << std::hex << (int)td_low << ")"
            << std::dec << std::endl;

  return true;
}

/**
 * @brief This will read a sample of i2c.
 * This is 100% convert from Python file.
 * I don't have any data sheet of the sensor
 *
 * @param file Point to the I2C pointer
 * @return float Speed value of current
 */
float read_single_sample(int file) {
  if (true == is_randomized) {
    static int loc_Counter = 0;
    static int sample_count{0};

    if (sample_count > 500 && sample_count < 1000) {
      loc_Counter = loc_Counter - 10;

    } else {
      loc_Counter = loc_Counter + 10;
    }
    sample_count++;

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
 * @brief NEW: This will read a sample of i2c with rounding (matches Python
 * behavior). This is 100% convert from Python file. I don't have any data sheet
 * of the sensor
 *
 * @param file Point to the I2C pointer
 * @return float Speed value of current with 2 decimal rounding
 */
float read_single_sample_rounded(int file) {
  if (true == is_randomized) {
    static int loc_Counter = 0;
    static int sample_count{0};

    if (sample_count > 500 && sample_count < 1000) {
      loc_Counter = loc_Counter - 10;

    } else {
      loc_Counter = loc_Counter + 10;
    }
    sample_count++;

    // Round to 2 decimal places like Python
    float raw_result = ((float)loc_Counter * 0.073f);
    return std::round(raw_result * 100.0f) / 100.0f;
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

  // Apply conversion factor AND round to 2 decimal places (like Python)
  float result = raw_data * 0.073f;
  return std::round(result * 100.0f) / 100.0f;
}

/**
 * @brief Get the median object of the I2C sensor
 *
 * @param values Array of the float value
 * @param count Number of total sample
 * @return float
 */
float median_filter(float values[], int count) {
  if (count == 0) return -1;

  // Simple bubble sort. No need to call the O(n * log(n)) of the function
  // STL,only 40 samples
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

/**
 * @brief NEW: Get the MODE (most frequent value) from array - matches Python
 * behavior exactly
 *
 * @param values Array of float values
 * @param count Number of samples
 * @return float Most frequent value, or median of modes if tie
 */
float mode_filter(float values[], int count) {
  if (count == 0) return -1.0f;

  // Create frequency map (equivalent to Python dictionary)
  std::map<float, int> freq;
  for (int i = 0; i < count; i++) {
    freq[values[i]]++;  // Count occurrences
  }

  // Find the maximum frequency
  int max_freq = 0;
  for (const auto &pair : freq) {
    if (pair.second > max_freq) {
      max_freq = pair.second;
    }
  }

  // Collect all values that appear with maximum frequency
  std::vector<float> modes;
  for (const auto &pair : freq) {
    if (pair.second == max_freq) {
      modes.push_back(pair.first);
    }
  }

  // If multiple modes, return median of the modes (Python behavior)
  if (modes.size() > 1) {
    std::sort(modes.begin(), modes.end());
    size_t mid = modes.size() / 2;
    return modes[mid];
  }

  // Return the single mode
  return modes[0];
}

/**
 * @brief reading sensor value from the i2c sensor. This is 100% convert from
 * the python file of the predecessor owner, i don't have any datasheet of the
 * sensor
 *
 * @param file file to the linux sensor
 * @return float sensor value with the filtered median.
 */
float read_sensor_data(int file) {
  float samples[40];
  int valid_samples = 0;

  // std::cout << "Taking 40 samples..." << std::endl;

  // Take 40 samples with 25ms intervals
  for (int i = 0; i < 40 && i2c_running_flg; i++) {
    float sample = read_single_sample_rounded(file);  // Use rounded version now
    if (sample >= 0) {
      samples[valid_samples++] = sample;
    } else {
      // Do nothing, just filter out the value
    }

    // Sleep 25ms and waiting for next reading
    std::this_thread::sleep_for(25ms);  // 25ms delay
  }

  if (valid_samples > 0) {
    float result =
        mode_filter(samples, valid_samples);  // Use MODE instead of median
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
bool i2c_get_current_data(i2c_data_structure_t &data) {
  // Reading data only, no need to use the exculsive lock
  std::shared_lock<std::shared_mutex> lock(data_mutex_shared);
  data = i2c_shared_data;
  return data.is_data_valid_flg;
}

/**
 * @brief Check if i2c sensor is initialized or not
 *
 * @return true sensor initialization is finish
 * @return false sensor initialization is not finish
 */
// Function to check if I2C is initialized
bool i2c_init_check() { return i2c_init_flg; }

// Function to stop I2C reading
void i2c_stop_handler() { i2c_running_flg = false; }

/********************************************************************************
 * I2C Reader Thread Function
 ********************************************************************************/
void i2c_reader_thread() {
  std::cout << "Starting I2C reader thread..." << std::endl;

  i2c_config config;
  int i2c_fd = -1;

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

    config.i2c_fd = i2c_fd;
    i2c_init_flg = true;

    std::cout << "I2C reader thread initialized successfully" << std::endl;

    // Step 4: Continuous reading loop
    int reading_count = 0;
    while (i2c_running_flg) {
      float speed = read_sensor_data(i2c_fd);
      time_t current_time = time(nullptr);
      std::string currentTime_str = ctime(&current_time);
      currentTime_str.pop_back();

      // Get high-precision time
      auto now = std::chrono::system_clock::now();
      auto time_t_now = std::chrono::system_clock::to_time_t(now);
      auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(
                              now.time_since_epoch()) %
                          1000000;

      // Convert the data from float to string (this is because <format> still
      // not fully support on the GCC12 on Raspberry Pi)
      std::ostringstream string_stream;

      // Create time string with microseconds after seconds
      std::ostringstream time_stream;
      time_stream << std::put_time(std::localtime(&time_t_now),
                                   "%a %b %d %H:%M:%S");
      time_stream << "." << std::setfill('0') << std::setw(6)
                  << microseconds.count();
      time_stream << std::put_time(std::localtime(&time_t_now), " %Y");
      std::string currTime_chrono = time_stream.str();

      // Combine speed and time string
      string_stream << std::fixed << std::setprecision(2) << speed << " "
                    << currTime_chrono;
      std::string tempRawData_str = string_stream.str();

      // Update global data with thread safety
      {
        std::unique_lock<std::shared_mutex> lock(data_mutex_shared);

        if (speed >= 0) {
          // Update data to global structure
          i2c_shared_data.current_data = speed;
          i2c_shared_data.is_data_valid_flg = true;
          i2c_shared_data.last_timestamp = current_time;
          i2c_shared_data.raw_data_str = tempRawData_str;

          // ===================================
        } else {
          i2c_shared_data.is_data_valid_flg = false;
          std::cerr << "[I2C Thread] Failed to get valid reading #"
                    << ++reading_count << std::endl;
        }
      }

      // Small delay to prevent CPU overload
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
  } catch (std::runtime_error &e) {
    std::cerr << e.what() << std::endl;
  } catch (const std::exception &e) {
    std::cerr << "I2C reader thread exception: " << e.what() << std::endl;
  } catch (...) {
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
bool i2c_init() {
  // Initialize global data
  memset(&i2c_shared_data, 0, sizeof(i2c_shared_data));
  i2c_running_flg = true;
  i2c_init_flg = false;

  std::cout << "I2C module initialized" << std::endl;
  return true;
}

/**
 * @brief Function for set flag of i2c running status
 *
 */
void i2c_cleanup_handler() {
  i2c_running_flg = false;
  std::cout << "I2C module cleanup completed" << std::endl;
}
