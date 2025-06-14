#pragma once
#include <time.h>

template<typename T>
class Sensor_I2C {
private:
    // Current time stamp for the reconding
    time_t time_stamp;

    // Raw value
    std::string rawValue_str;


public:

    Sensor_I2C();

    time_t getCurrentTimeStap() {return time_stamp;}

    std::string getRawValueString() {return rawValue_str;}
};