/**
 * @file server.cpp
 * @author Bui Khanh Van
 * @brief
 * @version 0.1
 * @date 2025-07-30
 *
 * @copyright Copyright (c) 2025
 *
 */

#include <open62541/plugin/log_stdout.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>

/* General inclusion */
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <shared_mutex>
#include <thread>

#include "cert_parser.h"
#include "key_parser.h"
#include "opcua_i2c.h"
#define OPCUA_SERVER_CALLBACK_TIME 500  // 1 seconds in milliseconds
#define OPCUA_SERVER_EVENT_TIME 1000    // 1 seconds in milliseconds
#define OPCUA_SERVER_RAW_DATA_SIZE 10   // 2 bytes length + 8 bytes of data
#define OPCUA_SERVER_SIGNATURE_SIZE CRYPTO_BYTES  // 2 Signature buffer

std::string get_current_time_us() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                  now.time_since_epoch()) %
              1000000;

    std::ostringstream oss;
    oss << "[" << std::put_time(std::localtime(&time_t), "%H:%M:%S");
    oss << "." << std::setfill('0') << std::setw(6) << us.count() << "]";

    return oss.str();
}

//=============================
// MEASUREMENT PURPOSE
//=============================
std::chrono::_V2::system_clock::time_point signing_start_time;
int64_t signing_timestamp;
std::string signing_time;
//=======================
//----------------------------
// Global  Memory for Signing
//----------------------------
MLDSA mldsa_signer;
std::array<uint8_t, CRYPTO_SECRETKEYBYTES> OpcUa_SecretKey_array;

// array for storing the signature
std::array<uint8_t, OPCUA_SERVER_SIGNATURE_SIZE> OpcUa_SignatureBuf;

/*----------------------
 *  Mode selection
 *----------------------
 */
typedef enum { MODE_CALLBACK = 0, MODE_EVENT_DRIVEN = 1 } OperationMode_t;

OperationMode_t operation_mode{MODE_CALLBACK};

// repeative callback for the server
UA_UInt64 server_repeative_callback_id;
/*-------------------------------------------------------------------------
    Local API define
---------------------------------------------------------------------------*/
static bool update_data_from_i2c(void);

/**************************
 * NODE ID GLOBAL
 **************************/

UA_NodeId OpcUa_SpeedSensorObjId_st;
UA_NodeId OpcUa_Signature_ObjId_st;
UA_NodeId OpcUa_sensorName_st;
UA_NodeId OpcUa_sigType_st;
UA_NodeId OpcUa_sigLength_st;
UA_NodeId OpcUa_sensorSignatureId_NodeIdSt;
UA_NodeId OpcUa_sensorSpeedValue_NodeIdSt;
UA_NodeId OpcUa_sensorTimestamp_NodeIdSt;
UA_NodeId OpcUa_rawData_String_NodeIdSt;

// node id for the event driven mode
UA_NodeId value_increasement_event_typeid;
UA_NodeId value_increasement_event_id;

/*********************************
 * Global buffer for OPC UA server
 *********************************/
typedef struct {
    UA_Boolean is_data_valid_flg;
    UA_Byte signatureBuf_au8[OPCUA_SERVER_SIGNATURE_SIZE];
    UA_Float current_data;
    UA_DateTime last_timestamp;
    std::string data_and_timestamp;

    // event driven tracking
    UA_Boolean data_updated_since_last_check;
    UA_Boolean should_update_nodes;
} OpcUa_Server_globData_tst;

// Global data structure for OPC UA
OpcUa_Server_globData_tst OpcUa_Server_globData_st;

// Local server synchronization
std::mutex serverDataMutex;
std::mutex signingMutex;
// variable for event driven mode
UA_Float previous_data{0.0f};
bool first_sample{true};

/*****************************
 * OPC UA Server Functions
 *****************************/

/**
 * @brief Reading the value from I2C server.
 * According to the mode (EVENT_DRIVEN or CALLBACK mode), then the server data
 * structure will update according.
 */
static bool update_data_from_i2c(void) {
    i2c_data_structure_t i2c_data;
    bool is_valid_flg{false};

    // check if the i2c-driver is fined
    if (i2c_init_check()) {
        is_valid_flg = i2c_get_current_data(i2c_data);
    }

    // =====================================================================
    // Only signing data with valid patter, signing could block other
    // hence, signing must taking in lock-free region
    // =====================================================================
    // if (is_valid_flg) {
    //     // not taking much time, put here for saving coding space
    //     std::span<uint8_t> dataIn(
    //         reinterpret_cast<uint8_t *>(i2c_data.raw_data_str.data()),
    //         i2c_data.raw_data_str.size());
    //
    //     if (operation_mode == MODE_EVENT_DRIVEN) {
    //         if (true == first_sample || i2c_data.current_data > previous_data) {
    //             // only sign the proper data incase of the correct data
    //             i2c_sensor_signing(dataIn, OpcUa_SignatureBuf);
    //         } else {
    //             // do nothing since the data is not valid for signing
    //         }
    //     } else {
    //         // //=============================
    //         // // MEASUREMENT PURPOSE
    //         // //=============================
    //         // signing_start_time = std::chrono::high_resolution_clock::now();
    //         // signing_timestamp =
    //         // std::chrono::duration_cast<std::chrono::microseconds>(
    //         //                         signing_start_time.time_since_epoch())
    //         //                         .count();
    //         // signing_time = get_current_time_us();
    //         // signing_time += " ";
    //         // signing_time += std::to_string(signing_timestamp);
    //         // //=======================
    //         i2c_sensor_signing(dataIn, OpcUa_SignatureBuf);
    //     }
    // }

    {
        // lock-scope for the current data
        std::lock_guard<std::mutex> lock(serverDataMutex);
        if (is_valid_flg) {
            if (operation_mode == MODE_EVENT_DRIVEN) {
                // optain the data from last time for later comparision
                UA_Float temp_previous = OpcUa_Server_globData_st.current_data;

                /**
                    NOTE: data in the event-driven mode only update when current
                   data (read from i2c) > last_data. This mode is designed for
                   saving the traffic of network, only sending data when needed.
                */

                if (true == first_sample ||
                    i2c_data.current_data > previous_data) {
                    // update the temp previous
                    previous_data = temp_previous;

                    /* update the last value */
                    // set data valid
                    OpcUa_Server_globData_st.is_data_valid_flg = UA_TRUE;
                    // current sensor value
                    OpcUa_Server_globData_st.current_data =
                        i2c_data.current_data;
                    // current time_stamp
                    OpcUa_Server_globData_st.last_timestamp =
                        UA_DateTime_fromUnixTime(i2c_data.last_timestamp);
                    // string data
                    OpcUa_Server_globData_st.data_and_timestamp =
                        i2c_data.raw_data_str;
                    // copy the sensor
                    memcpy(OpcUa_Server_globData_st.signatureBuf_au8,
                           OpcUa_SignatureBuf.data(),
                           OPCUA_SERVER_SIGNATURE_SIZE);

                    // essential flag for the event driven mode
                    OpcUa_Server_globData_st.data_updated_since_last_check =
                        UA_TRUE;
                    OpcUa_Server_globData_st.should_update_nodes = UA_TRUE;

                    // since the first sample the current data is 0, data
                    // working must always work
                    first_sample = UA_FALSE;
                } else {
                    // marked in the server to not update the data
                    OpcUa_Server_globData_st.should_update_nodes = UA_FALSE;

                    // log the value during the development -> will be delete
                    // after finish development
                    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                                "[EVENT DRIVEN MODE]: sensor data not increase "
                                "%.2f < %.2f\n",
                                i2c_data.current_data, temp_previous);
                }
            } else {

                std::span<uint8_t> dataIn(
                    reinterpret_cast<uint8_t *>(i2c_data.raw_data_str.data()),
                    i2c_data.raw_data_str.size());
                // //=============================
                // // MEASUREMENT PURPOSE
                // //=============================
                signing_start_time = std::chrono::high_resolution_clock::now();
                signing_timestamp =
                std::chrono::duration_cast<std::chrono::microseconds>(
                                        signing_start_time.time_since_epoch())
                                        .count();
                signing_time = get_current_time_us();
                signing_time += " ";
                signing_time += std::to_string(signing_timestamp);
                // //=======================
                i2c_sensor_signing(dataIn, OpcUa_SignatureBuf);
                /**
                 * NOTE: data must always update in the case of callback mode
                 */

                // mark as valid value
                OpcUa_Server_globData_st.is_data_valid_flg = UA_TRUE;

                // current raw data (float) format
                OpcUa_Server_globData_st.current_data = i2c_data.current_data;

                // get the time stamp (not really need)
                OpcUa_Server_globData_st.last_timestamp =
                    UA_DateTime_fromUnixTime(i2c_data.last_timestamp);

                // the string data
                OpcUa_Server_globData_st.data_and_timestamp =
                    i2c_data.raw_data_str;

                // copy the signature from i2c-device driver -> the server
                // server
                memcpy(OpcUa_Server_globData_st.signatureBuf_au8,
                       OpcUa_SignatureBuf.data(), OPCUA_SERVER_SIGNATURE_SIZE);

                // mark the require flag
                OpcUa_Server_globData_st.data_updated_since_last_check =
                    UA_TRUE;
                OpcUa_Server_globData_st.should_update_nodes = UA_TRUE;

                // this flag is not needed anymore
                first_sample = UA_FALSE;
            }
        } else {
            // data is not valid -> mark this as failure nothing for transfering
            OpcUa_Server_globData_st.is_data_valid_flg = false;
            OpcUa_Server_globData_st.should_update_nodes = false;
        }
    }

    return is_valid_flg;
}

/**
 * @brief Create a data increasement event type object
 *
 * @param server pointer to the server
 * @return UA_StatusCode the status code of the server
 */
static UA_StatusCode create_data_increasement_event_type(UA_Server *server) {
    UA_StatusCode ret;
    UA_ObjectTypeAttributes obj_type_attr = UA_ObjectTypeAttributes_default;
    obj_type_attr.displayName =
        UA_LOCALIZEDTEXT("en-US", "Data Increasement Event Type");

    obj_type_attr.description =
        UA_LOCALIZEDTEXT("en-US", "Type for event triggered method");

    ret = UA_Server_addObjectTypeNode(
        server, UA_NODEID_STRING(1, "DataIncreasementEventType"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEEVENTTYPE),
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASSUBTYPE),
        UA_QUALIFIEDNAME(1, "DataIncresementEventType"), obj_type_attr, NULL,
        &value_increasement_event_typeid);

    return ret;
}

/**
 * @brief This sub-API is used for updating the nodes (string + signature)
 * incase of event-driven mode
 *
 * @param server pointer to the server
 * @param currentSpeed latest speed (logging purpose)
 * @param previousSpeed previous speed (logging purpose)
 */
static void trigger_data_increasing_event(UA_Server *server,
                                          UA_Float current_value,
                                          UA_Float previous_value) {
    // create the new event with the pre-defined type
    UA_StatusCode retval = UA_Server_createEvent(
        server, value_increasement_event_typeid, &value_increasement_event_id);
    if (retval != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                       "Failed to create speed increase event");
        return;
    }

    // Set event properties
    UA_Variant value;

    // set the message for the notification
    char messageBuffer[256];
    snprintf(messageBuffer, sizeof(messageBuffer),
             "Speed increased from %.2f to %.2f RPM", previous_value,
             current_value);
    UA_LocalizedText message = UA_LOCALIZEDTEXT("en-US", messageBuffer);
    UA_Variant_setScalar(&value, &message, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    UA_Server_writeObjectProperty_scalar(server, value_increasement_event_id,
                                         UA_QUALIFIEDNAME(0, "Message"), &value,
                                         &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);

    // Set severity (informational)
    UA_UInt16 severity = 100;
    UA_Variant_setScalar(&value, &severity, &UA_TYPES[UA_TYPES_UINT16]);
    UA_Server_writeObjectProperty_scalar(server, value_increasement_event_id,
                                         UA_QUALIFIEDNAME(0, "Severity"),
                                         &value, &UA_TYPES[UA_TYPES_UINT16]);

    // Set source name
    UA_String sourceName = UA_STRING("I2C Speed Sensor");
    UA_Variant_setScalar(&value, &sourceName, &UA_TYPES[UA_TYPES_STRING]);
    UA_Server_writeObjectProperty_scalar(server, value_increasement_event_id,
                                         UA_QUALIFIEDNAME(0, "SourceName"),
                                         &value, &UA_TYPES[UA_TYPES_STRING]);

    // Trigger the event
    retval = UA_Server_triggerEvent(server, value_increasement_event_id,
                                    OpcUa_SpeedSensorObjId_st, NULL, UA_TRUE);

    if (retval == UA_STATUSCODE_GOOD) {
        UA_LOG_INFO(
            UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
            "\033[1;32mEVENT TRIGGERED:\033[0m Speed increased from %.2f "
            "to %.2f RPM",
            previous_value, current_value);
    } else {
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                       "Failed to trigger speed increase event");
    }
}

/**
 * @brief Node update sub-API, this will update the relevant node based on
 * the mode. This sub-API will be called with the corresponding callback -
 * function from the main() function
 *
 * @param server pointer to the server of OPC-UA
 * @param mode_name name of mode (for logging purpose)
 */
static void update_opcua_nodes(UA_Server *server, std::string mode_name) {
    std::lock_guard<std::mutex> lock(serverDataMutex);
    /* -------------------------------------------------------------
        Return immediately incase of the node is shall not updated
        Case: - invalid data return from i2c file
              - prev_value > curr_value -> not update
     ---------------------------------------------------------------*/
    if (false == OpcUa_Server_globData_st.should_update_nodes) {
        return;
    }

    /* other cases happend here:
        1. callback mode (always update)
        2. event-driven and valid data
    */

    // transmiting string

    //=============================
    // MEASUREMENT PURPOSE
    //=============================
    // signing_start_time = std::chrono::high_resolution_clock::now();
    // signing_timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
    //                         signing_start_time.time_since_epoch())
    //                         .count();
    // signing_time = get_current_time_us();
    // signing_time += " ";
    // signing_time += std::to_string(signing_timestamp);
    //=======================

    UA_Variant data_time_variant;
    UA_String data_time_string =
        UA_STRING_ALLOC(OpcUa_Server_globData_st.data_and_timestamp.c_str());
    UA_Variant_setScalar(&data_time_variant, &data_time_string,
                         &UA_TYPES[UA_TYPES_STRING]);
    UA_Server_writeValue(server, OpcUa_rawData_String_NodeIdSt,
                         data_time_variant);

    // transmiting signature
    UA_Variant signature_buffer;
    UA_Variant_setArray(&signature_buffer,
                        OpcUa_Server_globData_st.signatureBuf_au8,
                        OPCUA_SERVER_SIGNATURE_SIZE, &UA_TYPES[UA_TYPES_BYTE]);
    UA_Server_writeValue(server, OpcUa_sensorSignatureId_NodeIdSt,
                         signature_buffer);
    /*
    ----------------------------
     LOG: Debug purpsoe
    ----------------------------
    */
    std::string log_data =
        std::string(reinterpret_cast<char *>(data_time_string.data),
                    data_time_string.length);

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                "\033[1;36m[%s] SERVER DATA:\033[0m \033[1;35m%s\033[0m",
                mode_name.c_str(), log_data.c_str());
    std::cout << signing_time << std::endl;

    /*
    -----------------------------------------------------
     EVENT_DRIVEN: trigger event for notifying the event
    -----------------------------------------------------
    */
    if (operation_mode == MODE_EVENT_DRIVEN &&
        true == OpcUa_Server_globData_st.should_update_nodes) {
        trigger_data_increasing_event(
            server, OpcUa_Server_globData_st.current_data, previous_data);
    }

    // then reset the flag and free the memory for next time usage
    OpcUa_Server_globData_st.should_update_nodes = UA_FALSE;
    UA_String_clear(&data_time_string);
}

/**
 * @brief callback function which will be called from server
 *
 * @param server pointer to the server
 * @param data unused param (required by prototype)
 */
static void update_sendor_data_callback(UA_Server *server, void *data) {
    // get the data from i2c
    bool is_valid_data = update_data_from_i2c();

    if (is_valid_data) {
        // update the nodes with callback
        update_opcua_nodes(server, "CALLBACK_MODE");
    } else {
        // log the failure case
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                       "[CALLBACK_MODE] Data Invalid\n");
    }
}

static void update_sendor_data_event_mode(UA_Server *server, void *data) {
    // get the data from i2c
    bool is_valid_data = update_data_from_i2c();

    if (is_valid_data) {
        bool should_update{false};
        UA_Float current_value{0.0f};

        {
            // Lock-guard to avoid data race
            std::lock_guard<std::mutex> lock(serverDataMutex);
            should_update = OpcUa_Server_globData_st.should_update_nodes;
            current_value = OpcUa_Server_globData_st.current_data;
        }

        // actually, this is check is not required since the check already
        // performed in the beginning of update_opcua_nodes
        if (should_update) {
            update_opcua_nodes(server, "EVENT_DRIVEN");
        }
    } else {
        // log the failure case
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                       "[EVENT_DRIVEN] Data Invalid\n");
    }

    // reset this flag, but it not required in data handler
    {
        std::lock_guard<std::mutex> lock(serverDataMutex);
        OpcUa_Server_globData_st.data_updated_since_last_check = UA_FALSE;
    }
}

/*
--------------------------------------------------------------
    Unix signal handler
--------------------------------------------------------------
*/
thread_local static volatile UA_Boolean opcua_running = true;

/**
 * @brief Software interrupt handler with Linux system
 *
 * @param sig Stop with SIGINT or SIGTERM
 */
static void stopHandler(int sig) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "Received stop signal");
    opcua_running = false;
    i2c_stop_handler();
}

int main(int argc, char **argv) {
    /*
    -----------------------------------------------------
        set mode for the server
    -----------------------------------------------------
    */
    if (argc > 1) {
        if (strcmp(argv[1], "0") == 0 || strcmp(argv[1], "CALLBACK") == 0) {
            operation_mode = MODE_CALLBACK;
        } else if (strcmp(argv[1], "1") == 0 || strcmp(argv[1], "EVENT") == 0) {
            operation_mode = MODE_EVENT_DRIVEN;
        } else {
            std::cerr << "Invalid argument, only: \n"
                      << "CALLBACK mode: 0 or CALLBACK\n"
                      << "EVENT mode: 1 or EVENT" << std::endl;
        }
    }

    /*===========================================================================
      Read the certificate in the first cycle
      ===========================================================================*/
    // Read the key from the .DER file and store into global array
    KeyParser keyHolder(
        "/home/vanbu/KeyAndCertificate/OpcUA/mldsa_87/private_key.der",
        "ML-DSA-87");

    // Check if the key is size if fit for the application
    if (keyHolder.privateKey.size() != OpcUa_SecretKey_array.size()) {
        std::cerr << "!!! Secret key size is not as same as  !!!\n";
    } else {
        // Copy data from key to global key array
        std::copy_n(keyHolder.privateKey.begin(), keyHolder.privateKey.size(),
                    OpcUa_SecretKey_array.begin());
    }
    /*
    -------------------------------------------------
        start the sensor communication
    -------------------------------------------------
    */
    std::cout << "=== OPC UA Server with I2C Speed Sensor Integration ==="
              << std::endl;

    // Initialize I2C module
    if (!i2c_init()) {
        std::cerr << "Failed to initialize I2C module" << std::endl;
        return 1;
    }

    // Initialize OPC UA global data
    memset(&OpcUa_Server_globData_st, 0, sizeof(OpcUa_Server_globData_st));

    // Register the signal handler
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    // Start I2C reader thread
    std::cout << "Starting I2C reader thread..." << std::endl;
    std::thread i2cThread(i2c_reader_thread);

    // Wait for I2C initialization
    std::cout << "Waiting for I2C initialization..." << std::endl;
    int timeout_count = 0;
    while (!i2c_init_check() && opcua_running && timeout_count < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        timeout_count++;
    }

    if (!opcua_running) {
        std::cout << "Shutdown requested before I2C initialization"
                  << std::endl;
        if (i2cThread.joinable()) {
            i2cThread.join();
        }
        i2c_cleanup_handler();
        return 1;
    }

    if (!i2c_init_check()) {
        std::cout
            << "I2C initialization timeout. Starting OPC UA server anyway..."
            << std::endl;
    } else {
        std::cout << "I2C initialized successfully!" << std::endl;
    }

    std::cout << "Starting OPC UA server..." << std::endl;

    /* Create a server with default configuration */
    UA_Server *server = UA_Server_new();
    UA_ServerConfig_setDefault(UA_Server_getConfig(server));

    /*
    ---------------------
        OBJECT NODES
    ---------------------
     */

    /**
     *
     * Each sensor will contain the following configuration for each sensor
     *
     * Sensor Object
     *  ├── (String) Data with Time Stamp
     *  ├── (String) Sensor Type/Name
     *  └── (UA_Object) Signature Object
     *      ├── (String) Signature Algorithm Name
     *      ├── (String) Signature Length
     *      └── (Bytes) Signature Byte Buffer
     */

    // Create the main sensor object
    UA_ObjectAttributes spdSensorObjAttribute_st = UA_ObjectAttributes_default;
    spdSensorObjAttribute_st.displayName =
        UA_LOCALIZEDTEXT("en-US", "Speed.Sensor");
    spdSensorObjAttribute_st.description = UA_LOCALIZEDTEXT(
        "en-US",
        "Motor rotational Speed monitored with I2C communication standard");

    UA_Server_addObjectNode(server, UA_NODEID_STRING(1, "Speed.Sensor"),
                            UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
                            UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                            UA_QUALIFIEDNAME(1, "I2C Speed Sensor"),
                            UA_NODEID_NUMERIC(0, UA_NS0ID_BASEOBJECTTYPE),
                            spdSensorObjAttribute_st, NULL,
                            &OpcUa_SpeedSensorObjId_st);

    // Contructor testing
    UA_ObjectAttributes signatureObject_st = UA_ObjectAttributes_default;
    signatureObject_st.displayName = UA_LOCALIZEDTEXT("en-US", "Signature");
    signatureObject_st.description =
        UA_LOCALIZEDTEXT("en-US", "Signature Object");

    UA_Server_addObjectNode(
        server, UA_NODEID_STRING(1, "Signature.Object"),
        OpcUa_SpeedSensorObjId_st,  // -> Parent shall be the object node id
        UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
        UA_QUALIFIEDNAME(1, "Signature"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEOBJECTTYPE), signatureObject_st, NULL,
        &OpcUa_Signature_ObjId_st);

    /*
    ---------------------
        VARIABLE NODES
    ---------------------
     */

    /* ========= sensor name =================================================
     */
    UA_VariableAttributes sensorNameAttribute_st =
        UA_VariableAttributes_default;
    UA_String sensorName_uastr = UA_STRING("I2C Motor Speed Sensor (rpm)");
    UA_Variant_setScalar(&sensorNameAttribute_st.value, &sensorName_uastr,
                         &UA_TYPES[UA_TYPES_STRING]);
    sensorNameAttribute_st.displayName =
        UA_LOCALIZEDTEXT("en-US", "Sensor Type");
    sensorNameAttribute_st.description =
        UA_LOCALIZEDTEXT("en-US", "Type and unit of the sensor");

    UA_Server_addVariableNode(
        server, UA_NODEID_STRING(1, "speed.sensor.name"),
        OpcUa_SpeedSensorObjId_st, UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
        UA_QUALIFIEDNAME(1, "Sensor Type"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
        sensorNameAttribute_st, NULL, &OpcUa_sensorName_st);

    /* ========= raw string data ============================= */
    UA_VariableAttributes rawStringDataAttr_st = UA_VariableAttributes_default;
    UA_String uaRawStringInitial_uaStr = UA_STRING("");
    UA_Variant_setScalar(&rawStringDataAttr_st.value, &uaRawStringInitial_uaStr,
                         &UA_TYPES[UA_TYPES_STRING]);
    rawStringDataAttr_st.displayName =
        UA_LOCALIZEDTEXT("en-US", "Sensor Data with Time Stamp");
    rawStringDataAttr_st.description =
        UA_LOCALIZEDTEXT("en-US", "Timestamp of last sensor reading");

    UA_Server_addVariableNode(
        server, UA_NODEID_STRING(1, "current.sensor.rawdata.string"),
        OpcUa_SpeedSensorObjId_st, UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
        UA_QUALIFIEDNAME(1, "String of the data"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
        rawStringDataAttr_st, NULL, &OpcUa_rawData_String_NodeIdSt);

    /* ============ signature name
     * ============================================*/
    UA_VariableAttributes signame_var_attr = UA_VariableAttributes_default;
    UA_String sig_algo_name_str = UA_STRING("ML-DSA");
    UA_Variant_setScalar(&signame_var_attr.value, &sig_algo_name_str,
                         &UA_TYPES[UA_TYPES_STRING]);
    signame_var_attr.displayName = UA_LOCALIZEDTEXT("en-US", "Signature Name");
    signame_var_attr.description = UA_LOCALIZEDTEXT("en-US", "Signature Name");

    UA_Server_addVariableNode(
        server, UA_NODEID_STRING(1, "signature.algo.name"),
        OpcUa_Signature_ObjId_st, UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
        UA_QUALIFIEDNAME(1, "SignatureAlgoName"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE), signame_var_attr,
        NULL, &OpcUa_sigType_st);
    /* ================ signature length =====================================*/
    UA_VariableAttributes sign_length_attr = UA_VariableAttributes_default;
    UA_UInt16 sig_length = OPCUA_SERVER_SIGNATURE_SIZE;
    UA_Variant_setScalar(&sign_length_attr.value, &sig_length,
                         &UA_TYPES[UA_TYPES_UINT16]);
    sign_length_attr.displayName =
        UA_LOCALIZEDTEXT("en-US", "Signature Length");
    sign_length_attr.description =
        UA_LOCALIZEDTEXT("en-US", "Signature Length");

    UA_Server_addVariableNode(
        server, UA_NODEID_STRING(1, "signature.length"),
        OpcUa_Signature_ObjId_st, UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
        UA_QUALIFIEDNAME(1, "SignatureLength"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE), sign_length_attr,
        NULL, &OpcUa_sigLength_st);

    /* ============ signature byte buffer ==================================*/
    UA_VariableAttributes sensorSignatureAttribute_st =
        UA_VariableAttributes_default;
    sensorSignatureAttribute_st.displayName =
        UA_LOCALIZEDTEXT("en-US", "Signature Data Buffer");
    sensorSignatureAttribute_st.description =
        UA_LOCALIZEDTEXT("en-US", "Signature Byte Buffer");

    UA_Byte signatureBuffer_u8[OPCUA_SERVER_SIGNATURE_SIZE] = {0};
    UA_Variant_setArray(&sensorSignatureAttribute_st.value, signatureBuffer_u8,
                        OPCUA_SERVER_SIGNATURE_SIZE, &UA_TYPES[UA_TYPES_BYTE]);

    UA_Server_addVariableNode(
        server, UA_NODEID_STRING(1, "current.sensor.signature"),
        OpcUa_Signature_ObjId_st, UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
        UA_QUALIFIEDNAME(1, "Sensor Data Signature"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
        sensorSignatureAttribute_st, NULL, &OpcUa_sensorSignatureId_NodeIdSt);

    /*
    ========================================================
        handle the server call-back mode/ event driven mode
    ========================================================
    */

    if (operation_mode == MODE_CALLBACK) {
        // logging the information
        std::cout << "Setting up callback mode each"
                  << OPCUA_SERVER_CALLBACK_TIME << "(ms)" << std::endl;

        // add the repeative callback
        UA_Server_addRepeatedCallback(
            server,
            update_sendor_data_callback,   // callback function
            NULL,                          // callback data
            OPCUA_SERVER_CALLBACK_TIME,    // interval in ms
            &server_repeative_callback_id  // callback ID
        );

        // log the information to the server
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                    "CALLBACK mode activated with %d(ms)\n",
                    OPCUA_SERVER_CALLBACK_TIME);
    } else if (operation_mode == MODE_EVENT_DRIVEN) {
        // loggin the information
        std::cout << "Setting up event mode" << std::endl;

        // create the event for the server
        UA_StatusCode event_status =
            create_data_increasement_event_type(server);

        if (UA_STATUSCODE_GOOD != event_status) {
            UA_LOG_WARNING(
                UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                "Failed to create event-type of data increasement\n");
        }

        // also add the call-back but with the fasterr data response time
        UA_Server_addRepeatedCallback(
            server,
            update_sendor_data_event_mode,  // callback function
            NULL,                           // callback data
            OPCUA_SERVER_EVENT_TIME,        // interval in ms
            &server_repeative_callback_id   // callback ID
        );

        // log the information to the server
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                    "EVEN-DRIVEN mode activated with %d(ms)\n",
                    OPCUA_SERVER_EVENT_TIME);
    }

    /*
    ----------------------------------------------
        loging the server information
    ----------------------------------------------
    */

    // inform server will be started
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                "OPC UA Server started successfully!");

    // print the current host server (but local host only)
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                "Server endpoint: opc.tcp://localhost:4840");

    // print information for the signal handler
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                "Press Ctrl+C to stop the server");

    /*
    ----------------------------------------------
        execute the server
    ----------------------------------------------
    */

    UA_StatusCode status = UA_Server_run(server, &opcua_running);

    /*
    ----------------------------------------------
        clean up:
            1. Signal handler of SIGINT or SIGTERM with the case of
    UA_Server_run
            2. Ctrl + C (SIGTERM) with UA_Server_runUntilInterrupt()
    ----------------------------------------------
    */
    std::cout << "\n========================================" << std::endl;
    std::cout << "\nStop the server with signals" << std::endl;
    std::cout << "\n========================================" << std::endl;

    // Stop I2C reader
    i2c_stop_handler();

    // Wait for I2C thread to finish
    if (i2cThread.joinable()) {
        std::cout << "Waiting for I2C thread to stop..." << std::endl;
        i2cThread.join();
        std::cout << "I2C thread stopped." << std::endl;
    }

    // Clean up I2C module
    i2c_cleanup_handler();

    // Clean up server
    UA_Server_delete(server);

    std::cout << "Cleanup completed. Server status: "
              << (status == UA_STATUSCODE_GOOD ? "SUCCESS" : "FAILURE")
              << std::endl;

    return status == UA_STATUSCODE_GOOD ? EXIT_SUCCESS : EXIT_FAILURE;
}

/**
 * @brief Signing the data with Shake 256
 *
 * @param dataIn Data for signing (sensor data)
 * @param sigOut Signature of data
 * @return true Signature is ready
 * @return false Signature is not ready
 */
void i2c_sensor_signing(std::span<uint8_t> dataIn, std::span<uint8_t> sigOut) {
    // add lock for the signing purpose
    std::lock_guard<std::mutex> lock_signing(signingMutex);
    // Local value
    bool retVal_b = false;  // return value if the signature is available
    std::array<uint8_t, 128> dataHash_au8;
    dataHash_au8.fill(0);  // hash containning array

    size_t sigLength{0};

    // shake init state
    keccak_state state;
    shake128_init(&state);

    // shake absorb state
    shake128_absorb(&state, dataIn.data(), dataIn.size());

    // finalize the shake
    shake128_finalize(&state);

    // Get the value of the shake128 function
    shake128_squeeze(dataHash_au8.data(), 128, &state);

    std::cout << std::endl;
    // Signing the data
    mldsa_signer.Sign(
        sigOut.data(),         // Signed mesasge
        &sigLength,            // Signed data lenth
        dataHash_au8.data(),   // Message in (hash of data with shake128)
        128,                   // Use all 128 byte of the message
        nullptr, 0,            // No context message at all
        OpcUa_SecretKey_array  // The array that set the secret key
    );
}
