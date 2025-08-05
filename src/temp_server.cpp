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
#include <iostream>
#include <mutex>
#include <shared_mutex>
#include <thread>

#define OPCUA_SERVER_UPDATE_INTERVAL 4000        // 4 seconds in milliseconds
#define OPCUA_SERVER_RAW_DATA_SIZE 10            // 2 bytes length + 8 bytes of data
#define OPCUA_SERVER_SIGNATURE_SIZE CRYPTO_BYTES // 2 Signature buffer

/********************************************************************************
 * I2C Reader Integration - Include the I2C module header
 ********************************************************************************/
#include "opcua_i2c.h" // Include the I2C module header

/********************************************************************************
 * Operation Mode Definitions
 ********************************************************************************/
typedef enum
{
    MODE_CALLBACK = 0, // Regular callback mode - updates every interval
    MODE_EVENT_DRIVEN =
        1 // Event-driven mode - updates only when speed increases
} OperationMode_t;

// Global operation mode
OperationMode_t g_operationMode = MODE_CALLBACK;

/********************************************************************************
 * NODE ID GLOBAL
 ********************************************************************************/

UA_NodeId OpcUa_SpeedSensorObjId_st;
UA_NodeId OpcUa_Signature_ObjId_st;
UA_NodeId OpcUa_sensorName_st;
UA_NodeId OpcUa_sigType_st;
UA_NodeId OpcUa_sigLength_st;
UA_NodeId OpcUa_sensorSignatureId_NodeIdSt;
UA_NodeId OpcUa_sensorSpeedValue_NodeIdSt;
UA_NodeId OpcUa_sensorTimestamp_NodeIdSt;
UA_NodeId OpcUa_rawData_String_NodeIdSt;

/********************************************************************************
 * Event-driven mode globals
 ********************************************************************************/
UA_NodeId speedIncreaseEventTypeId;
UA_NodeId speedIncreaseEventId;
UA_Float previous_data = 0.0f;
UA_Boolean first_sample = UA_TRUE;
UA_UInt64 callbackId = 0; // For callback cleanup

/********************************************************************************
 * Global buffer for OPC UA server
 ********************************************************************************/
typedef struct
{
    UA_Boolean is_data_valid_flg;
    UA_Byte signatureBuf_au8[OPCUA_SERVER_SIGNATURE_SIZE];
    UA_Float current_data;
    UA_DateTime last_timestamp;
    std::string data_and_timestamp;

    // Event-driven mode tracking
    UA_Boolean data_updated_since_last_check;
    UA_Boolean should_update_nodes;
} OpcUa_Server_globData_tst;

// Global data structure for OPC UA
OpcUa_Server_globData_tst OpcUa_Server_globData_st;

// Local server synchronization
std::mutex serverDataMutex;

// Signal Handler
thread_local static volatile UA_Boolean opcua_running = true;

/********************************************************************************
 * Function Declarations
 ********************************************************************************/

/**
 * @brief Print usage information
 */
static void printUsage(const char *programName)
{
    std::cout << "Usage: " << programName << " [mode]" << std::endl;
    std::cout << "Modes:" << std::endl;
    std::cout << "  0 or callback    - Use repeated callback mode (default)"
              << std::endl;
    std::cout << "  1 or event       - Use event-driven mode (updates only on "
                 "speed increase)"
              << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << programName << " 0" << std::endl;
    std::cout << "  " << programName << " callback" << std::endl;
    std::cout << "  " << programName << " 1" << std::endl;
    std::cout << "  " << programName << " event" << std::endl;
}

/**
 * @brief Create custom event type for speed increase notifications
 */
static UA_StatusCode createSpeedIncreaseEventType(UA_Server *server)
{
    UA_ObjectTypeAttributes attr = UA_ObjectTypeAttributes_default;
    attr.displayName = UA_LOCALIZEDTEXT("en-US", "SpeedIncreaseEventType");
    attr.description =
        UA_LOCALIZEDTEXT("en-US", "Event triggered when speed increases");

    return UA_Server_addObjectTypeNode(
        server, UA_NODEID_STRING(1, "SpeedIncreaseEventType"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEEVENTTYPE),
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASSUBTYPE),
        UA_QUALIFIEDNAME(1, "SpeedIncreaseEventType"), attr, NULL,
        &speedIncreaseEventTypeId);
}

/**
 * @brief Trigger speed increase event - only called when speed actually
 * increased
 */
static void triggerSpeedIncreaseEvent(UA_Server *server, UA_Float currentSpeed,
                                      UA_Float previousSpeed)
{
    // At this point, we know speed increased because updateLocalDataFromI2C()
    // already validated it before setting should_update_nodes = true

    // Create event instance
    UA_StatusCode retval = UA_Server_createEvent(server, speedIncreaseEventTypeId,
                                                 &speedIncreaseEventId);
    if (retval != UA_STATUSCODE_GOOD)
    {
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                       "Failed to create speed increase event");
        return;
    }

    // Set event properties
    UA_Variant value;

    // Set message
    char messageBuffer[256];
    snprintf(messageBuffer, sizeof(messageBuffer),
             "Speed increased from %.2f to %.2f RPM", previousSpeed,
             currentSpeed);
    UA_LocalizedText message = UA_LOCALIZEDTEXT("en-US", messageBuffer);
    UA_Variant_setScalar(&value, &message, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    UA_Server_writeObjectProperty_scalar(server, speedIncreaseEventId,
                                         UA_QUALIFIEDNAME(0, "Message"), &value,
                                         &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);

    // Set severity (informational)
    UA_UInt16 severity = 100;
    UA_Variant_setScalar(&value, &severity, &UA_TYPES[UA_TYPES_UINT16]);
    UA_Server_writeObjectProperty_scalar(server, speedIncreaseEventId,
                                         UA_QUALIFIEDNAME(0, "Severity"), &value,
                                         &UA_TYPES[UA_TYPES_UINT16]);

    // Set source name
    UA_String sourceName = UA_STRING("I2C Speed Sensor");
    UA_Variant_setScalar(&value, &sourceName, &UA_TYPES[UA_TYPES_STRING]);
    UA_Server_writeObjectProperty_scalar(server, speedIncreaseEventId,
                                         UA_QUALIFIEDNAME(0, "SourceName"),
                                         &value, &UA_TYPES[UA_TYPES_STRING]);

    // Trigger the event
    retval = UA_Server_triggerEvent(server, speedIncreaseEventId,
                                    OpcUa_SpeedSensorObjId_st, NULL, UA_TRUE);

    if (retval == UA_STATUSCODE_GOOD)
    {
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                    "\033[1;32mEVENT TRIGGERED:\033[0m Speed increased from %.2f "
                    "to %.2f RPM",
                    previousSpeed, currentSpeed);
    }
    else
    {
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                       "Failed to trigger speed increase event");
    }
}

/**
 * @brief Update local data structure from I2C (common for both modes)
 */
static bool updateLocalDataFromI2C()
{
    i2c_data_structure_t i2c_data;
    bool is_valid_data_flg = false;

    // Get latest I2C data
    if (i2c_init_check())
    {
        is_valid_data_flg = i2c_get_current_data(i2c_data);
    }

    // Update local server data structure
    {
        std::lock_guard<std::mutex> lock(serverDataMutex);

        if (is_valid_data_flg)
        {
            // For event-driven mode: check if speed increased BEFORE updating global
            // data
            if (g_operationMode == MODE_EVENT_DRIVEN)
            {
                // Store current data for comparison
                UA_Float temp_previous = OpcUa_Server_globData_st.current_data;

                // Check if speed increased (or if it's the first sample)
                if (first_sample || i2c_data.current_data > temp_previous)
                {
                    // Speed increased or first sample - update global data structure
                    previous_data = temp_previous; // Store for event triggering

                    // Update global data structure
                    OpcUa_Server_globData_st.is_data_valid_flg = UA_TRUE;
                    OpcUa_Server_globData_st.current_data = i2c_data.current_data;
                    OpcUa_Server_globData_st.last_timestamp =
                        UA_DateTime_fromUnixTime(i2c_data.last_timestamp);
                    OpcUa_Server_globData_st.data_and_timestamp = i2c_data.raw_data_str;
                    memcpy(OpcUa_Server_globData_st.signatureBuf_au8,
                           i2c_data.signature.data(), CRYPTO_BYTES);

                    OpcUa_Server_globData_st.data_updated_since_last_check = UA_TRUE;
                    OpcUa_Server_globData_st.should_update_nodes = UA_TRUE;

                    first_sample = UA_FALSE;
                }
                else
                {
                    // Speed did not increase - do NOT update global data structure
                    OpcUa_Server_globData_st.should_update_nodes = UA_FALSE;

                    // Log when data is rejected due to speed decrease/no change
                    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                                "[EVENT] Speed did not increase (current: %.2f, "
                                "previous: %.2f) - Data rejected",
                                i2c_data.current_data, temp_previous);
                }
            }
            else
            {
                // Callback mode: always update global data structure
                OpcUa_Server_globData_st.is_data_valid_flg = UA_TRUE;
                OpcUa_Server_globData_st.current_data = i2c_data.current_data;
                OpcUa_Server_globData_st.last_timestamp =
                    UA_DateTime_fromUnixTime(i2c_data.last_timestamp);
                OpcUa_Server_globData_st.data_and_timestamp = i2c_data.raw_data_str;
                memcpy(OpcUa_Server_globData_st.signatureBuf_au8,
                       i2c_data.signature.data(), CRYPTO_BYTES);

                OpcUa_Server_globData_st.data_updated_since_last_check = UA_TRUE;
                OpcUa_Server_globData_st.should_update_nodes = UA_TRUE;

                first_sample = UA_FALSE;
            }
        }
        else
        {
            // set the invalid data flag
            OpcUa_Server_globData_st.is_data_valid_flg = UA_FALSE;
            OpcUa_Server_globData_st.should_update_nodes = UA_FALSE;
        }
    }

    return is_valid_data_flg;
}

/**
 * @brief Update OPC UA nodes with current data (common for both modes)
 */
static void updateOPCUANodes(UA_Server *server, const char *modePrefix)
{
    std::lock_guard<std::mutex> lock(serverDataMutex);

    if (!OpcUa_Server_globData_st.should_update_nodes)
    {
        return; // No update needed
    }

    // string for transfer the data
    UA_Variant data_string;
    UA_String rawStringCpy_uaStr =
        UA_STRING_ALLOC(OpcUa_Server_globData_st.data_and_timestamp.c_str());
    UA_Variant_setScalar(&data_string, &rawStringCpy_uaStr,
                         &UA_TYPES[UA_TYPES_STRING]);
    UA_Server_writeValue(server, OpcUa_rawData_String_NodeIdSt, data_string);

    // Update signature data node
    UA_Variant signatureValue;
    UA_Variant_setArray(&signatureValue,
                        OpcUa_Server_globData_st.signatureBuf_au8, CRYPTO_BYTES,
                        &UA_TYPES[UA_TYPES_BYTE]);
    UA_Server_writeValue(server, OpcUa_sensorSignatureId_NodeIdSt,
                         signatureValue);

    // Log the data
    std::string logData =
        std::string(reinterpret_cast<char *>(rawStringCpy_uaStr.data),
                    rawStringCpy_uaStr.length);
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                "\033[1;36m[%s] SERVER DATA:\033[0m \033[1;35m%s\033[0m",
                modePrefix, logData.c_str());

    // Trigger event if in event-driven mode and speed increased
    if (g_operationMode == MODE_EVENT_DRIVEN &&
        OpcUa_Server_globData_st.should_update_nodes)
    {
        triggerSpeedIncreaseEvent(server, OpcUa_Server_globData_st.current_data,
                                  previous_data);
    }

    // Reset the update flag
    OpcUa_Server_globData_st.should_update_nodes = UA_FALSE;

    UA_String_clear(&rawStringCpy_uaStr);
}

/**
 * @brief Callback Mode Update Function
 */
static void updateSensorData_CallbackMode(UA_Server *server, void *data)
{
    bool is_valid_data = updateLocalDataFromI2C();

    if (is_valid_data)
    {
        updateOPCUANodes(server, "CALLBACK");
    }
    else
    {
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                       "[CALLBACK] No valid I2C data available for update");
    }
}

/**
 * @brief Event-Driven Mode Update Function
 */
static void updateSensorData_EventMode(UA_Server *server, void *data)
{
    bool is_valid_data = updateLocalDataFromI2C();

    if (is_valid_data)
    {
        // Check if nodes should be updated BEFORE calling updateOPCUANodes
        bool should_update = false;
        UA_Float current_speed = 0.0f;
        {
            std::lock_guard<std::mutex> lock(serverDataMutex);
            should_update = OpcUa_Server_globData_st.should_update_nodes;
            current_speed = OpcUa_Server_globData_st.current_data;
        }

        if (should_update)
        {
            updateOPCUANodes(server, "EVENT");
        }
        // Removed the else clause that logged "Speed did not increase" because
        // that logging is now handled in updateLocalDataFromI2C()
    }
    else
    {
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                       "[EVENT] No valid I2C data available for update");
    }

    // Reset the data updated flag
    {
        std::lock_guard<std::mutex> lock(serverDataMutex);
        OpcUa_Server_globData_st.data_updated_since_last_check = UA_FALSE;
    }
}

/**
 * @brief Software interrupt handler with Linux system
 *
 * @param sig Stop with SIGINT or SIGTERM
 */
static void stopHandler(int sig)
{
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "Received stop signal");
    opcua_running = false;
    i2c_stop_handler();
}

int main(int argc, char **argv)
{
    // Parse command line arguments
    if (argc > 1)
    {
        if (strcmp(argv[1], "0") == 0 || strcmp(argv[1], "callback") == 0)
        {
            g_operationMode = MODE_CALLBACK;
        }
        else if (strcmp(argv[1], "1") == 0 || strcmp(argv[1], "event") == 0)
        {
            g_operationMode = MODE_EVENT_DRIVEN;
        }
        else if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)
        {
            printUsage(argv[0]);
            return 0;
        }
        else
        {
            std::cerr << "Invalid mode: " << argv[1] << std::endl;
            printUsage(argv[0]);
            return 1;
        }
    }

    std::cout << "=== OPC UA Server with I2C Speed Sensor Integration ==="
              << std::endl;
    std::cout << "Operation Mode: "
              << (g_operationMode == MODE_CALLBACK ? "CALLBACK" : "EVENT-DRIVEN")
              << std::endl;

    // Initialize I2C module
    if (!i2c_init())
    {
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
    while (!i2c_init_check() && opcua_running && timeout_count < 100)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        timeout_count++;
    }

    if (!opcua_running)
    {
        std::cout << "Shutdown requested before I2C initialization" << std::endl;
        if (i2cThread.joinable())
        {
            i2cThread.join();
        }
        i2c_cleanup_handler();
        return 1;
    }

    if (!i2c_init_check())
    {
        std::cout << "I2C initialization timeout. Starting OPC UA server anyway..."
                  << std::endl;
    }
    else
    {
        std::cout << "I2C initialized successfully!" << std::endl;
    }

    std::cout << "Starting OPC UA server..." << std::endl;

    /* Create a server with default configuration */
    UA_Server *server = UA_Server_new();
    UA_ServerConfig_setDefault(UA_Server_getConfig(server));

    /************************************************************************************
     * OBJECT CONSTRUCTION
     ************************************************************************************/

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

    // Constructor testing
    UA_ObjectAttributes signatureObject_st = UA_ObjectAttributes_default;
    signatureObject_st.displayName = UA_LOCALIZEDTEXT("en-US", "Signature");
    signatureObject_st.description =
        UA_LOCALIZEDTEXT("en-US", "Signature Object");

    UA_Server_addObjectNode(
        server, UA_NODEID_STRING(1, "Signature.Object"),
        OpcUa_SpeedSensorObjId_st, // -> Parent shall be the object node id
        UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
        UA_QUALIFIEDNAME(1, "Signature"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEOBJECTTYPE), signatureObject_st, NULL,
        &OpcUa_Signature_ObjId_st);

    /************************************************************************************
     * VARIABLE NODES
     ************************************************************************************/

    /* ========= sensor name ================================================= */
    UA_VariableAttributes sensorNameAttribute_st = UA_VariableAttributes_default;
    UA_String sensorName_uastr = UA_STRING("I2C Motor Speed Sensor (rpm)");
    UA_Variant_setScalar(&sensorNameAttribute_st.value, &sensorName_uastr,
                         &UA_TYPES[UA_TYPES_STRING]);
    sensorNameAttribute_st.displayName = UA_LOCALIZEDTEXT("en-US", "Sensor Type");
    sensorNameAttribute_st.description =
        UA_LOCALIZEDTEXT("en-US", "Type and unit of the sensor");

    UA_Server_addVariableNode(server, UA_NODEID_STRING(1, "speed.sensor.name"),
                              OpcUa_SpeedSensorObjId_st,
                              UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                              UA_QUALIFIEDNAME(1, "Sensor Type"),
                              UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                              sensorNameAttribute_st, NULL, &OpcUa_sensorName_st);

    /* ============ signature name ============================================*/
    UA_VariableAttributes signame_var_attr = UA_VariableAttributes_default;
    UA_String sig_algo_name_str = UA_STRING("ML-DSA");
    UA_Variant_setScalar(&signame_var_attr.value, &sig_algo_name_str,
                         &UA_TYPES[UA_TYPES_STRING]);
    signame_var_attr.displayName = UA_LOCALIZEDTEXT("en-US", "Signature Name");
    signame_var_attr.description = UA_LOCALIZEDTEXT("en-US", "Signature Name");

    UA_Server_addVariableNode(server, UA_NODEID_STRING(1, "signature.algo.name"),
                              OpcUa_Signature_ObjId_st,
                              UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                              UA_QUALIFIEDNAME(1, "SignatureAlgoName"),
                              UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                              signame_var_attr, NULL, &OpcUa_sigType_st);

    /* ================ signature length =====================================*/
    UA_VariableAttributes sign_length_attr = UA_VariableAttributes_default;
    UA_UInt16 sig_length = OPCUA_SERVER_SIGNATURE_SIZE;
    UA_Variant_setScalar(&sign_length_attr.value, &sig_length,
                         &UA_TYPES[UA_TYPES_UINT16]);
    sign_length_attr.displayName = UA_LOCALIZEDTEXT("en-US", "Signature Length");
    sign_length_attr.description = UA_LOCALIZEDTEXT("en-US", "Signature Length");

    UA_Server_addVariableNode(server, UA_NODEID_STRING(1, "signature.length"),
                              OpcUa_Signature_ObjId_st,
                              UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                              UA_QUALIFIEDNAME(1, "SignatureLength"),
                              UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                              sign_length_attr, NULL, &OpcUa_sigLength_st);

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
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE), rawStringDataAttr_st,
        NULL, &OpcUa_rawData_String_NodeIdSt);

    /************************************************************************************
     * MODE-SPECIFIC SETUP
     ************************************************************************************/

    if (g_operationMode == MODE_CALLBACK)
    {
        // Callback mode: Add repeated callback function
        std::cout << "Setting up CALLBACK mode..." << std::endl;
        UA_Server_addRepeatedCallback(server, updateSensorData_CallbackMode, NULL,
                                      OPCUA_SERVER_UPDATE_INTERVAL, &callbackId);
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                    "CALLBACK mode activated - Updates every %d ms",
                    OPCUA_SERVER_UPDATE_INTERVAL);
    }
    else if (g_operationMode == MODE_EVENT_DRIVEN)
    {
        // Event-driven mode: Create event type and setup
        std::cout << "Setting up EVENT-DRIVEN mode..." << std::endl;

        UA_StatusCode eventStatus = createSpeedIncreaseEventType(server);
        if (eventStatus != UA_STATUSCODE_GOOD)
        {
            UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                           "Failed to create speed increase event type");
        }

        // Add callback that checks for data changes but only updates on speed
        // increase
        UA_Server_addRepeatedCallback(server, updateSensorData_EventMode, NULL,
                                      OPCUA_SERVER_UPDATE_INTERVAL, &callbackId);
        UA_LOG_INFO(
            UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
            "EVENT-DRIVEN mode activated - Updates only when speed increases");
    }

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                "OPC UA Server started successfully!");
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                "Server endpoint: opc.tcp://localhost:4840");
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                "Press Ctrl+C to stop the server");

    // Run the server
    UA_StatusCode status = UA_Server_run(server, &opcua_running);

    /************************************************************************************
     * CLEANUP
     ************************************************************************************/

    std::cout << "\nStopping OPC UA server and I2C reader..." << std::endl;

    // Stop I2C reader
    i2c_stop_handler();

    // Wait for I2C thread to finish
    if (i2cThread.joinable())
    {
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