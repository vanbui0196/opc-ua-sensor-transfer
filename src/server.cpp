#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/log_stdout.h>

/* General inclusion */
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <iostream>

#define OPCUA_SERVER_UPDATE_INTERVAL 4000        // 4 seconds in milliseconds
#define OPCUA_SERVER_RAW_DATA_SIZE 10            // 2 bytes length + 8 bytes of data
#define OPCUA_SERVER_SIGNATURE_SIZE CRYPTO_BYTES // 2 Signature buffer

/********************************************************************************
 * I2C Reader Integration - Include the I2C module header
 ********************************************************************************/
#include "opcua_i2c.h" // Include the I2C module header

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
 * Global buffer for OPC UA server
 ********************************************************************************/
typedef struct
{
    UA_Boolean is_data_valid_flg;
    UA_Byte signatureBuf_au8[OPCUA_SERVER_SIGNATURE_SIZE];
    UA_Float current_data;
    UA_DateTime last_timestamp;
    std::string data_and_timestamp;
} OpcUa_Server_globData_tst;

// Global data structure for OPC UA
OpcUa_Server_globData_tst OpcUa_Server_globData_st;

// Local server synchronization
std::mutex serverDataMutex;

/********************************************************************************
 * OPC UA Server Functions
 ********************************************************************************/

/**
 * @brief Update OPC UA nodes with latest I2C data
 *
 * @param server Pointer to the server structure
 * @param data Data Pointer (UNUSED)
 */
static void updateSensorData(UA_Server *server, void *data)
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
            // set the flag for data status
            OpcUa_Server_globData_st.is_data_valid_flg = UA_TRUE;

            // set the current data
            OpcUa_Server_globData_st.current_data = i2c_data.current_data;

            // convert to UA_Time from Linux time
            OpcUa_Server_globData_st.last_timestamp = UA_DateTime_fromUnixTime(i2c_data.last_timestamp);

            // update the data from string from peripheral reader to the server data structure
            OpcUa_Server_globData_st.data_and_timestamp = i2c_data.raw_data_str;

            // copy the signature to the server buffer
            memcpy(OpcUa_Server_globData_st.signatureBuf_au8, i2c_data.signature.data(), CRYPTO_BYTES);
        }
        else
        {
            // set the invalid data flag
            OpcUa_Server_globData_st.is_data_valid_flg = UA_FALSE;
        }
    }

    // Update OPC UA nodes
    if (is_valid_data_flg)
    {
        // string for transfer the data
        UA_Variant data_string;
        UA_String rawStringCpy_uaStr = UA_STRING_ALLOC(OpcUa_Server_globData_st.data_and_timestamp.c_str());
        UA_Variant_setScalar(&data_string, &rawStringCpy_uaStr, &UA_TYPES[UA_TYPES_STRING]);
        UA_Server_writeValue(server, OpcUa_rawData_String_NodeIdSt, data_string);

        // Update signature data node
        UA_Variant signatureValue;

        UA_Variant_setArray(&signatureValue,
                            OpcUa_Server_globData_st.signatureBuf_au8,
                            CRYPTO_BYTES,
                            &UA_TYPES[UA_TYPES_BYTE]);
        UA_Server_writeValue(server, OpcUa_sensorSignatureId_NodeIdSt, signatureValue);

        // Log the data
        std::string logData = std::string(reinterpret_cast<char *>(rawStringCpy_uaStr.data), rawStringCpy_uaStr.length);
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                    "\033[1;36mSERVER DATA:\033[0m \033[1;35m%s\033[0m", logData.c_str());
    }
    else
    {
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                       "No valid I2C data available for update");
    }
}

// Signal Handler
thread_local static volatile UA_Boolean opcua_running = true;

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
    std::cout << "=== OPC UA Server with I2C Speed Sensor Integration ===" << std::endl;

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
        std::cout << "I2C initialization timeout. Starting OPC UA server anyway..." << std::endl;
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
    spdSensorObjAttribute_st.displayName = UA_LOCALIZEDTEXT("en-US", "Speed.Sensor");
    spdSensorObjAttribute_st.description = UA_LOCALIZEDTEXT("en-US", "Motor rotational Speed monitored with I2C communication standard");

    UA_Server_addObjectNode(
        server,
        UA_NODEID_STRING(1, "Speed.Sensor"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
        UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
        UA_QUALIFIEDNAME(1, "I2C Speed Sensor"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEOBJECTTYPE),
        spdSensorObjAttribute_st,
        NULL,
        &OpcUa_SpeedSensorObjId_st);

    // Contructor testing
    UA_ObjectAttributes signatureObject_st = UA_ObjectAttributes_default;
    signatureObject_st.displayName = UA_LOCALIZEDTEXT("en-US", "Signature");
    signatureObject_st.description = UA_LOCALIZEDTEXT("en-US", "Signature Object");

    UA_Server_addObjectNode(
        server,
        UA_NODEID_STRING(1, "Signature.Object"),
        OpcUa_SpeedSensorObjId_st, // -> Parent shall be the object node id
        UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
        UA_QUALIFIEDNAME(1, "Signature"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEOBJECTTYPE),
        signatureObject_st,
        NULL,
        &OpcUa_Signature_ObjId_st);

    /************************************************************************************
     * VARIABLE NODES
     ************************************************************************************/

    /*-------------------------------------------------------
     * Signature name
     *-------------------------------------------------------*/
    UA_VariableAttributes sensorNameAttribute_st = UA_VariableAttributes_default;
    UA_String sensorName_uastr = UA_STRING("I2C Motor Speed Sensor (rpm)");
    UA_Variant_setScalar(&sensorNameAttribute_st.value, &sensorName_uastr, &UA_TYPES[UA_TYPES_STRING]);
    sensorNameAttribute_st.displayName = UA_LOCALIZEDTEXT("en-US", "Sensor Type");
    sensorNameAttribute_st.description = UA_LOCALIZEDTEXT("en-US", "Type and unit of the sensor");

    UA_Server_addVariableNode(
        server,
        UA_NODEID_STRING(1, "speed.sensor.name"),
        OpcUa_SpeedSensorObjId_st,
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
        UA_QUALIFIEDNAME(1, "Sensor Type"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
        sensorNameAttribute_st,
        NULL,
        &OpcUa_sensorName_st);

    /**
     * Signature Name
     */
    UA_VariableAttributes signame_var_attr = UA_VariableAttributes_default;
    UA_String sig_algo_name_str = UA_STRING("ML-DSA");
    UA_Variant_setScalar(&signame_var_attr.value, &sig_algo_name_str, &UA_TYPES[UA_TYPES_STRING]);
    signame_var_attr.displayName = UA_LOCALIZEDTEXT("en-US", "Signature Name");
    signame_var_attr.description = UA_LOCALIZEDTEXT("en-US", "Signature Name");

    UA_Server_addVariableNode(
        server,
        UA_NODEID_STRING(1, "signature.algo.name"),
        OpcUa_Signature_ObjId_st,
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
        UA_QUALIFIEDNAME(1, "SignatureAlgoName"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
        signame_var_attr,
        NULL,
        &OpcUa_sigType_st);
    /**
     * Signature Length
     */
    UA_VariableAttributes sign_length_attr = UA_VariableAttributes_default;
    UA_UInt16 sig_length = OPCUA_SERVER_SIGNATURE_SIZE;
    UA_Variant_setScalar(&sign_length_attr.value, &sig_length, &UA_TYPES[UA_TYPES_UINT16]);
    sign_length_attr.displayName = UA_LOCALIZEDTEXT("en-US", "Signature Length");
    sign_length_attr.description = UA_LOCALIZEDTEXT("en-US", "Signature Length");

    UA_Server_addVariableNode(
        server,
        UA_NODEID_STRING(1, "signature.length"),
        OpcUa_Signature_ObjId_st,
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
        UA_QUALIFIEDNAME(1, "SignatureLength"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
        sign_length_attr,
        NULL,
        &OpcUa_sigLength_st);

    /**
     * Signature byte buffer in the signature object
     */
    UA_VariableAttributes sensorSignatureAttribute_st = UA_VariableAttributes_default;
    sensorSignatureAttribute_st.displayName = UA_LOCALIZEDTEXT("en-US", "Signature Data Buffer");
    sensorSignatureAttribute_st.description = UA_LOCALIZEDTEXT("en-US", "Signature Byte Buffer");

    UA_Byte signatureBuffer_u8[OPCUA_SERVER_SIGNATURE_SIZE] = {0};
    UA_Variant_setArray(&sensorSignatureAttribute_st.value, signatureBuffer_u8, OPCUA_SERVER_SIGNATURE_SIZE, &UA_TYPES[UA_TYPES_BYTE]);

    UA_Server_addVariableNode(
        server,
        UA_NODEID_STRING(1, "current.sensor.signature"),
        OpcUa_Signature_ObjId_st,
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
        UA_QUALIFIEDNAME(1, "Sensor Data Signature"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
        sensorSignatureAttribute_st,
        NULL,
        &OpcUa_sensorSignatureId_NodeIdSt);

    /* 6. String data */
    UA_VariableAttributes rawStringDataAttr_st = UA_VariableAttributes_default;
    UA_String uaRawStringInitial_uaStr = UA_STRING("");
    UA_Variant_setScalar(&rawStringDataAttr_st.value, &uaRawStringInitial_uaStr, &UA_TYPES[UA_TYPES_STRING]);
    rawStringDataAttr_st.displayName = UA_LOCALIZEDTEXT("en-US", "Sensor Data with Time Stamp");
    rawStringDataAttr_st.description = UA_LOCALIZEDTEXT("en-US", "Timestamp of last sensor reading");

    UA_Server_addVariableNode(
        server,
        UA_NODEID_STRING(1, "current.sensor.rawdata.string"),
        OpcUa_SpeedSensorObjId_st,
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
        UA_QUALIFIEDNAME(1, "String of the data"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
        rawStringDataAttr_st,
        NULL,
        &OpcUa_rawData_String_NodeIdSt);

    /************************************************************************************
     * REPEATED CALLBACK SETUP
     ************************************************************************************/

    // add repeated callback function
    UA_UInt64 callbackId;
    UA_Server_addRepeatedCallback(
        server,
        updateSensorData,             // callback function
        NULL,                         // callback data
        OPCUA_SERVER_UPDATE_INTERVAL, // interval in ms
        &callbackId                   // callback ID
    );

    /************************************************************************************
     * SERVER STARTUP AND MAIN LOOP
     ************************************************************************************/

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
              << (status == UA_STATUSCODE_GOOD ? "SUCCESS" : "FAILURE") << std::endl;

    return status == UA_STATUSCODE_GOOD ? EXIT_SUCCESS : EXIT_FAILURE;
}