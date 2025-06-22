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

#define OPCUA_SERVER_UPDATE_INTERVAL        4000       // 4 seconds in milliseconds
#define OPCUA_SERVER_RAW_DATA_SIZE          10         // 2 bytes length + 8 bytes of data
#define OPCUA_SERVER_SIGNATURE_SIZE         4098       // 2 bytes length  + 1 bytes of sig type + 8KB remaining

/********************************************************************************
 * I2C Reader Integration - Include the I2C module header
 ********************************************************************************/
#include "opcua_i2c.h"  // Include the I2C module header

/********************************************************************************
 * NODE ID GLOBAL
 ********************************************************************************/
UA_NodeId OpcUa_SpeedSensorObjId_st;
UA_NodeId OpcUa_sensorSignatureId_NodeIdSt;
UA_NodeId OpcUa_sensorSpeedValue_NodeIdSt;
UA_NodeId OpcUa_sensorTimestamp_NodeIdSt;
UA_NodeId OpcUa_rawData_String_NodeIdSt;

/********************************************************************************
 * Global buffer for OPC UA server
 ********************************************************************************/
typedef struct {
    UA_Boolean dataValid_b;
    UA_Byte signatureBuf_au8[OPCUA_SERVER_SIGNATURE_SIZE];
    UA_Float currentSpeed;
    UA_DateTime lastUpdateTime;
    std::string rawStringData_str;
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
static void updateSensorData(UA_Server *server, void *data) {
    I2C_SharedData_tst i2cData;
    bool hasValidData = false;
    
    // Get latest I2C data
    if (I2C_IsInitialized()) {
        hasValidData = I2C_GetCurrentData(i2cData);
    }
    
    // Update local server data structure
    {
        std::lock_guard<std::mutex> lock(serverDataMutex);
        
        if (hasValidData) {
            OpcUa_Server_globData_st.dataValid_b = UA_TRUE;
            OpcUa_Server_globData_st.currentSpeed = i2cData.currentSpeed;
            OpcUa_Server_globData_st.lastUpdateTime = UA_DateTime_fromUnixTime(i2cData.lastUpdateTime);
            
            // Coppy the signature from I2C module
            memcpy(OpcUa_Server_globData_st.signatureBuf_au8, i2cData.signature.data(), CRYPTO_BYTES + 2);
            
            // Adding the value to string
            OpcUa_Server_globData_st.rawStringData_str = i2cData.rawData_str;
        } else {
            OpcUa_Server_globData_st.dataValid_b = UA_FALSE;
        }
    }
    
    // Update OPC UA nodes
    if (hasValidData) {
        
        // Update signature data node
        UA_Variant signatureValue;

        UA_Variant_setArray(&signatureValue, 
                           OpcUa_Server_globData_st.signatureBuf_au8, 
                           OPCUA_SERVER_SIGNATURE_SIZE, 
                           &UA_TYPES[UA_TYPES_BYTE]);
        UA_Server_writeValue(server, OpcUa_sensorSignatureId_NodeIdSt, signatureValue);
        
        // Update speed value node
        UA_Variant speedValue;
        UA_Variant_setScalar(&speedValue, &OpcUa_Server_globData_st.currentSpeed, &UA_TYPES[UA_TYPES_FLOAT]);
        UA_Server_writeValue(server, OpcUa_sensorSpeedValue_NodeIdSt, speedValue);
        
        // Update timestamp node
        UA_Variant timestampValue;
        UA_Variant_setScalar(&timestampValue, &OpcUa_Server_globData_st.lastUpdateTime, &UA_TYPES[UA_TYPES_DATETIME]);
        UA_Server_writeValue(server, OpcUa_sensorTimestamp_NodeIdSt, timestampValue);

        // Sensor data + time stamp
        UA_Variant rawStringValue;
        UA_String rawStringCpy_uaStr = UA_STRING_ALLOC(OpcUa_Server_globData_st.rawStringData_str.c_str());
        UA_Variant_setScalar(&rawStringValue, &rawStringCpy_uaStr, &UA_TYPES[UA_TYPES_STRING]);
        UA_Server_writeValue(server, OpcUa_rawData_String_NodeIdSt, rawStringValue);

        // Log the data
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, 
                    "Updated sensor data: Speed=%.2f rpm, Valid=%s", 
                    OpcUa_Server_globData_st.currentSpeed,
                    OpcUa_Server_globData_st.dataValid_b ? "true" : "false");
    } else {
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, 
                      "No valid I2C data available for update");
    }
}

// Signal Handler
thread_local static volatile UA_Boolean opcua_running = true;

static void stopHandler(int sig) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "Received stop signal");
    opcua_running = false;
    I2C_Stop();  // Also stop I2C reader
}

int main(int argc, char** argv) {
    std::cout << "=== OPC UA Server with I2C Speed Sensor Integration ===" << std::endl;
    
    // Initialize I2C module
    if (!I2C_Initialize()) {
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
    while (!I2C_IsInitialized() && opcua_running && timeout_count < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        timeout_count++;
    }
    
    if (!opcua_running) {
        std::cout << "Shutdown requested before I2C initialization" << std::endl;
        if (i2cThread.joinable()) {
            i2cThread.join();
        }
        I2C_Cleanup();
        return 1;
    }
    
    if (!I2C_IsInitialized()) {
        std::cout << "I2C initialization timeout. Starting OPC UA server anyway..." << std::endl;
    } else {
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
    spdSensorObjAttribute_st.displayName = UA_LOCALIZEDTEXT("en-US", "I2C Speed Sensor");
    spdSensorObjAttribute_st.description = UA_LOCALIZEDTEXT("en-US", "Real-time I2C motor speed sensor");

    UA_Server_addObjectNode(
        server,
        UA_NODEID_NULL,
        UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
        UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
        UA_QUALIFIEDNAME(1, "I2C Speed Sensor"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEOBJECTTYPE),
        spdSensorObjAttribute_st,
        NULL,
        &OpcUa_SpeedSensorObjId_st
    );

    /************************************************************************************
     * VARIABLE NODES
     ************************************************************************************/

    /* 1. Sensor Type/Name */
    UA_VariableAttributes sensorNameAttribute_st = UA_VariableAttributes_default;
    UA_String sensorName_uastr = UA_STRING("I2C Motor Speed Sensor (rpm)");
    UA_Variant_setScalar(&sensorNameAttribute_st.value, &sensorName_uastr, &UA_TYPES[UA_TYPES_STRING]);
    sensorNameAttribute_st.displayName = UA_LOCALIZEDTEXT("en-US", "Sensor Type");
    sensorNameAttribute_st.description = UA_LOCALIZEDTEXT("en-US", "Type and unit of the sensor");
    
    UA_Server_addVariableNode(
        server,
        UA_NODEID_NULL,
        OpcUa_SpeedSensorObjId_st,
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
        UA_QUALIFIEDNAME(1, "Sensor Type"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
        sensorNameAttribute_st,
        NULL,
        NULL
    );

    /* 2. Current Speed Value */
    UA_VariableAttributes speedValueAttribute_st = UA_VariableAttributes_default;
    UA_Float initialSpeed = 0.0f;
    UA_Variant_setScalar(&speedValueAttribute_st.value, &initialSpeed, &UA_TYPES[UA_TYPES_FLOAT]);
    speedValueAttribute_st.displayName = UA_LOCALIZEDTEXT("en-US", "Current Speed");
    speedValueAttribute_st.description = UA_LOCALIZEDTEXT("en-US", "Current motor speed in RPM");
    
    UA_Server_addVariableNode(
        server,
        UA_NODEID_NULL,
        OpcUa_SpeedSensorObjId_st,
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
        UA_QUALIFIEDNAME(1, "Current Speed"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
        speedValueAttribute_st,
        NULL,
        &OpcUa_sensorSpeedValue_NodeIdSt
    );

    /* 3. Last Update Timestamp */
    UA_VariableAttributes timestampAttribute_st = UA_VariableAttributes_default;
    UA_DateTime initialTime = UA_DateTime_now();
    UA_Variant_setScalar(&timestampAttribute_st.value, &initialTime, &UA_TYPES[UA_TYPES_DATETIME]);
    timestampAttribute_st.displayName = UA_LOCALIZEDTEXT("en-US", "Time Stamp");
    timestampAttribute_st.description = UA_LOCALIZEDTEXT("en-US", "Timestamp of last sensor reading");
    
    UA_Server_addVariableNode(
        server,
        UA_NODEID_NULL,
        OpcUa_SpeedSensorObjId_st,
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
        UA_QUALIFIEDNAME(1, "Last Update Time"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
        timestampAttribute_st,
        NULL,
        &OpcUa_sensorTimestamp_NodeIdSt
    );

    /* 5. Sensor Data Signature */
    UA_VariableAttributes sensorSignatureAttribute_st = UA_VariableAttributes_default;
    sensorSignatureAttribute_st.displayName = UA_LOCALIZEDTEXT("en-US", "Signature");
    sensorSignatureAttribute_st.description = UA_LOCALIZEDTEXT("en-US", "Cryptographic signature: 2 bytes length + 1 byte type + 8KB signature");

    UA_Byte signatureBuffer_u8[OPCUA_SERVER_SIGNATURE_SIZE] = {0};
    UA_Variant_setArray(&sensorSignatureAttribute_st.value, signatureBuffer_u8, OPCUA_SERVER_SIGNATURE_SIZE, &UA_TYPES[UA_TYPES_BYTE]);

    UA_Server_addVariableNode(
        server,
        UA_NODEID_NULL,
        OpcUa_SpeedSensorObjId_st,
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
        UA_QUALIFIEDNAME(1, "Sensor Data Signature"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
        sensorSignatureAttribute_st,
        NULL,
        &OpcUa_sensorSignatureId_NodeIdSt
    );

    /* 6. String data */
    UA_VariableAttributes rawStringDataAttr_st = UA_VariableAttributes_default;
    UA_String uaRawStringInitial_uaStr = UA_STRING("");
    UA_Variant_setScalar(&rawStringDataAttr_st.value, &uaRawStringInitial_uaStr, &UA_TYPES[UA_TYPES_STRING]);
    rawStringDataAttr_st.displayName = UA_LOCALIZEDTEXT("en-US", "Sensor Data with Time Stamp");
    rawStringDataAttr_st.description = UA_LOCALIZEDTEXT("en-US", "Timestamp of last sensor reading");
    
    UA_Server_addVariableNode(
        server,
        UA_NODEID_NULL,
        OpcUa_SpeedSensorObjId_st,
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
        UA_QUALIFIEDNAME(1, "String of the data"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
        rawStringDataAttr_st,
        NULL,
        &OpcUa_rawData_String_NodeIdSt
    );


    /************************************************************************************
     * REPEATED CALLBACK SETUP
     ************************************************************************************/
    
    /* Add repeated callback for updating sensor data every 4 seconds */
    UA_UInt64 callbackId;
    UA_Server_addRepeatedCallback(
        server,
        updateSensorData,        // callback function
        NULL,                    // callback data
        OPCUA_SERVER_UPDATE_INTERVAL,  // interval in ms
        &callbackId              // callback ID
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
    I2C_Stop();
    
    // Wait for I2C thread to finish
    if (i2cThread.joinable()) {
        std::cout << "Waiting for I2C thread to stop..." << std::endl;
        i2cThread.join();
        std::cout << "I2C thread stopped." << std::endl;
    }
    
    // Clean up I2C module
    I2C_Cleanup();
    
    // Clean up server
    UA_Server_delete(server);
    
    std::cout << "Cleanup completed. Server status: " 
              << (status == UA_STATUSCODE_GOOD ? "SUCCESS" : "FAILURE") << std::endl;
    
    return status == UA_STATUSCODE_GOOD ? EXIT_SUCCESS : EXIT_FAILURE;
}