#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/log_stdout.h>
#include <string>
#include <vector>
#include <array>
#include <span>
#include "mldsa.h"
typedef struct
{
    UA_NodeId id;
    UA_LocalizedText displ_name;
    UA_LocalizedText description;
    UA_QualifiedName qualified_name;
} variable_object_config_tst;

typedef struct
{
    variable_object_config_tst sensor_obj;
    struct
    {
        variable_object_config_tst data_timestamp;
        variable_object_config_tst sensor_type;
        variable_object_config_tst signature_object;
        struct
        {
            variable_object_config_tst signature_buffer;
            variable_object_config_tst signature_length;
            variable_object_config_tst signature_name;
        } signature_child;
    } sensor_child;

    // Variable for the configurat of each object
    std::string data_and_timestamp;
    std::string signature_algorithm_name;
    size_t signature_len;
    std::vector<uint8_t> signature;
    std::string sensor_name;
} sensor_config_tst;

namespace server_configuration
{
    sensor_config_tst sensor_config_array_ast[] = {
        /* First object -> Speed sensor*/
        {
            .sensor_obj{
                .id = UA_NODEID_STRING(1, "Speed.Sensor"),
                .displ_name = UA_LOCALIZEDTEXT("en-US", "Speed.Sensor"),
                .description = UA_LOCALIZEDTEXT("en-US", "Moto rotational speed"),
                .qualified_name = UA_QUALIFIEDNAME(1, "I2C Speed Sensor"),
            },
            .sensor_child{
                .data_timestamp{
                    .id = UA_NODEID_STRING(1, "current.sensor.rawdata.string"),
                    .displ_name = UA_LOCALIZEDTEXT("en-US", "Sensor Data with Time Stamp"),
                    .description = UA_LOCALIZEDTEXT("en-US", "Timestamp of last sensor reading"),
                    .qualified_name = UA_QUALIFIEDNAME(1, "String of the data"),
                },
                .sensor_type{
                    .id = UA_NODEID_STRING(1, "speed.sensor.name"),
                    .displ_name = UA_LOCALIZEDTEXT("en-US", "Sensor Type"),
                    .description = UA_LOCALIZEDTEXT("en-US", "Type and unit of the sensor"),
                    .qualified_name = UA_QUALIFIEDNAME(1, "Sensor Type"),
                },
                .signature_object{
                    .id = UA_NODEID_STRING(1, "Signature.Object"),
                    .displ_name = UA_LOCALIZEDTEXT("en-US", "Signature"),
                    .description = UA_LOCALIZEDTEXT("en-US", "Signature Object"),
                    .qualified_name = UA_QUALIFIEDNAME(1, "Signature"),
                },
                .signature_child{
                    .signature_buffer{
                        .id = UA_NODEID_STRING(1, "current.sensor.signature"),
                        .displ_name = UA_LOCALIZEDTEXT("en-US", "Signature Data Buffer"),
                        .description = UA_LOCALIZEDTEXT("en-US", "Signature Byte Buffer"),
                        .qualified_name = UA_QUALIFIEDNAME(1, "Sensor Data Signature"),
                    },
                    .signature_length{
                        .id = UA_NODEID_STRING(1, "signature.length"),
                        .displ_name = UA_LOCALIZEDTEXT("en-US", "Signature Length"),
                        .description = UA_LOCALIZEDTEXT("en-US", "Signature Length"),
                        .qualified_name = UA_QUALIFIEDNAME(1, "SignatureLength"),
                    },
                    .signature_name{
                        .id = UA_NODEID_STRING(1, "signature.algo.name"),
                        .displ_name = UA_LOCALIZEDTEXT("en-US", "Signature Name"),
                        .description = UA_LOCALIZEDTEXT("en-US", "Signature Name"),
                        .qualified_name = UA_QUALIFIEDNAME(1, "SignatureAlgoName"),
                    }}

            },
            .signature_algorithm_name = std::string("ML-DSA-44"),
            .signature_len = CRYPTO_BYTES,
            .data_and_timestamp = std::string(""),
            .signature = std::vector<uint8_t>(CRYPTO_BYTES, 0),
            .sensor_name = "Speed Rotational Sensor"}};
}

namespace server_lib
{
    /**
     * @brief create the sensor type for easier reading
     *
     * @param server pointer to the server
     * @param out_typeid reference to the NodeId type
     */
    void server_init(UA_Server *server)
    {
        namespace config = server_configuration;

        size_t number_of_config = sizeof(config::sensor_config_array_ast) /
                                  sizeof(config::sensor_config_array_ast[0]);

        for (size_t idx = 0; idx < number_of_config; ++idx)
        {
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
            // Sensor Object
            UA_ObjectAttributes sensor_obj_attr = UA_ObjectAttributes_default;
            sensor_obj_attr.displayName = config::sensor_config_array_ast[idx].sensor_obj.displ_name;
            sensor_obj_attr.description = config::sensor_config_array_ast[idx].sensor_obj.description;

            UA_Server_addObjectNode(
                server,
                config::sensor_config_array_ast[idx].sensor_obj.id,
                UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
                UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                config::sensor_config_array_ast[idx].sensor_obj.qualified_name,
                UA_NODEID_NUMERIC(0, UA_NS0ID_BASEOBJECTTYPE),
                sensor_obj_attr,
                NULL,
                NULL);

            // Sensor name/type
            UA_VariableAttributes sensor_name_attr = UA_VariableAttributes_default;
            UA_String sensor_name_str = UA_STRING_ALLOC(config::sensor_config_array_ast[idx].sensor_name.c_str());
            UA_Variant_setScalar(&sensor_name_attr.value, &sensor_name_str, &UA_TYPES[UA_TYPES_STRING]);
            sensor_name_attr.displayName = config::sensor_config_array_ast[idx].sensor_child.sensor_type.displ_name;
            sensor_name_attr.description = config::sensor_config_array_ast[idx].sensor_child.sensor_type.description;

            UA_Server_addVariableNode(
                server,
                config::sensor_config_array_ast[idx].sensor_child.sensor_type.id,
                config::sensor_config_array_ast[idx].sensor_obj.id,
                UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                config::sensor_config_array_ast[idx].sensor_child.sensor_type.qualified_name,
                UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                sensor_name_attr,
                NULL,
                NULL);

            // data + time stamp
            UA_VariableAttributes data_timestamp_attr = UA_VariableAttributes_default;
            UA_String data_time_stamp_init = UA_STRING("");
            UA_Variant_setScalar(&data_timestamp_attr.value, &data_time_stamp_init, &UA_TYPES[UA_TYPES_STRING]);
            data_timestamp_attr.displayName = config::sensor_config_array_ast[idx].sensor_child.data_timestamp.displ_name;
            data_timestamp_attr.description = config::sensor_config_array_ast[idx].sensor_child.data_timestamp.description;
            UA_Server_addVariableNode(
                server,
                config::sensor_config_array_ast[idx].sensor_child.data_timestamp.id,
                config::sensor_config_array_ast[idx].sensor_obj.id,
                UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                config::sensor_config_array_ast[idx].sensor_child.data_timestamp.qualified_name,
                UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                data_timestamp_attr,
                NULL,
                NULL);

            // sensor object
            UA_ObjectAttributes signature_obj_attr = UA_ObjectAttributes_default;
            signature_obj_attr.displayName = config::sensor_config_array_ast[idx].sensor_child.signature_object.displ_name;
            signature_obj_attr.description = config::sensor_config_array_ast[idx].sensor_child.signature_object.description;

            UA_Server_addObjectNode(
                server,
                config::sensor_config_array_ast[idx].sensor_child.signature_object.id,
                config::sensor_config_array_ast[idx].sensor_obj.id, // -> Parent shall be the object sensor
                UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                config::sensor_config_array_ast[idx].sensor_child.signature_object.qualified_name,
                UA_NODEID_NUMERIC(0, UA_NS0ID_BASEOBJECTTYPE),
                signature_obj_attr,
                NULL,
                NULL);

            // signature algorithm name
            UA_VariableAttributes signature_algo_name_attr = UA_VariableAttributes_default;
            UA_String sig_algo_name_str = UA_STRING_ALLOC(config::sensor_config_array_ast[idx].signature_algorithm_name.c_str());
            UA_Variant_setScalar(&signature_algo_name_attr.value, &sig_algo_name_str, &UA_TYPES[UA_TYPES_STRING]);
            signature_algo_name_attr.displayName = config::sensor_config_array_ast[idx].sensor_child.signature_child.signature_name.displ_name;
            signature_algo_name_attr.description = config::sensor_config_array_ast[idx].sensor_child.signature_child.signature_name.description;

            UA_Server_addVariableNode(
                server,
                config::sensor_config_array_ast[idx].sensor_child.signature_child.signature_name.id,
                config::sensor_config_array_ast[idx].sensor_child.signature_object.id,
                UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                config::sensor_config_array_ast[idx].sensor_child.signature_child.signature_name.qualified_name,
                UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                signature_algo_name_attr,
                NULL,
                NULL);

            // signature length
            UA_VariableAttributes signature_length_attr = UA_VariableAttributes_default;
            UA_UInt16 sig_length = CRYPTO_BYTES;
            UA_Variant_setScalar(&signature_length_attr.value, &sig_length, &UA_TYPES[UA_TYPES_UINT16]);
            signature_length_attr.displayName = config::sensor_config_array_ast[idx].sensor_child.signature_child.signature_length.displ_name;
            signature_length_attr.description = config::sensor_config_array_ast[idx].sensor_child.signature_child.signature_length.description;

            UA_Server_addVariableNode(
                server,
                config::sensor_config_array_ast[idx].sensor_child.signature_child.signature_length.id,
                config::sensor_config_array_ast[idx].sensor_child.signature_object.id,
                UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                config::sensor_config_array_ast[idx].sensor_child.signature_child.signature_length.qualified_name,
                UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                signature_length_attr,
                NULL,
                NULL);

            // signature byte buffer
            UA_VariableAttributes signature_byte_buffer_attr = UA_VariableAttributes_default;
            signature_byte_buffer_attr.displayName = config::sensor_config_array_ast[idx].sensor_child.signature_child.signature_buffer.displ_name;

            signature_byte_buffer_attr.description = config::sensor_config_array_ast[idx].sensor_child.signature_child.signature_buffer.description;
            std::vector<uint8_t> tmpBuffer(config::sensor_config_array_ast[idx].signature_len, 0);

            UA_Variant_setArray(&signature_byte_buffer_attr.value,
                                tmpBuffer.data(),
                                config::sensor_config_array_ast[idx].signature_len,
                                &UA_TYPES[UA_TYPES_BYTE]);

            UA_Server_addVariableNode(
                server,
                config::sensor_config_array_ast[idx].sensor_child.signature_child.signature_buffer.id,
                config::sensor_config_array_ast[idx].sensor_child.signature_object.id,
                UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                config::sensor_config_array_ast[idx].sensor_child.signature_child.signature_buffer.qualified_name,
                UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                signature_byte_buffer_attr,
                NULL,
                NULL);
        }
    }
}

/**
 * @brief Patch the data from the sensor -> Server lib
 *
 * @param config_index location in the configuration of the table
 * @param input_data
 */
void fetch_data(size_t config_index, std::string input_data)
{
    namespace config = server_configuration;
    size_t number_of_config = sizeof(config::sensor_config_array_ast) /
                              sizeof(config::sensor_config_array_ast[0]);
    if (config_index > number_of_config)
    {
        return;
    }
    else
    {
        config::sensor_config_array_ast[config_index].data_and_timestamp = input_data;
    }
}

/**
 * @brief Patch the signature from the sensor -> Severlib, shall be called by sensor
 *
 * @param config_index Index inthe configuration table
 * @param signature Span of the signature
 */
void fetch_signature(size_t config_index, std::span<uint8_t> signature)
{
    namespace config = server_configuration;
    size_t number_of_config = sizeof(config::sensor_config_array_ast) /
                              sizeof(config::sensor_config_array_ast[0]);
    if (config_index > number_of_config)
    {
        return;
    }
    else
    {
        // Copy data from source to the buffer
        std::copy(signature.begin(),
                  signature.end(),
                  config::sensor_config_array_ast[config_index].signature.begin());
    }
}
