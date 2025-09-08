#pragma once
#include <open62541/plugin/log_stdout.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>

#include <thread>

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
#include <span>
#include <thread>
#include <unordered_map>

#include "cert_parser.h"
#include "key_parser.h"

class opcua_server {
 public:
  enum operation_mode { CALLBACK = 0, EVENT_DRIVEN = 1, ON_DEMAND = 2 };
  // data integrity
  std::mutex data_mut;

  // operation mode;
  opcua_server(int repeat_time, operation_mode op_mode)
      : m_repeat_time{repeat_time}, m_op_mode{op_mode} {
    // load all the cert parser into ram
  }

  // add node
  int add_node() {}

  // data signing
  int signature_generate(std::string_view algo_name, std::span<uint8_t> data,
                         std::span<uint8_t> signature) {}

 private:
  // internal repeat time
  int m_repeat_time{1000};

  // internal repet mode
  int m_op_mode{opcua_server::operation_mode::CALLBACK};

  // node list
  std::vector<std::string> node_name;

  // OPC-UA node id
  std::unordered_map<std::string, UA_NodeId> m_nodeid_map;
};