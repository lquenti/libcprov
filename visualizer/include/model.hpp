#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

enum class ResponseType { ProvData, Error };
enum class OperationType { Read, Write, Delete };

struct ProcessStart {
    std::string process_name;
    uint64_t env_variables_hash;
};
struct Read {
    std::string path_in;
};
struct Write {
    std::string path_out;
};
struct Delete {
    std::string deleted_path;
};
using ExecuteSetMap
    = std::unordered_map<uint64_t, std::unordered_set<uint64_t>>;
using RenameMap = std::unordered_map<std::string, std::string>;

struct Operations {
    bool read = false;
    bool write = false;
    bool deleted = false;
};

struct Process {
    std::string process_command;
    uint64_t env_variable_hash;
    std::unordered_map<std::string, Operations> operation_map;
};

using EnvVariableHashPairs = std::unordered_map<uint64_t, std::string>;
using ProcessMap = std::unordered_map<uint64_t, Process>;
struct ExecData {
    uint64_t exec_id;
    uint64_t start_time;
    ProcessMap process_map;
    ExecuteSetMap execute_set_map;
    RenameMap rename_map;
    EnvVariableHashPairs env_variables_hash_to_variables;
    std::string json;
    std::string path;
    std::string command;
};

struct JobData {
    std::string job_name;
    std::string username;
    uint64_t start_time;
    uint64_t end_time;
    std::string path;
    std::string json;
    std::vector<ExecData> execs;
};

struct ParsedLibcprovData {
    ResponseType response_type;
    std::optional<JobData> job_data;
};
