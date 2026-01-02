#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

enum class InjectorDataType { Start, End, Exec };
enum class OperationType { Read, Write, Link, Symlink, Delete };

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
/*
struct Rename {
    std::string original_path;
    std::string new_path;
};
struct Link {
    std::string original_path;
    std::string new_path;
};
struct Symlink {
    std::string original_path;
    std::string new_path;
};*/

/*struct Operation {
    OperationType operation_type;
    // std::variant<Read, Write, Link, Symlink, Delete> operation_payload;
    std::variant<Read, Write, Delete> operation_payload;
};*/

struct Operations {
    bool read = false;
    bool write = false;
    bool deleted = false;
};

struct Process {
    std::string process_command;
    // uint64_t process_hash;
    uint64_t env_variable_hash;
    // std::vector<Operation> operations;
    std::unordered_map<std::string, Operations> operation_map;
};

using EnvVariableHashPairs = std::unordered_map<uint64_t, std::string>;
using ProcessMap = std::unordered_map<uint64_t, Process>;
struct ExecData {
    std::optional<uint64_t> exec_id;
    std::optional<uint64_t> start_time;
    ProcessMap process_map;
    ExecuteSetMap execute_set_map;
    RenameMap rename_map;
    EnvVariableHashPairs env_variables_hash_to_variables;
    std::string json;
    std::string path;
    std::string command;
};

struct StartData {
    std::string job_name;
    std::string username;
    std::string json;
    std::string path;
};

struct ParsedInjectorData {
    InjectorDataType injector_data_type;
    uint64_t job_id;
    std::string cluster_name;
    uint64_t timestamp;
    std::optional<std::variant<StartData, ExecData>> payload;
};

struct JobData {
    bool succeded;
    std::string job_name;
    std::string username;
    uint64_t start_time;
    uint64_t end_time;
    std::string path;
    std::string json;
    std::vector<ExecData> exec_data_vector;
};

struct ParsedGraphRequestData {
    uint64_t job_id;
    std::string cluster_name;
};
