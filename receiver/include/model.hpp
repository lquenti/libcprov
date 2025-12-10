#pragma once

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

enum class InjectorDataType { Start, End, Exec };

enum class OperationType {
    ProcessStart,
    Read,
    Write,
    Execute,
    Rename,
    Link,
    Symlink,
    Delete
};

struct ProcessStart {};
struct Read {
    std::string path_in;
};
struct Write {
    std::string path_out;
};
struct Execute {
    std::string path_exec;
    uint64_t child_pid;
};
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
};
struct Delete {
    std::string deleted_path;
};

struct Event {
    uint64_t pid;
    int order_number;
    OperationType operation_type;
    std::variant<ProcessStart, Read, Write, Execute, Rename, Link, Symlink,
                 Delete>
        operation_data;
};

struct ExecData {
    uint64_t exec_hash_id;
    std::vector<Event> events;
    std::string json;
    std::string path;
    std::string command;
};

struct StartData {
    uint64_t slurm_job_id;
    std::string slurm_cluster_name;
    std::string json;
    std::string path;
    ExecData exec_data;
};

struct EndData {
    std::string json;
};

struct ParsedInjectorData {
    InjectorDataType injector_data_type;
    uint64_t job_hash_id;
    uint64_t timestamp;
    std::variant<StartData, EndData, ExecData> payload;
};
