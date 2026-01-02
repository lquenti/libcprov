#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

enum class SysOp {
    Write,
    Writev,
    Pwrite,
    Pwritev,
    Truncate,
    Msync,
    Fallocate,
    Read,
    Readv,
    Pread,
    Preadv,
    Getdents,
    Transfer,
    Open,
    Close,
    Dup,
    Pipe,
    Rename,
    Link,
    SymLink,
    Unlink,
    NetSend,
    NetRecv,
    Exec,
    Spawn,
    Fork,
    System,
    ProcessStart,
    ProcessEnd,
    JobStart,
    JobEnd,
    Unknown
};

struct EventHeader {
    uint64_t ts = 0;
    SysOp op = SysOp::Unknown;
    std::string raw_type;
};
struct AccessIn {
    std::string path_in;
    uint32_t count = 0;
};
struct AccessOut {
    std::string path_out;
    uint32_t count = 0;
};
struct AccessInOut {
    std::string path_in;
    std::string path_out;
};
struct ExecCall {
    std::string target;
    int target_fd = -1;
    std::string target_path;
    int err = 0;
    bool failed = false;
};
struct SpawnCall {
    uint64_t child_pid = -1;
    std::string target;
};
struct ForkCall {
    uint64_t child_pid = -1;
};
struct ProcessStart {
    uint64_t ppid = 0;
    std::string process_name;
    std::string env_variables;
    std::string process_hash;
    // std::string step_id;
    // std::string step_name;
};
struct ProcessEnd {};

using EventPayload
    = std::variant<AccessIn, AccessOut, AccessInOut, ExecCall, SpawnCall,
                   ForkCall, ProcessStart, ProcessEnd>;

struct Event {
    uint64_t ts = 0;
    SysOp operation = SysOp::Unknown;
    uint64_t pid = 0;
    std::string slurmd_nodename = "";
    EventPayload event_payload;
};

struct OperationTable {
    bool read = false;
    bool write = false;
    bool execute = false;
};

struct GoedlOperations {
    std::unordered_map<std::string, OperationTable> goedl_operation_map;
};

struct EnvVariablesHashToVariables {
    uint64_t hash;
    std::string env_variables;
};

using ExecuteSetMap
    = std::unordered_map<uint64_t, std::unordered_set<uint64_t>>;

struct Operations {
    bool read = false;
    bool write = false;
    bool deleted = false;
};

struct Process {
    std::string process_name;
    uint64_t env_variable_hash;
    // std::vector<std::string> process_json_operation_objects_;
    std::unordered_map<std::string, Operations> operation_map;
};
using ProcessMap = std::unordered_map<uint64_t, Process>;
struct ProcessedExecData {
    ProcessMap process_map;
    std::unordered_map<std::string, std::string> rename_map;
    ExecuteSetMap execute_set_map;
    std::unordered_map<uint64_t, std::string> env_variables_hash_to_variables;
};
struct ProcessedInjectorData {
    GoedlOperations goedl_operations;
    ProcessedExecData processed_exec_data;
};
