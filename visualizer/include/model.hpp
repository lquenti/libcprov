#pragma once

#include <cstdint>
#include <optional>
#include <queue>
#include <string>
#include <variant>
#include <vector>

enum class ResponseType { ProvData, Error };

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
    OperationType operation_type;
    int order_number;
    uint64_t pid;
    std::variant<ProcessStart, Read, Write, Execute, Rename, Link, Symlink,
                 Delete>
        operation_data;
};

struct ExecData {
    uint64_t hash_id;
    uint64_t start_time;
    std::string path;
    std::string json;
    std::string command;
    std::vector<Event> events;
};

struct Payload {
    uint64_t hash_id;
    uint64_t start_time;
    uint64_t end_time;
    std::vector<ExecData> exec_vector;
};

struct ParsedLibcprovData {
    ResponseType response_type;
    std::optional<Payload> payload;
};
