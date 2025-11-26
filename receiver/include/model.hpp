#pragma once
#include <cstdint>
#include <string>
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
    std::string step_id;
    std::string step_name;
};
struct ProcessEnd {};

using EventPayload
    = std::variant<AccessIn, AccessOut, AccessInOut, ExecCall, SpawnCall,
                   ForkCall, ProcessStart, ProcessEnd>;

struct Event {
    uint64_t ts = 0;
    SysOp operation = SysOp::Unknown;
    EventPayload payload;
};

enum class CallType { Start, End, Exec };

struct ParsedBatch {
    CallType type;
    uint64_t pid;
    std::string job_id;
    std::string cluster_name;
    std::string path;
    std::vector<Event> events;
};
