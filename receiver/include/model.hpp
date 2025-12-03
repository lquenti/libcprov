#pragma once
#include <cstdint>
#include <mutex>
#include <queue>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <variant>

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
    uint64_t pid = 0;
    EventPayload event_payload;
};

enum class CallType { Start, End, Exec };

struct StartOrEnd {
    uint64_t ts = 0;
};

struct Exec {
    uint64_t start_time = 0;
    uint64_t end_time = 0;
    std::queue<Event> events;
};

using RequestPayload = std::variant<StartOrEnd, Exec>;

struct ParsedRequest {
    CallType type;
    std::string job_id;
    std::string cluster_name;
    std::string path;
    RequestPayload request_payload;
};

struct ParsedRequestQueue {
    std::mutex queue_mutex;
    std::queue<ParsedRequest> parsed_batch_queue;
    void push(ParsedRequest batch) {
        std::lock_guard<std::mutex> lock(queue_mutex);
        parsed_batch_queue.push(std::move(batch));
    }
    std::queue<ParsedRequest> take_all() {
        std::lock_guard<std::mutex> lock(queue_mutex);
        std::queue<ParsedRequest> copy = std::move(parsed_batch_queue);
        parsed_batch_queue = {};
        return copy;
    }
};

struct ProcessProvOperation {
    uint64_t ts;
    std::string path;
};
struct ProcessProvNamebind {
    uint64_t ts;
    std::string path_source;
    std::string path_target;
};
struct ProcessProvExec {
    uint64_t ts;
    uint64_t child_pid;
    std::string target_path;
    // bool failed = false;
};
struct ProcessProvOperations {
    std::vector<ProcessProvOperation> reads;
    std::vector<ProcessProvOperation> writes;
    std::vector<ProcessProvExec> executes;
    std::vector<ProcessProvNamebind> renames;
    std::vector<ProcessProvNamebind> link;
    std::vector<ProcessProvNamebind> symlink;
    std::vector<ProcessProvOperation> deletes;
};

struct ProcessProvData {
    std::string node;
    uint64_t ppid;
    uint64_t start_time;
    uint64_t end_time;
    std::unordered_map<std::string, std::string> symlink_map;
    ProcessProvOperations prov_operations;
};

struct ExecProvOperations {
    std::unordered_set<std::string> reads;
    std::unordered_set<std::string> writes;
    std::unordered_set<std::string> executes;
};

struct ExecProvData {
    std::string step_name;
    uint64_t start_time;
    uint64_t end_time;
    std::unordered_map<std::string, std::string> rename_map;
    std::unordered_map<std::string, std::string> symlink_map;
    ExecProvOperations prov_operations;
    std::unordered_map<uint64_t, ProcessProvData> process_map;
};

struct ProcessedJobData {
    std::string job_id;
    std::string cluster_name;
    std::string job_name;
    std::string nodelist;
    std::string user;
    std::string path;
    uint64_t start_time;
    uint64_t end_time;
    std::queue<ExecProvData> exec_prov_data_queue;
};
