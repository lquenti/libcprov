#include "parser.hpp"

#include <simdjson.h>

using namespace simdjson;

static std::string get_string(ondemand::object& obj, const char* name) {
    auto s = obj.find_field_unordered(name).get_string();
    if (!s.error()) {
        return std::string(s.value());
    }
    return "";
}

static uint64_t get_uint64(ondemand::object& obj, const char* name) {
    auto s = obj.find_field_unordered(name).get_uint64();
    if (!s.error()) {
        return s.value();
    }
    return 0;
}

CallType get_call_type(std::string& type) {
    CallType current_call_type;
    if (type == "start") {
        current_call_type = CallType::Start;
    } else if (type == "end") {
        current_call_type = CallType::End;
    } else if (type == "exec") {
        current_call_type = CallType::Exec;
    }
    return current_call_type;
}

static inline bool one_of(std::string_view t, std::string_view a) {
    return t == a;
}
template <class... Ss>
static inline bool one_of(std::string_view t, std::string_view a, Ss... s) {
    return (t == a) || one_of(t, s...);
}
static SysOp sysop_from(std::string_view t) {
    using O = SysOp;
    if (one_of(t, "WRITE", "FWRITE", "DPRINTF", "FPUTS", "FPRINTF", "VFPRINTF",
               "FPUTC", "FPUTS_UNLOCKED", "FWRITE_UNLOCKED"))
        return O::Write;
    if (one_of(t, "WRITEV", "PWRITEV", "PWRITEV2")) return O::Writev;
    if (one_of(t, "PWRITE", "PWRITE64")) return O::Pwrite;
    if (one_of(t, "TRUNCATE", "FTRUNCATE")) return O::Truncate;
    if (one_of(t, "MSYNC")) return O::Msync;
    if (one_of(t, "READ")) return O::Read;
    if (one_of(t, "READV", "PREADV", "PREADV2")) return O::Readv;
    if (one_of(t, "PREAD", "PREAD64")) return O::Pread;
    if (one_of(t, "GETDENTS", "GETDENTS64")) return O::Getdents;
    if (one_of(t, "COPY_FILE_RANGE", "SENDFILE", "SENDFILE64", "SPLICE"))
        return O::Transfer;
    if (one_of(t, "OPEN", "OPEN64", "OPENAT", "OPENAT2", "CREAT"))
        return O::Open;
    if (one_of(t, "CLOSE", "FCLOSE", "CLOSE_RANGE")) return O::Close;
    if (one_of(t, "DUP", "DUP2", "DUP3")) return O::Dup;
    if (one_of(t, "PIPE", "PIPE2")) return O::Pipe;
    if (one_of(t, "RENAME", "RENAMEAT", "RENAMEAT2")) return O::Rename;
    if (one_of(t, "LINK", "LINKAT")) return O::Link;
    if (one_of(t, "SYMLINK", "SYMLINKAT")) return O::SymLink;
    if (one_of(t, "UNLINK", "UNLINKAT", "REMOVE", "RMDIR", "SHM_UNLINK",
               "MQ_UNLINK", "SEM_UNLINK"))
        return O::Unlink;
    if (one_of(t, "SENDTO", "SENDMSG", "SENDMMSG")) return O::NetSend;
    if (one_of(t, "RECVFROM", "RECVMSG", "RECVMMSG")) return O::NetRecv;
    if (one_of(t, "EXECVE", "EXECVEAT", "FEXECVE", "EXECV", "EXECL", "EXECLP",
               "EXECPVP", "EXECPVE", "EXECLE"))
        return O::Exec;
    if (one_of(t, "SYSTEM")) return O::System;
    if (one_of(t, "POSIX_SPAWN", "POSIX_SPAWNP")) return O::Spawn;
    if (one_of(t, "FORK", "VFORK", "CLONE")) return O::Fork;
    if (one_of(t, "PROCESS_START")) return O::ProcessStart;
    if (one_of(t, "PROCESS_END")) return O::ProcessEnd;
    if (one_of(t, "JOB_START")) return O::JobStart;
    if (one_of(t, "JOB_END")) return O::JobEnd;
    return O::Unknown;
}

std::vector<Event> parse_events(ondemand::object& payload) {
    std::vector<Event> processedEvents;
    ondemand::array events
        = payload.find_field_unordered("events").get_array().value();
    for (ondemand::value event_val : events) {
        auto event_obj = event_val.get_object().value();
        Event new_event;
        ondemand::object event_header
            = event_obj.find_field_unordered("event_header")
                  .get_object()
                  .value();
        ondemand::object event_data
            = event_obj.find_field_unordered("event_data").get_object().value();
        new_event.ts = get_uint64(event_header, "ts");
        std::string operation = get_string(event_header, "operation");
        SysOp current_sysop = sysop_from(operation);
        new_event.operation = current_sysop;
        using O = SysOp;
        switch (current_sysop) {
            case O::ProcessStart:
                new_event.payload
                    = ProcessStart{.ppid = get_uint64(event_data, "ppid")};
                break;
            case O::ProcessEnd:
                new_event.payload = ProcessEnd{};
                break;
            case O::Read:
            case O::Readv:
            case O::Pread:
            case O::Preadv:
                new_event.payload
                    = AccessIn{.path_in = get_string(event_data, "path_in")};
                break;
            case O::Write:
            case O::Writev:
            case O::Pwrite:
            case O::Pwritev:
            case O::Truncate:
            case O::Fallocate:
                new_event.payload
                    = AccessOut{.path_out = get_string(event_data, "path_out")};
                break;
            case O::Transfer:
            case O::Rename:
            case O::Link:
            case O::SymLink:
                new_event.payload = AccessInOut{
                    .path_in = get_string(event_data, "path_in"),
                    .path_out = get_string(event_data, "path_out")};
                break;
            case O::Exec:
            case O::System:
                new_event.payload
                    = ExecCall{.target = get_string(event_data, "path")};
                break;
            case O::Spawn:
                new_event.payload = SpawnCall{
                    .child_pid = get_uint64(event_data, "child_pid"),
                    .target = get_string(event_data, "path")};
                break;
            case O::Fork:
                new_event.payload = ForkCall{
                    .child_pid = get_uint64(event_data, "child_pid")};
                break;
        }
        processedEvents.push_back(new_event);
    }
    return processedEvents;
}

ParsedBatch parse_batch(const std::string& json_body) {
    ParsedBatch new_batch;
    ondemand::parser parser;
    padded_string p(json_body);
    auto doc = parser.iterate(p);
    auto env = doc.get_object().value();
    auto hdr = env.find_field_unordered("header").get_object().value();
    std::string type = get_string(hdr, "type");
    new_batch.type = get_call_type(type);
    new_batch.pid = get_uint64(hdr, "pid");
    new_batch.job_id = get_string(hdr, "job_id");
    new_batch.cluster_name = get_string(hdr, "cluster_name");
    auto payload = env.find_field_unordered("payload").get_object().value();
    new_batch.path = get_string(payload, "path");
    if (type == "exec") {
        new_batch.events = parse_events(payload);
    }
    return new_batch;
}
