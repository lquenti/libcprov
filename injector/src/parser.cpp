#include "parser.hpp"

#include <simdjson.h>

#include <cstdint>
#include <filesystem>
#include <iterator>
#include <string>
#include <vector>

using namespace simdjson;
/*
std::vector<Event> parse_injector_data(const std::string& path_access) {
    std::vector<Event> events;
    std::vector<std::string> filenames;
    ondemand::parser parser;
    for (const auto& entry : std::filesystem::directory_iterator(path_access)) {
        std::ifstream injector_data_file(entry.path());
        std::string json_object;
        bool first = true;
        uint64_t child_pid;
        while (std::getline(injector_data_file, json_object)) {
            ondemand::document doc = parser.iterate(json_object);

            padded_string p(json_body);
            auto doc = parser.iterate(p);
            auto env = doc.get_object().value();
            auto hdr = env.find_field_unordered("header").get_object().value();
*/

std::string get_string(ondemand::object& obj, const char* name) {
    auto s = obj.find_field_unordered(name).get_string();
    if (!s.error()) {
        return std::string(s.value());
    }
    return "";
}

uint64_t get_uint64(ondemand::object& obj, const char* name) {
    auto s = obj.find_field_unordered(name).get_uint64();
    if (!s.error()) {
        return s.value();
    }
    return 0;
}

bool one_of(std::string_view t, std::string_view a) {
    return t == a;
}
template <class... Ss>
bool one_of(std::string_view t, std::string_view a, Ss... s) {
    return (t == a) || one_of(t, s...);
}
SysOp sysop_from(std::string_view t) {
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
    return O::Unknown;
}

Event parse_event_object(ondemand::object event_obj, uint64_t& pid) {
    auto hdr_res = event_obj.find_field_unordered("event_header").get_object();
    auto hdr = hdr_res.value();
    uint64_t ts = get_uint64(hdr, "ts");
    std::string op = get_string(hdr, "operation");
    ondemand::object event_data{};
    auto dr = event_obj.find_field_unordered("event_data").get_object();
    event_data = dr.value();
    Event new_event;
    new_event.ts = ts;
    new_event.operation = sysop_from(op);
    new_event.pid = pid;
    using O = SysOp;
    switch (new_event.operation) {
        case O::ProcessStart:
            new_event.event_payload
                = ProcessStart{.ppid = get_uint64(event_data, "ppid")};
            pid = get_uint64(event_data, "pid");
            new_event.pid = pid;
            break;
        case O::ProcessEnd:
            new_event.event_payload = ProcessEnd{};
            break;
        case O::Read:
        case O::Readv:
        case O::Pread:
        case O::Preadv:
            new_event.event_payload
                = AccessIn{.path_in = get_string(event_data, "path_in")};
            break;
        case O::Write:
        case O::Writev:
        case O::Pwrite:
        case O::Pwritev:
        case O::Truncate:
        case O::Fallocate:
            new_event.event_payload
                = AccessOut{.path_out = get_string(event_data, "path_out")};
            break;
        case O::Transfer:
        case O::Rename:
        case O::Link:
        case O::SymLink:
            new_event.event_payload
                = AccessInOut{.path_in = get_string(event_data, "path_in"),
                              .path_out = get_string(event_data, "path_out")};
            break;
        case O::Exec:
        case O::System:
            new_event.event_payload
                = ExecCall{.target = get_string(event_data, "path")};
            break;
        case O::Spawn:
            new_event.event_payload
                = SpawnCall{.child_pid = get_uint64(event_data, "child_pid"),
                            .target = get_string(event_data, "path")};
            break;
        case O::Fork:
            new_event.event_payload
                = ForkCall{.child_pid = get_uint64(event_data, "child_pid")};
            break;
    }
    return new_event;
}

std::vector<Event> parse_jsonl_file(const std::string& path,
                                    simdjson::ondemand::parser& parser) {
    std::vector<Event> events;
    auto p_res = simdjson::padded_string::load(path);
    simdjson::padded_string p = std::move(p_res.value());
    uint64_t current_pid = 0;
    auto stream_res = parser.iterate_many(p.data(), p.size(), size_t(1) << 20);
    for (auto doc : *stream_res) {
        auto obj_res = doc.get_object();
        auto ev_opt = parse_event_object(obj_res.value(), current_pid);
        events.push_back(std::move(ev_opt));
    }
    return events;
}

std::vector<Event> parse_all_jsonl_files(const std::string& path_access) {
    std::vector<Event> all_events;
    simdjson::ondemand::parser parser;
    for (const auto& entry : std::filesystem::directory_iterator(path_access)) {
        auto processed = parse_jsonl_file(entry.path().string(), parser);
        all_events.reserve(all_events.size() + processed.size());
        std::ranges::move(processed, std::back_inserter(all_events));
    }
    return all_events;
}
