#include "parser.hpp"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

enum : uint32_t {
    EV_PROCESS_START = 1,
    EV_PROCESS_END = 2,
    EV_READ = 3,
    EV_WRITE = 4,
    EV_TRANSFER = 5,
    EV_RENAME = 6,
    EV_UNLINK = 7,
    EV_EXEC = 8,
    EV_EXEC_FAIL = 9
};

#pragma pack(push, 1)
struct RecHdr {
    uint32_t type;
    uint32_t size;
    uint64_t ts_ns;
    int32_t pid;
    int32_t tid;
};
#pragma pack(pop)

static inline bool read_u32(const uint8_t* base, size_t size, size_t& pos,
                            uint32_t& out) {
    if (pos + sizeof(uint32_t) > size) return false;
    memcpy(&out, base + pos, sizeof(uint32_t));
    pos += sizeof(uint32_t);
    return true;
}

static inline bool read_i32(const uint8_t* base, size_t size, size_t& pos,
                            int32_t& out) {
    if (pos + sizeof(int32_t) > size) return false;
    memcpy(&out, base + pos, sizeof(int32_t));
    pos += sizeof(int32_t);
    return true;
}

static inline bool read_str(const uint8_t* base, size_t size, size_t& pos,
                            std::string& out) {
    uint32_t len;
    if (!read_u32(base, size, pos, len)) return false;
    if (pos + len > size) return false;
    out.assign((const char*)(base + pos), (size_t)len);
    pos += (size_t)len;
    return true;
}

static inline Event event_from_record(const uint8_t* rec_base,
                                      size_t rec_size) {
    const RecHdr* h = (const RecHdr*)rec_base;
    EventPayload empty_payload;
    Event e{.ts = h->ts_ns,
            .operation = SysOp::Exec,
            .process_id = "",
            .event_payload = empty_payload};
    size_t pos = sizeof(RecHdr);
    switch (h->type) {
        case EV_PROCESS_START: {
            e.operation = SysOp::ProcessStart;
            int32_t pid32 = 0;
            int32_t ppid32 = 0;
            std::string launch_command;
            std::string env_vars_json;
            if (!read_i32(rec_base, rec_size, pos, pid32)) break;
            if (!read_i32(rec_base, rec_size, pos, ppid32)) break;
            if (!read_str(rec_base, rec_size, pos, launch_command)) break;
            if (!read_str(rec_base, rec_size, pos, env_vars_json)) break;
            e.event_payload
                = ProcessStart{.pid = (uint64_t)pid32,
                               .ppid = (uint64_t)ppid32,
                               .process_name = std::move(launch_command),
                               .env_variables = std::move(env_vars_json)};
            break;
        }
        case EV_PROCESS_END: {
            e.operation = SysOp::ProcessEnd;
            break;
        }
        case EV_READ: {
            e.operation = SysOp::Read;
            int32_t fd = -1;
            std::string path;
            if (!read_i32(rec_base, rec_size, pos, fd)) break;
            if (!read_str(rec_base, rec_size, pos, path)) break;
            e.event_payload = std::move(path);
            break;
        }
        case EV_WRITE: {
            e.operation = SysOp::Write;
            int32_t fd = -1;
            std::string path;
            if (!read_i32(rec_base, rec_size, pos, fd)) break;
            if (!read_str(rec_base, rec_size, pos, path)) break;
            e.event_payload = std::move(path);
            break;
        }
        case EV_UNLINK: {
            e.operation = SysOp::Unlink;
            std::string path;
            if (!read_str(rec_base, rec_size, pos, path)) break;
            e.event_payload = std::move(path);
            break;
        }
        case EV_TRANSFER: {
            e.operation = SysOp::Transfer;
            int32_t rfd = -1;
            int32_t wfd = -1;
            std::string path_read;
            std::string path_write;
            if (!read_i32(rec_base, rec_size, pos, rfd)) break;
            if (!read_i32(rec_base, rec_size, pos, wfd)) break;
            if (!read_str(rec_base, rec_size, pos, path_read)) break;
            if (!read_str(rec_base, rec_size, pos, path_write)) break;
            e.event_payload = Transfer{.path_read = std::move(path_read),
                                       .path_write = std::move(path_write)};
            break;
        }
        case EV_RENAME: {
            e.operation = SysOp::Rename;
            std::string oldp;
            std::string newp;
            if (!read_str(rec_base, rec_size, pos, oldp)) break;
            if (!read_str(rec_base, rec_size, pos, newp)) break;
            e.event_payload = Rename{.original_path = std::move(oldp),
                                     .new_path = std::move(newp)};
            break;
        }
        case EV_EXEC: {
            e.operation = SysOp::Exec;
            break;
        }
        case EV_EXEC_FAIL: {
            e.operation = SysOp::ExecFail;
            break;
        }
        default: {
            break;
        }
    }
    return e;
}

static std::vector<Event> parse_bin_file(const std::string& path) {
    std::vector<Event> events;
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return events;
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return events;
    }
    size_t sz = (size_t)st.st_size;
    if (sz == 0) {
        close(fd);
        return events;
    }
    void* map = mmap(nullptr, sz, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        return events;
    }
    const uint8_t* base = (const uint8_t*)map;
    size_t off = 0;
    while (off + sizeof(RecHdr) <= sz) {
        const RecHdr* h = (const RecHdr*)(base + off);
        if (h->size < sizeof(RecHdr)) break;
        if (off + (size_t)h->size > sz) break;
        events.push_back(event_from_record(base + off, (size_t)h->size));
        off += (size_t)h->size;
    }
    munmap(map, sz);
    close(fd);
    return events;
}

EventsByFile parse_all_jsonl_files(const std::string& path_access) {
    EventsByFile events_by_file;
    for (const auto& entry : std::filesystem::directory_iterator(path_access)) {
        if (!entry.is_regular_file()) continue;
        events_by_file.push_back(parse_bin_file(entry.path().string()));
    }
    return events_by_file;
}
