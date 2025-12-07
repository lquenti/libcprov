#include <cstdint>
#include <iostream>
#include <model.hpp>
#include <string>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>

struct RecordParameters {
    std::unordered_map<std::string, std::string>& exec_rename_map;
    std::unordered_map<std::string, std::string>& exec_symlink_map;
    ExecProvOperations& exec_prov_operations;
    ProcessProvOperations& process_prov_operations;
};

void rename_writes(RecordParameters& record_parameters) {
    std::unordered_set<std::string>& writes
        = record_parameters.exec_prov_operations.writes;
    for (const std::pair<std::string, std::string>& kv :
         record_parameters.exec_rename_map) {
        const std::string& new_file_name = kv.first;
        const std::string& original_file_name = kv.second;
        std::unordered_set<std::string>::const_iterator it
            = writes.find(original_file_name);
        if (it != writes.end()) {
            writes.erase(it);
            writes.insert(new_file_name);
        }
    }
}

std::string resolve_path(
    const std::string& path,
    const std::unordered_map<std::string, std::string>& path_map) {
    auto it = path_map.find(path);
    if (it != path_map.end()) {
        return it->second;
    }
    return path;
}

std::unordered_map<std::string, std::string> combine_path_maps(
    std::unordered_map<std::string, std::string> rename_map,
    std::unordered_map<std::string, std::string> symlink_map) {
    std::unordered_map<std::string, std::string> combined_path_maps
        = rename_map;
    combined_path_maps.insert(symlink_map.begin(), symlink_map.end());
    return combined_path_maps;
}

template <std::unordered_set<std::string> ExecProvOperations::* ExecOperation>
void record_exec_path(const std::string& path,
                      RecordParameters& record_parameters) {
    const std::unordered_map<std::string, std::string>& exec_rename_map
        = record_parameters.exec_rename_map;
    const std::unordered_map<std::string, std::string>& exec_symlink_map
        = record_parameters.exec_symlink_map;
    std::unordered_map<std::string, std::string> exec_combined_path_maps
        = combine_path_maps(exec_rename_map, exec_symlink_map);
    std::string exec_path = resolve_path(path, exec_combined_path_maps);
    (record_parameters.exec_prov_operations.*ExecOperation).insert(exec_path);
}

template <
    std::vector<ProcessProvOperation> ProcessProvOperations::* ProcessOperation>
void record_process_path(uint64_t ts, const std::string& path,
                         RecordParameters& record_parameters) {
    ProcessProvOperation op{.ts = ts, .path = path};
    (record_parameters.process_prov_operations.*ProcessOperation).push_back(op);
}

void record_write(const uint64_t& ts, const std::string& path,
                  RecordParameters& record_parameters) {
    record_exec_path<&ExecProvOperations::writes>(path, record_parameters);
    record_process_path<&ProcessProvOperations::writes>(ts, path,
                                                        record_parameters);
}

void record_read(const uint64_t& ts, const std::string& path,
                 RecordParameters& record_parameters) {
    record_exec_path<&ExecProvOperations::reads>(path, record_parameters);
    record_process_path<&ProcessProvOperations::reads>(ts, path,
                                                       record_parameters);
}

void record_execute_exec(const uint64_t& ts, const std::string& path,
                         RecordParameters& record_parameters) {
    record_exec_path<&ExecProvOperations::executes>(path, record_parameters);
}

void record_delete(const uint64_t& ts, const std::string& path,
                   RecordParameters& record_parameters) {
    record_process_path<&ProcessProvOperations::deletes>(ts, path,
                                                         record_parameters);
}

void record_process_exec(const uint64_t& ts, const std::string& path,
                         const uint64_t& child_pid,
                         RecordParameters& record_parameters) {
    ProcessProvExec process_prov_exec{
        .ts = ts, .child_pid = child_pid, .target_path = path};
    record_parameters.process_prov_operations.executes.push_back(
        process_prov_exec);
}

template <std::vector<ProcessProvNamebind> ProcessProvOperations::* NamebindOps>
void record_namebind(uint64_t ts, const std::string& path_target,
                     const std::string& path_source,
                     RecordParameters& record_parameters) {
    ProcessProvNamebind namebind{
        .ts = ts, .path_source = path_source, .path_target = path_target};
    (record_parameters.process_prov_operations.*NamebindOps)
        .push_back(namebind);
}

void record_rename(const uint64_t& ts, const std::string& path_target,
                   const std::string& path_source,
                   RecordParameters& record_parameters) {
    record_namebind<&ProcessProvOperations::renames>(
        ts, path_target, path_source, record_parameters);
}

void record_link(const uint64_t& ts, const std::string& path_target,
                 const std::string& path_source,
                 RecordParameters& record_parameters) {
    record_namebind<&ProcessProvOperations::link>(ts, path_target, path_source,
                                                  record_parameters);
}

void record_symlink(const uint64_t& ts, const std::string& path_target,
                    const std::string& path_source,
                    RecordParameters& record_parameters) {
    record_namebind<&ProcessProvOperations::symlink>(
        ts, path_target, path_source, record_parameters);
}

std::pair<std::string, std::string> case_link_body(
    const uint64_t& event_ts, RecordParameters& record_parameters,
    const EventPayload& event_payload) {
    const std::unordered_map<std::string, std::string>& exec_rename_map
        = record_parameters.exec_rename_map;
    std::unordered_map<std::string, std::string>& exec_symlink_map
        = record_parameters.exec_symlink_map;
    const AccessInOut& access_in_out = std::get<AccessInOut>(event_payload);
    std::string path_out = access_in_out.path_out;
    std::string path_in = access_in_out.path_in;
    std::unordered_map<std::string, std::string> combined_path_maps
        = combine_path_maps(exec_rename_map, exec_symlink_map);
    std::string exec_path = resolve_path(path_in, combined_path_maps);
    exec_symlink_map[path_out] = exec_path;
    record_write(event_ts, path_out, record_parameters);
    return std::make_pair(path_out, path_in);
}

struct OperationTable {
    bool read;
    bool write;
    bool execute;
};

struct DBProcessEvents {
    std::unordered_map<std::string, OperationTable> operation_map;
};
/*
struct AllDBProcessEvents {
    std::unordered_map<uint64_t, DBProcessEvents> process_events_map;
};

struct GoedlEvents {
    std::unordered_map<std::string, OperationTable> operation_map;
};
*/

struct EventRecorder {
    std::unordered_map<std::string, std::string> goedl_rename_map;
    std::unordered_map<std::string, OperationTable> goedl_events_operation_map;
    std::unordered_map<uint64_t, DBProcessEvents> all_process_events_map;
    std::vector<std::string> process_json_operation_objects;
    uint64_t current_pid;
    std::string current_operation;
    DBProcessEvents current_process_events;
    std::string resolve_path(const std::string& path) {
        auto it = this->goedl_rename_map.find(path);
        if (it != this->goedl_rename_map.end()) {
            return it->second;
        }
        return path;
    }
    void add_current_process(const std::string& current_db_payload) {
        std::string current_header = R"({"operation":")"
                                     + this->current_operation + R"(","pid":)"
                                     + this->current_pid + R"(,)";
        this->process_json_operation_objects.push_back(current_header
                                                       + current_db_payload);
    }
    void log_read(const std::string& path) {
        std::string resolved_path = resolve_path(path);
        goedl_events_operation_map[resolved_path].read = true;
        auto& table
            = this->all_process_events_map[current_pid].operation_map[path];
        if (!table.read) {
            table.read = true;
            std::string current_db_payload
                = R"("path_in":")" + resolved_path + R"("})";
            add_current_process(current_db_payload);
        }
    }
    void log_write(const std::string& path) {
        std::string resolved_path = resolve_path(path);
        goedl_events_operation_map[resolved_path].write = true;
        auto& table
            = this->all_process_events_map[current_pid].operation_map[path];
        if (!table.write) {
            table.write = true;
            std::string current_db_payload
                = R"("path_out":")" + resolved_path + R"("})";
            add_current_process(current_db_payload);
        }
    }
    void log_exec(const std::string& path, const uint64_t ppid) {
        std::string resolved_path = resolve_path(path);
        goedl_events_operation_map[resolved_path].exec = true;
        auto& table
            = this->all_process_events_map[current_pid].operation_map[path];
        if (!table.exec) {
            table.exec = true;
            std::string current_db_payload = R"("path_out":")" + resolved_path
                                             + R"(","ppid":)" + ppid + R"(})";
            add_current_process(current_db_payload);
        }
    }
    void remove_path_from_operations(const std::string& path) {
        auto& table
            = this->all_process_events_map[current_pid].operation_map[path];
        table.read = false;
        table.write = false;
        table.exec = false;
    }
    void rename(const std::string& origin_path, const std::string& new_path) {
        if (this->goedl_rename_map.find(origin_path)
            == this->goedl_rename_map.end()) {
            this->goedl_rename_map[new_path] = origin_path;
        } else {
            this->goedl_rename_map[new_path]
                = this->goedl_rename_map[origin_path];
            this->goedl_rename_map.erase(origin_path);
        }
        remove_path_from_operations(origin_path);
    }
};

void process_events(std::vector<Event> events) {
    // std::unordered_map<std::string, std::string> exec_rename_map;
    // std::unordered_map<std::string, std::string> exec_symlink_map;
    bool first_event = true;
    for (Event event : events) {
        uint64_t event_pid = event.pid;
        uint64_t event_ts = event.ts;
        SysOp op = event.operation;
        const EventPayload& event_payload = event.event_payload;
        // DBProcessEvents current_process_events
        //     = all_process_events.process_events_map[pid];
        /*
        ProcessProvData& current_process_prov_data
            = current_exec_prov_data.process_map[event_pid];
        ProcessProvOperations& process_prov_operations
            = current_process_prov_data.prov_operations;
        RecordParameters record_parameters = {
            .exec_rename_map = exec_rename_map,
            .exec_symlink_map = exec_symlink_map,
            .exec_prov_operations = exec_prov_operations,
            .process_prov_operations = process_prov_operations,
        };
        */

        switch (op) {
            case SysOp::ProcessStart: {
                if (first_event) {
                    ProcessStart process_start
                        = std::get<ProcessStart>(event_payload);
                    uint64_t ppid = process_start.ppid;
                    // current_process_prov_data.start_time = event.ts;
                    // current_process_prov_data.ppid = ppid;
                    db_json = R"({"operation":"PROCESS_START", "pid":})"
                              + event_pid + R"({})";
                    process_json_operation_objects.push_back();
                    first_event = false;
                }
                break;
            }
            case SysOp::ProcessEnd: {
                break;
            }
            case SysOp::Write:
            case SysOp::Writev:
            case SysOp::Pwrite:
            case SysOp::Pwritev:
            case SysOp::Truncate:
            case SysOp::Fallocate: {
                AccessOut access_out = std::get<AccessOut>(event_payload);
                std::string path_out = access_out.path_out;
                record_write(event_ts, path_out, record_parameters);
                break;
            }
            case SysOp::Read:
            case SysOp::Readv:
            case SysOp::Pread:
            case SysOp::Preadv: {
                AccessIn access_in = std::get<AccessIn>(event_payload);
                std::string path_in = access_in.path_in;
                record_read(event_ts, path_in, record_parameters);
                break;
            }
            case SysOp::Transfer: {
                AccessInOut access_in_out
                    = std::get<AccessInOut>(event_payload);
                std::string path_out = access_in_out.path_out;
                std::string path_in = access_in_out.path_in;
                record_write(event_ts, path_out, record_parameters);
                record_read(event_ts, path_in, record_parameters);
                break;
            }
            case SysOp::Rename: {
                const auto& access_in_out
                    = std::get<AccessInOut>(event_payload);
                std::string path_out = access_in_out.path_out;
                std::string path_in = access_in_out.path_in;
                if (exec_rename_map.find(path_in) == exec_rename_map.end()) {
                    exec_rename_map[path_out] = path_in;
                } else {
                    exec_rename_map[path_out] = exec_rename_map[path_in];
                    exec_rename_map.erase(path_in);
                }
                record_rename(event_ts, path_out, path_in, record_parameters);
                break;
            }
            case SysOp::Link: {
                auto [path_out, path_in] = case_link_body(
                    event_ts, record_parameters, event_payload);
                record_link(event_ts, path_out, path_in, record_parameters);
                break;
            }
            case SysOp::SymLink: {
                auto [path_out, path_in] = case_link_body(
                    event_ts, record_parameters, event_payload);
                record_symlink(event_ts, path_out, path_in, record_parameters);
                break;
            }
            case SysOp::Unlink: {
                const auto& access_out = std::get<AccessOut>(event_payload);
                std::string path_out = access_out.path_out;
                exec_symlink_map.erase(path_out);
                record_delete(event_ts, path_out, record_parameters);
                break;
            }
            case SysOp::Exec:
            case SysOp::System: {
                const auto& access_exec = std::get<ExecCall>(event_payload);
                std::string target = access_exec.target;
                record_execute_exec(event_ts, target, record_parameters);
                record_process_exec(event_ts, target, event_pid,
                                    record_parameters);
                break;
            }
            case SysOp::Spawn: {
                const auto& access_spawn = std::get<SpawnCall>(event_payload);
                std::string target = access_spawn.target;
                uint64_t child_pid = access_spawn.child_pid;
                record_execute_exec(event_ts, target, record_parameters);
                record_process_exec(event_ts, target, child_pid,
                                    record_parameters);
                break;
            }
            case SysOp::Fork: {
                const auto& access_fork = std::get<ForkCall>(event_payload);
                uint64_t child_pid = access_fork.child_pid;
                record_process_exec(event_ts, "", child_pid, record_parameters);
                break;
            }
            default:
                break;
        }
        events.pop();
    }
    processed_job_data.exec_prov_data_queue.push(current_exec_prov_data);
}
