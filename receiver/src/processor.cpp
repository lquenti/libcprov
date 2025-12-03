#include <iostream>
#include <model.hpp>
#include <string>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>

// tmp debug output

void print_process_operations(const ProcessProvOperations& ops) {
    auto print_vec = [](const auto& vec, const std::string& name) {
        using Elem = typename std::decay_t<decltype(vec)>::value_type;
        if (vec.empty()) return;

        std::cout << name << ":\n";
        for (const auto& op : vec) {
            if constexpr (std::is_same_v<Elem, ProcessProvOperation>) {
                std::cout << "  ts=" << op.ts << ", path=" << op.path << "\n";
            } else if constexpr (std::is_same_v<Elem, ProcessProvExec>) {
                std::cout << "  ts=" << op.ts << ", child_pid=" << op.child_pid
                          << ", target_path=" << op.target_path << "\n";
            } else if constexpr (std::is_same_v<Elem, ProcessProvNamebind>) {
                std::cout << "  ts=" << op.ts << ", source=" << op.path_source
                          << ", target=" << op.path_target << "\n";
            }
        }
    };

    print_vec(ops.reads, "Reads");
    print_vec(ops.writes, "Writes");
    print_vec(ops.executes, "Executes");
    print_vec(ops.renames, "Renames");
    print_vec(ops.link, "Links");
    print_vec(ops.symlink, "Symlinks");
    print_vec(ops.deletes, "Deletes");
}

void print_process_data(const ExecProvData& exec) {
    for (const auto& [pid, proc_data] : exec.process_map) {
        std::cout << "Process PID: " << pid << ", PPID: " << proc_data.ppid
                  << ", Start: " << proc_data.start_time
                  << ", End: " << proc_data.end_time << "\n";
        print_process_operations(proc_data.prov_operations);
        std::cout << "-------------------------------------" << std::endl;
    }
}

void print_set(const std::unordered_set<std::string>& s,
               const std::string& name) {
    std::cout << name << ": { ";
    for (const auto& item : s) {
        std::cout << item << " ";
    }
    std::cout << "}" << std::endl;
}

void print_exec_data(const ExecProvData& exec) {
    std::cout << "Exec Step Name: " << exec.step_name << "\n"
              << "Start Time: " << exec.start_time << "\n"
              << "End Time: " << exec.end_time << "\n";

    print_set(exec.prov_operations.reads, "Exec Reads");
    print_set(exec.prov_operations.writes, "Exec Writes");
    print_set(exec.prov_operations.executes, "Exec Executes");

    if (!exec.rename_map.empty()) {
        std::cout << "Rename Map: { ";
        for (const auto& [k, v] : exec.rename_map) {
            std::cout << k << "->" << v << " ";
        }
        std::cout << "}" << std::endl;
    }

    if (!exec.symlink_map.empty()) {
        std::cout << "Symlink Map: { ";
        for (const auto& [k, v] : exec.symlink_map) {
            std::cout << k << "->" << v << " ";
        }
        std::cout << "}" << std::endl;
    }

    std::cout << "---- Process-Level Provenance ----" << std::endl;
    print_process_data(exec);
    std::cout << "-------------------------------------" << std::endl;
}

void print_full_job_data(const ProcessedJobData& job) {
    std::cout << "=== Job ID: " << job.job_id
              << ", Cluster: " << job.cluster_name
              << ", Job Name: " << job.job_name << " ===\n"
              << "Path: " << job.path << "\n"
              << "Start Time: " << job.start_time
              << ", End Time: " << job.end_time << "\n"
              << "-------------------------------------\n";

    std::queue<ExecProvData> exec_queue_copy = job.exec_prov_data_queue;
    while (!exec_queue_copy.empty()) {
        const ExecProvData& exec = exec_queue_copy.front();
        print_exec_data(exec);
        exec_queue_copy.pop();
    }

    std::cout << "=== End of Job " << job.job_id << " ===\n\n";
}
//

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

void process_exec(const Exec& exec, ProcessedJobData& processed_job_data) {
    ExecProvData current_exec_prov_data;
    ExecProvOperations& exec_prov_operations
        = current_exec_prov_data.prov_operations;
    std::unordered_map<std::string, std::string>& exec_rename_map
        = current_exec_prov_data.rename_map;
    std::unordered_map<std::string, std::string>& exec_symlink_map
        = current_exec_prov_data.symlink_map;
    std::queue<Event> events = exec.events;
    ProcessProvOperations empty_process_prov_operations;
    while (!events.empty()) {
        const Event& event = events.front();
        uint64_t event_pid = event.pid;
        uint64_t event_ts = event.ts;
        SysOp op = event.operation;
        const EventPayload& event_payload = event.event_payload;
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

        switch (op) {
            case SysOp::ProcessStart: {
                ProcessStart process_start
                    = std::get<ProcessStart>(event_payload);
                uint64_t ppid = process_start.ppid;
                current_process_prov_data.start_time = event.ts;
                current_process_prov_data.ppid = ppid;
                break;
            }
            case SysOp::ProcessEnd: {
                current_process_prov_data.end_time = event.ts;
                rename_writes(record_parameters);
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

void process_parsed_requests(ParsedRequestQueue* parsed_request) {
    std::unordered_map<std::string, ProcessedJobData> processed_job_data_map;
    while (true) {
        std::queue<ParsedRequest> request_copy = parsed_request->take_all();
        while (!request_copy.empty()) {
            ParsedRequest request_copy_element = request_copy.front();
            std::string job_id = request_copy_element.job_id;
            std::string cluster_name = request_copy_element.cluster_name;
            std::string prov_data_key = job_id + cluster_name;
            if (request_copy_element.type == CallType::Start) {
                std::string path = request_copy_element.path;
                StartOrEnd start = std::get<StartOrEnd>(
                    request_copy_element.request_payload);
                ProcessedJobData new_processed_prov_data
                    = {.job_id = job_id,
                       .cluster_name = cluster_name,
                       .path = path,
                       .start_time = start.ts};
                processed_job_data_map[prov_data_key] = new_processed_prov_data;
            } else if (request_copy_element.type == CallType::End) {
                StartOrEnd end = std::get<StartOrEnd>(
                    request_copy_element.request_payload);
                processed_job_data_map[prov_data_key].end_time = end.ts;
                print_full_job_data(processed_job_data_map[prov_data_key]);
            } else if (request_copy_element.type == CallType::Exec) {
                Exec exec
                    = std::get<Exec>(request_copy_element.request_payload);
                process_exec(exec, processed_job_data_map[prov_data_key]);
            }
            request_copy.pop();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}
