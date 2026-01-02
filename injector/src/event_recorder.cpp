#include "event_recorder.hpp"

#include <xxhash.h>

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "model.hpp"

void EventRecorder::add_device_process_id_to_process_hash(
    const uint64_t& pid, const std::string& slurmd_nodename,
    const std::string& process_name, const std::string& env_variables) {
    std::string device_process_id = std::to_string(pid) + slurmd_nodename;
    std::string hash_source_string = process_name + env_variables;
    uint64_t process_hash
        = XXH64(hash_source_string.data(), hash_source_string.size(), 0);
    device_process_id_to_process_hash_[device_process_id] = process_hash;
}

uint64_t EventRecorder::get_env_variables_hash(
    const std::string& event_variables) {
    return XXH64(event_variables.data(), event_variables.size(), 0);
}

void EventRecorder::set_current_process_hash(
    const uint64_t& pid, const std::string& slurmd_nodename) {
    current_process_hash_
        = device_process_id_to_process_hash_[std::to_string(pid)
                                             + slurmd_nodename];
}

void EventRecorder::log_read(const std::string& path) {
    const std::string resolved = resolve_path(path);
    goedl_operations_.goedl_operation_map[resolved].read = true;
    auto& table
        = all_process_events_map_[current_process_hash_].operation_map[path];
    if (!table.read) {
        table.read = true;
        process_map_[current_process_hash_].operation_map[resolved].read = true;
    }
}
void EventRecorder::log_write(const std::string& path) {
    const std::string resolved = resolve_path(path);
    goedl_operations_.goedl_operation_map[resolved].write = true;
    auto& table
        = all_process_events_map_[current_process_hash_].operation_map[path];
    if (!table.write) {
        table.write = true;
        process_map_[current_process_hash_].operation_map[resolved].write
            = true;
    }
}
void EventRecorder::log_exec(const std::string& path, const uint64_t& child_pid,
                             const std::string& slurmd_nodename) {
    const std::string resolved = resolve_path(path);
    goedl_operations_.goedl_operation_map[resolved].execute = true;
    if (child_pid != 0) {
        uint64_t child_process_hash
            = device_process_id_to_process_hash_[std::to_string(child_pid)
                                                 + slurmd_nodename];
        execute_set_map_[current_process_hash_].insert(child_process_hash);
    }
}
void EventRecorder::log_process_start(const std::string& process_name,
                                      const std::string& env_variables) {
    uint64_t env_variables_hash = get_env_variables_hash(env_variables);
    env_variables_hash_map_.try_emplace(env_variables_hash, env_variables);
    process_map_[current_process_hash_].process_name = process_name;
    process_map_[current_process_hash_].env_variable_hash = env_variables_hash;
}
void EventRecorder::rename(const std::string& original_path,
                           const std::string& new_path) {
    auto it = rename_map_.find(original_path);
    if (it == rename_map_.end()) {
        rename_map_[new_path] = original_path;
    } else {
        rename_map_[new_path] = it->second;
        rename_map_.erase(it);
    }
    // std::string payload = R"("original_path":")" + original_path
    //                       + R"(","new_path":")" + new_path + R"("})";
    // add_current_process("RENAME", payload);
}
void EventRecorder::link(const std::string& original_path,
                         const std::string& new_path) {
    goedl_link_map_[new_path] = original_path;
    // std::string payload = R"("original_path":")" + original_path
    //                       + R"(","new_path":")" + new_path + R"("})";
    //  add_current_process("LINK", payload);
}
void EventRecorder::symlink(const std::string& original_path,
                            const std::string& new_path) {
    goedl_link_map_[new_path] = original_path;
    // std::string payload = R"("original_path":")" + original_path
    //                       + R"(","new_path":")" + new_path + R"("})";
    //  add_current_process("SYMLINK", payload);
}
void EventRecorder::delete_path(const std::string& path) {
    goedl_link_map_.erase(path);
    const std::string resolved = resolve_path(path);
    process_map_[current_process_hash_].operation_map[resolved].deleted = true;
}

std::string EventRecorder::resolve_path(const std::string& path) const {
    auto it = rename_map_.find(path);
    if (it != rename_map_.end()) return it->second;
    return path;
}

/*void EventRecorder::add_current_process(const std::string& current_operation,
                                        const std::string& event_data_payload) {
    std::string obj = R"({"operation_type":")" + current_operation
                      + R"(","operation_payload":)" + R"({)"
                      + event_data_payload + R"(})";
    process_map_[current_process_hash_]
        .process_json_operation_objects_.push_back(std::move(obj));
}

std::vector<std::string> EventRecorder::convert_env_var_hash_map() {
    std::vector<std::string> env_variables_hash_to_variables;
    for (auto& [hash, env_variables_string] : env_variables_hash_map_) {
        std::string env_variables_hash_to_variables_string
            = R"({"env_variables_hash":)" + std::to_string(hash)
              + R"(,"env_variables_array":)" + env_variables_string + R"(})";
        env_variables_hash_to_variables.push_back(
            env_variables_hash_to_variables_string);
    }
    return env_variables_hash_to_variables;
}*/

ProcessedInjectorData EventRecorder::consume_prov_data() {
    return ProcessedInjectorData{
        .goedl_operations = goedl_operations_,
        .processed_exec_data
        = ProcessedExecData{.process_map = process_map_,
                            .rename_map = rename_map_,
                            .execute_set_map = execute_set_map_,
                            .env_variables_hash_to_variables
                            = env_variables_hash_map_}
        //.process_map = process_map_, .execute_set_map = execute_set_map_,
        //.env_variables_hash_to_variables = convert_env_var_hash_map()
    };
}
