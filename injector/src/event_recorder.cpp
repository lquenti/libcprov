#include "event_recorder.hpp"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "model.hpp"

void EventRecorder::set_current_pid(const uint64_t& pid) {
    current_pid_ = pid;
}

void EventRecorder::log_read(const std::string& path) {
    const std::string resolved = resolve_path(path);
    goedl_operations_.goedl_operation_map[resolved].read = true;
    auto& table = all_process_events_map_[current_pid_].operation_map[path];
    if (!table.read) {
        table.read = true;
        std::string payload = R"("path_in":")" + path + R"("})";
        add_current_process("WRITE", payload);
    }
}
void EventRecorder::log_write(const std::string& path) {
    const std::string resolved = resolve_path(path);
    goedl_operations_.goedl_operation_map[resolved].write = true;
    auto& table = all_process_events_map_[current_pid_].operation_map[path];
    if (!table.write) {
        table.write = true;
        std::string payload = R"("path_out":")" + path + R"("})";
        add_current_process("READ", payload);
    }
}
void EventRecorder::log_exec(const std::string& path, const uint64_t& pid) {
    const std::string resolved = resolve_path(path);
    goedl_operations_.goedl_operation_map[resolved].execute = true;
    auto& table = all_process_events_map_[current_pid_].operation_map[path];
    if (!table.execute) {
        table.execute = true;
        std::string payload = R"("path_exec":")" + path + R"(","child_pid":)"
                              + std::to_string(pid) + R"(})";
        add_current_process("EXEC", payload);
    }
}
void EventRecorder::log_process_start() {
    std::string payload = R"(})";
    add_current_process("PROCESS_START", payload);
}
void EventRecorder::rename(const std::string& original_path,
                           const std::string& new_path) {
    auto it = goedl_rename_map_.find(original_path);
    if (it == goedl_rename_map_.end()) {
        goedl_rename_map_[new_path] = original_path;
    } else {
        goedl_rename_map_[new_path] = it->second;
        goedl_rename_map_.erase(it);
    }
    remove_path_from_operations(original_path);
    std::string payload = R"("original_path":")" + original_path
                          + R"(","new_path":")" + new_path + R"("})";
    add_current_process("RENAME", payload);
}
void EventRecorder::link(const std::string& original_path,
                         const std::string& new_path) {
    goedl_link_map_[new_path] = original_path;
    std::string payload = R"("original_path":")" + original_path
                          + R"(","new_path":")" + new_path + R"("})";
}
void EventRecorder::delete_path(const std::string& path) {
    goedl_link_map_.erase(path);
    remove_path_from_operations(path);
    std::string payload = R"("deleted_path":")" + path + R"("})";
    add_current_process("DELETE", payload);
}

ProcessedInjectorData EventRecorder::consume_prov_data() {
    ProcessedInjectorData new_processed_injector_data;
    new_processed_injector_data.goedl_operations = goedl_operations_;
    new_processed_injector_data.process_json_operation_objects
        = process_json_operation_objects_;
    return new_processed_injector_data;
}

std::string EventRecorder::resolve_path(const std::string& path) const {
    auto it = goedl_rename_map_.find(path);
    if (it != goedl_rename_map_.end()) return it->second;
    return path;
}

void EventRecorder::add_current_process(const std::string& current_operation,
                                        const std::string& event_data_payload) {
    std::string obj = R"({"operation":")" + current_operation + R"(","pid":)"
                      + std::to_string(current_pid_) + R"(,"order_number":)"
                      + std::to_string(current_order_number_)
                      + R"(,"event_data":)" + R"({)" + event_data_payload
                      + R"(}})";
    current_order_number_++;
    process_json_operation_objects_.push_back(std::move(obj));
}

void EventRecorder::remove_path_from_operations(const std::string& path) {
    auto it = all_process_events_map_.find(current_pid_);
    if (it == all_process_events_map_.end()) return;
    auto& opmap = it->second.operation_map;
    auto jt = opmap.find(path);
    if (jt == opmap.end()) return;
    jt->second.read = false;
    jt->second.write = false;
    jt->second.execute = false;
}
