#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "model.hpp"

struct DBProcessEvents {
    std::unordered_map<std::string, OperationTable> operation_map;
};

class EventRecorder {
   public:
    void set_current_pid(const uint64_t& pid);

    void log_read(const std::string& path);
    void log_write(const std::string& path);
    void log_exec(const std::string& path, const uint64_t& ppid);
    void log_process_start();
    void rename(const std::string& original_path, const std::string& new_path);
    void link(const std::string& original_path, const std::string& new_path);
    void delete_path(const std::string& path);

    ProcessedInjectorData consume_prov_data();

   private:
    std::unordered_map<std::string, std::string> goedl_rename_map_;
    std::unordered_map<std::string, std::string> goedl_link_map_;
    GoedlOperations goedl_operations_;
    std::unordered_map<uint64_t, DBProcessEvents> all_process_events_map_;
    std::vector<std::string> process_json_operation_objects_;
    uint64_t current_pid_ = 0;
    DBProcessEvents current_process_events_;
    int current_order_number_ = 0;

    std::string resolve_path(const std::string& path) const;
    void add_current_process(const std::string& current_operation,
                             const std::string& event_data_payload);
    void remove_path_from_operations(const std::string& path);
};
