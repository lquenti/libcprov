#pragma once
#include <cstdint>
#include <queue>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "model.hpp"

struct DBProcessEvents {
    std::unordered_map<std::string, OperationTable> operation_map;
};

class EventRecorder {
   public:
    void add_device_process_id_to_process_hash(
        const uint64_t& pid, const std::string& slurmd_nodename,
        const std::string& process_name, const std::string& env_variables);
    void set_current_process_hash(const uint64_t& pid,
                                  const std::string& slurmd_nodename);
    void log_read(const std::string& path);
    void log_write(const std::string& path);
    void log_exec(const std::string& path, const uint64_t& child_pid,
                  const std::string& slurmd_nodename);
    void log_process_start(const std::string& process_name,
                           const std::string& env_variables);
    void rename(const std::string& original_path, const std::string& new_path);
    void link(const std::string& original_path, const std::string& new_path);
    void symlink(const std::string& original_path, const std::string& new_path);
    void delete_path(const std::string& path);
    ProcessedInjectorData consume_prov_data();

   private:
    std::unordered_map<std::string, std::string> rename_map_;
    std::unordered_map<std::string, std::string> goedl_link_map_;
    GoedlOperations goedl_operations_;
    std::unordered_map<uint64_t, DBProcessEvents> all_process_events_map_;
    ExecuteSetMap execute_set_map_;
    ProcessMap process_map_;
    // Renames renames_;
    std::unordered_map<std::string, uint64_t>
        device_process_id_to_process_hash_;
    uint64_t current_process_hash_ = 0;
    std::unordered_map<uint64_t, std::string> env_variables_hash_map_;
    DBProcessEvents current_process_events_;
    int current_order_number_ = 0;

    uint64_t get_env_variables_hash(const std::string& event_variables);
    std::string resolve_path(const std::string& path) const;
    // void add_current_process(const std::string& current_operation,
    //                          const std::string& event_data_payload);
    // Renames convert_rename_map();
    // std::vector<std::string> convert_env_var_hash_map();
};
