#pragma once
#include <sqlite3.h>

#include <cstdint>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

#include "model.hpp"

class DB {
   public:
    DB();
    void build_tables();
    void add_process_start(const uint64_t job_hash_id,
                           const uint64_t exec_hash_id, const int order_number,
                           const uint64_t pid);
    void init_job(const uint64_t& job_hash_id);
    void finish_job(const uint64_t& job_hash_id);
    void commit_job(const uint64_t& job_hash_id);
    void add_job(const uint64_t job_hash_id, const uint64_t slurm_id,
                 const std::string& cluster_name, const uint64_t start_time,
                 const std::string& path, const std::string& json);
    void set_job_end_time(uint64_t job_hash_id, uint64_t end_time);
    void add_exec(const uint64_t job_hash_id, const uint64_t exec_hash_id,
                  const uint64_t start_time, const std::string& path,
                  const std::string& json, const std::string& command);
    void add_read_operation(const uint64_t job_hash_id,
                            const uint64_t exec_hash_id, const int order_number,
                            const uint64_t pid, const std::string& path);
    void add_write_operation(const uint64_t job_hash_id,
                             const uint64_t exec_hash_id,
                             const int order_number, const uint64_t pid,
                             const std::string& path);
    void add_execute_operation(const uint64_t job_hash_id,
                               const uint64_t exec_hash_id,
                               const int order_number, const uint64_t pid,
                               const uint64_t child_pid,
                               const std::string& path);
    void add_rename_operation(const uint64_t job_hash_id,
                              const uint64_t exec_hash_id,
                              const int order_number, const uint64_t pid,
                              const std::string& original_path,
                              const std::string& new_path);
    void add_link_operation(const uint64_t job_hash_id,
                            const uint64_t exec_hash_id, const int order_number,
                            const uint64_t pid, const std::string& source_path,
                            const std::string& link_path);
    void add_symlink_operation(const uint64_t job_hash_id,
                               const uint64_t exec_hash_id,
                               const int order_number, const uint64_t pid,
                               const std::string& source_path,
                               const std::string& symlink_path);
    void add_delete_operation(const uint64_t job_hash_id,
                              const uint64_t exec_hash_id,
                              const int order_number, const uint64_t pid,
                              const std::string& path);
    struct ExecDataDB {
        uint64_t exec_hash_id;
        std::vector<Event> events;
        uint64_t start_time;
        std::string path;
        std::string json;
        std::string command;
    };

    struct JobData {
        uint64_t hash_id;
        uint64_t start_time;
        uint64_t end_time;
        std::vector<ExecDataDB> execs;
    };

    JobData get_job_data(const uint64_t& job_hash_id);

   private:
    std::string db_file_;
    struct JobDBContext {
        sqlite3* db = nullptr;
        sqlite3_stmt* insert_job = nullptr;
        sqlite3_stmt* update_end_time_job = nullptr;
        sqlite3_stmt* insert_exec = nullptr;
        sqlite3_stmt* insert_process_start = nullptr;
        sqlite3_stmt* insert_read_operations = nullptr;
        sqlite3_stmt* insert_write_operations = nullptr;
        sqlite3_stmt* insert_execute_operations = nullptr;
        sqlite3_stmt* insert_rename_operations = nullptr;
        sqlite3_stmt* insert_link_operations = nullptr;
        sqlite3_stmt* insert_symlink_operations = nullptr;
        sqlite3_stmt* insert_delete_operations = nullptr;
    };
    std::unordered_map<uint64_t, JobDBContext> active_jobs_;
};
