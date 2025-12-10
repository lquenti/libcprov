#pragma once
#include <sqlite3.h>

#include <cstdint>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

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

    struct ProcessStart {
        int order_number;
        uint64_t pid;
    };
    struct ReadOperation {
        int order_number;
        uint64_t pid;
        std::string path;
    };
    struct WriteOperation {
        int order_number;
        uint64_t pid;
        std::string path;
    };
    struct ExecuteOperation {
        int order_number;
        uint64_t pid;
        uint64_t child_pid;
        std::string path;
    };
    struct RenameOperation {
        int order_number;
        uint64_t pid;
        std::string original_path;
        std::string new_path;
    };
    struct LinkOperation {
        int order_number;
        uint64_t pid;
        std::string source_path;
        std::string link_path;
    };
    struct SymlinkOperation {
        int order_number;
        uint64_t pid;
        std::string source_path;
        std::string symlink_path;
    };
    struct DeleteOperation {
        int order_number;
        uint64_t pid;
        std::string path;
    };

    using OperationVariant
        = std::variant<ProcessStart, ReadOperation, WriteOperation,
                       ExecuteOperation, RenameOperation, LinkOperation,
                       SymlinkOperation, DeleteOperation>;

    struct ExecData {
        uint64_t hash_id;
        uint64_t start_time;
        std::string path;
        std::string json;
        std::string command;
        std::vector<OperationVariant> operations;
    };

    struct JobData {
        uint64_t hash_id;
        uint64_t start_time;
        uint64_t end_time;
        std::vector<ExecData> execs;
    };

    JobData get_job_data(const uint64_t& job_hash_id);

   private:
    std::string db_file_;
    struct JobDBContext {
        sqlite3* db = nullptr;
        sqlite3_stmt* insert_job = nullptr;
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
