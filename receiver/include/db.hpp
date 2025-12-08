#pragma once
#include <sqlite3.h>

#include <cstdint>
#include <queue>
#include <string>
#include <unordered_map>
#include <variant>

class DB {
   public:
    DB();
    void build_tables();
    void add_process_start(const int64_t job_hash_id,
                           const int64_t exec_hash_id, const int order_number,
                           const int pid);
    void init_job(const int64_t& job_hash_id);
    void finish_job(const int64_t& job_hash_id);
    void commit_job(const int64_t& job_hash_id);
    void add_read_operation(const int64_t job_hash_id,
                            const int64_t exec_hash_id, const int order_number,
                            const int pid, const std::string& path);
    void add_write_operation(const int64_t job_hash_id,
                             const int64_t exec_hash_id, const int order_number,
                             const int pid, const std::string& path);
    void add_execute_operation(const int64_t job_hash_id,
                               const int64_t exec_hash_id,
                               const int order_number, const int pid,
                               const int child_pid, const std::string& path);
    void add_rename_operation(const int64_t job_hash_id,
                              const int64_t exec_hash_id,
                              const int order_number, const int pid,
                              const std::string& original_path,
                              const std::string& new_path);
    void add_link_operation(const int64_t job_hash_id,
                            const int64_t exec_hash_id, const int order_number,
                            const int pid, const std::string& source_path,
                            const std::string& link_path);
    void add_symlink_operation(const int64_t job_hash_id,
                               const int64_t exec_hash_id,
                               const int order_number, const int pid,
                               const std::string& source_path,
                               const std::string& symlink_path);
    void add_delete_operation(const int64_t job_hash_id,
                              const int64_t exec_hash_id,
                              const int order_number, const int pid,
                              const std::string& path);

    struct ProcessStart {
        int64_t order_number;
        int64_t pid;
    };
    struct ReadOperation {
        int64_t order_number;
        int64_t pid;
        std::string path;
    };
    struct WriteOperation {
        int64_t order_number;
        int64_t pid;
        std::string path;
    };
    struct ExecuteOperation {
        int64_t order_number;
        int64_t pid;
        int64_t child_pid;
        std::string path;
    };
    struct RenameOperation {
        int64_t order_number;
        int64_t pid;
        std::string original_path;
        std::string new_path;
    };
    struct LinkOperation {
        int64_t order_number;
        int64_t pid;
        std::string source_path;
        std::string link_path;
    };
    struct SymlinkOperation {
        int64_t order_number;
        int64_t pid;
        std::string source_path;
        std::string symlink_path;
    };
    struct DeleteOperation {
        int64_t order_number;
        int64_t pid;
        std::string path;
    };

    using OperationVariant
        = std::variant<ProcessStart, ReadOperation, WriteOperation,
                       ExecuteOperation, RenameOperation, LinkOperation,
                       SymlinkOperation, DeleteOperation>;

    struct ExecData {
        int64_t hash_id;
        int64_t start_time;
        std::string path;
        std::string json;
        std::string command;
        std::queue<OperationVariant> operations;
    };

    struct JobData {
        int64_t hash_id;
        int64_t start_time;
        int64_t end_time;
        std::unordered_map<int64_t, ExecData> execs;
    };

    JobData get_job_data(const int64_t& job_hash_id);

   private:
    std::string db_file_;
    struct JobDBContext {
        sqlite3* db = nullptr;
        sqlite3_stmt* insert_process_start = nullptr;
        sqlite3_stmt* insert_read_operations = nullptr;
        sqlite3_stmt* insert_write_operations = nullptr;
        sqlite3_stmt* insert_execute_operations = nullptr;
        sqlite3_stmt* insert_rename_operations = nullptr;
        sqlite3_stmt* insert_link_operations = nullptr;
        sqlite3_stmt* insert_symlink_operations = nullptr;
        sqlite3_stmt* insert_delete_operations = nullptr;
    };
    std::unordered_map<int64_t, JobDBContext> active_jobs_;
};
