#include <sqlite3.h>

#include <algorithm>
#include <cstdint>
#include <db.hpp>
#include <string>

DB::DB() {
    db_file_ = "/dev/shm/libcprov.db";
}

void DB::build_tables() {
    sqlite3* db = nullptr;
    int db_connection = sqlite3_open("example.db", &db);
    sqlite3_exec(db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    char* err = nullptr;
    const char* db_tables
        = "CREATE TABLE IF NOT EXISTS jobs ("
          "  hash_id INTEGER PRIMARY KEY,"
          "  slurm_id INTEGER NOT NULL,"
          "  cluster_name TEXT NOT NULL,"
          "  start_time INTEGER NOT NULL,"
          "  end_time INTEGER NOT NULL,"
          "  path TEXT NOT NULL,"
          "  json TEXT NOT NULL"
          ");"
          "CREATE TABLE IF NOT EXISTS execs ("
          "  hash_id INTEGER PRIMARY KEY,"
          "  job_hash_id INTEGER NOT NULL,"
          "  start_time INTEGER NOT NULL,"
          "  path TEXT NOT NULL,"
          "  json TEXT NOT NULL,"
          "  command TEXT NOT NULL,"
          "  FOREIGN KEY (job_hash_id)"
          "    REFERENCES jobs(hash_id)"
          "    ON DELETE CASCADE"
          "    ON UPDATE CASCADE"
          ");"
          "CREATE TABLE IF NOT EXISTS process_starts("
          "  exec_hash_id INTEGER NOT NULL,"
          "  order_number INTEGER NOT NULL,"
          "  pid INTEGER NOT NULL,"
          "  PRIMARY KEY (exec_hash_id, order_number),"
          "  FOREIGN KEY (exec_hash_id)"
          "    REFERENCES execs (hash_id)"
          "    ON DELETE CASCADE"
          "    ON UPDATE CASCADE"
          ");"
          "CREATE TABLE IF NOT EXISTS read_operations("
          "  exec_hash_id INTEGER NOT NULL,"
          "  order_number INTEGER NOT NULL,"
          "  pid INTEGER NOT NULL,"
          "  path TEXT NOT NULL,"
          "  PRIMARY KEY (exec_hash_id, order_number),"
          "  FOREIGN KEY (exec_hash_id)"
          "    REFERENCES execs (hash_id)"
          "    ON DELETE CASCADE"
          "    ON UPDATE CASCADE"
          ");"
          "CREATE TABLE IF NOT EXISTS write_operations("
          "  exec_hash_id INTEGER NOT NULL,"
          "  order_number INTEGER NOT NULL,"
          "  pid INTEGER NOT NULL,"
          "  path TEXT NOT NULL,"
          "  PRIMARY KEY (exec_hash_id, order_number),"
          "  FOREIGN KEY (exec_hash_id)"
          "    REFERENCES execs (hash_id)"
          "    ON DELETE CASCADE"
          "    ON UPDATE CASCADE"
          ");"
          "CREATE TABLE IF NOT EXISTS execute_operations("
          "  exec_hash_id INTEGER NOT NULL,"
          "  order_number INTEGER NOT NULL,"
          "  pid INTEGER NOT NULL,"
          "  child_pid INTEGER,"
          "  path TEXT,"
          "  PRIMARY KEY (exec_hash_id, order_number),"
          "  FOREIGN KEY (exec_hash_id)"
          "    REFERENCES execs (hash_id)"
          "    ON DELETE CASCADE"
          "    ON UPDATE CASCADE"
          ");"
          "CREATE TABLE IF NOT EXISTS rename_operations("
          "  exec_hash_id INTEGER NOT NULL,"
          "  order_number INTEGER NOT NULL,"
          "  pid INTEGER NOT NULL,"
          "  original_path TEXT,"
          "  new_path TEXT,"
          "  PRIMARY KEY (exec_hash_id, order_number),"
          "  FOREIGN KEY (exec_hash_id)"
          "    REFERENCES execs (hash_id)"
          "    ON DELETE CASCADE"
          "    ON UPDATE CASCADE"
          ");"
          "CREATE TABLE IF NOT EXISTS link_operations("
          "  exec_hash_id INTEGER NOT NULL,"
          "  order_number INTEGER NOT NULL,"
          "  pid INTEGER NOT NULL,"
          "  source_path TEXT NOT NULL,"
          "  link_path TEXT NOT NULL,"
          "  PRIMARY KEY (exec_hash_id, order_number),"
          "  FOREIGN KEY (exec_hash_id)"
          "    REFERENCES execs (hash_id)"
          "    ON DELETE CASCADE"
          "    ON UPDATE CASCADE"
          ");"
          "CREATE TABLE IF NOT EXISTS symlink_operations("
          "  exec_hash_id INTEGER NOT NULL,"
          "  order_number INTEGER NOT NULL,"
          "  pid INTEGER NOT NULL,"
          "  source_path TEXT NOT NULL,"
          "  symlink_path TEXT NOT NULL,"
          "  PRIMARY KEY (exec_hash_id, order_number),"
          "  FOREIGN KEY (exec_hash_id)"
          "    REFERENCES execs (hash_id)"
          "    ON DELETE CASCADE"
          "    ON UPDATE CASCADE"
          ");"
          "CREATE TABLE IF NOT EXISTS delete_operations("
          "  exec_hash_id INTEGER NOT NULL,"
          "  order_number INTEGER NOT NULL,"
          "  pid INTEGER NOT NULL,"
          "  path TEXT NOT NULL,"
          "  PRIMARY KEY (exec_hash_id, order_number),"
          "  FOREIGN KEY (exec_hash_id)"
          "    REFERENCES execs (hash_id)"
          "    ON DELETE CASCADE"
          "    ON UPDATE CASCADE"
          ");";
    db_connection = sqlite3_exec(db, db_tables, nullptr, nullptr, &err);
    sqlite3_close(db);
}

void DB::init_job(const uint64_t& job_hash_id) {
    JobDBContext job_db_context;
    sqlite3_open(db_file_.c_str(), &job_db_context.db);
    sqlite3_exec(job_db_context.db, "PRAGMA foreign_keys = ON;", nullptr,
                 nullptr, nullptr);
    sqlite3_exec(job_db_context.db, "BEGIN TRANSACTION;", nullptr, nullptr,
                 nullptr);
    sqlite3_prepare_v2(job_db_context.db,
                       "INSERT INTO jobs(hash_id, slurm_id, cluster_name, "
                       "start_time, end_time, path, json) "
                       "VALUES (?, ?, ?, ?, ?, ?, ?);",
                       -1, &job_db_context.insert_job, nullptr);
    sqlite3_prepare_v2(job_db_context.db,
                       "INSERT INTO execs(hash_id, job_hash_id, start_time, "
                       "path, json, command) "
                       "VALUES (?, ?, ?, ?, ?, ?);",
                       -1, &job_db_context.insert_exec, nullptr);
    sqlite3_prepare_v2(job_db_context.db,
                       "INSERT INTO process_starts(exec_hash_id, order_number, "
                       "pid) VALUES (?, ?, ?);",
                       -1, &job_db_context.insert_process_start, nullptr);
    sqlite3_prepare_v2(job_db_context.db,
                       "INSERT INTO read_operations(exec_hash_id, "
                       "order_number, pid, path) VALUES (?, ?, ?, ?);",
                       -1, &job_db_context.insert_read_operations, nullptr);
    sqlite3_prepare_v2(job_db_context.db,
                       "INSERT INTO write_operations(exec_hash_id, "
                       "order_number, pid, path) VALUES (?, ?, ?, ?);",
                       -1, &job_db_context.insert_write_operations, nullptr);
    sqlite3_prepare_v2(
        job_db_context.db,
        "INSERT INTO execute_operations(exec_hash_id, "
        "order_number, pid, child_pid, path) VALUES (?, ?, ?, ?, ?);",
        -1, &job_db_context.insert_execute_operations, nullptr);
    sqlite3_prepare_v2(
        job_db_context.db,
        "INSERT INTO rename_operations(exec_hash_id, "
        "order_number, pid, original_path, new_path) VALUES (?, ?, ?, ?, ?);",
        -1, &job_db_context.insert_rename_operations, nullptr);
    sqlite3_prepare_v2(
        job_db_context.db,
        "INSERT INTO link_operations(exec_hash_id, "
        "order_number, pid, source_path, link_path) VALUES (?, ?, ?, ?, ?);",
        -1, &job_db_context.insert_link_operations, nullptr);
    sqlite3_prepare_v2(
        job_db_context.db,
        "INSERT INTO symlink_operations(exec_hash_id, "
        "order_number, pid, source_path, symlink_path) VALUES (?, ?, ?, ?, ?);",
        -1, &job_db_context.insert_symlink_operations, nullptr);
    sqlite3_prepare_v2(job_db_context.db,
                       "INSERT INTO delete_operations(exec_hash_id, "
                       "order_number, pid, path) VALUES (?, ?, ?, ?);",
                       -1, &job_db_context.insert_delete_operations, nullptr);
    active_jobs_[job_hash_id] = job_db_context;
}
void DB::finish_job(const uint64_t& job_hash_id) {
    auto& job_db_context = active_jobs_[job_hash_id];
    sqlite3_exec(job_db_context.db, "COMMIT;", nullptr, nullptr, nullptr);
    sqlite3_finalize(job_db_context.insert_job);
    sqlite3_finalize(job_db_context.insert_exec);
    sqlite3_finalize(job_db_context.insert_process_start);
    sqlite3_finalize(job_db_context.insert_read_operations);
    sqlite3_finalize(job_db_context.insert_write_operations);
    sqlite3_finalize(job_db_context.insert_execute_operations);
    sqlite3_finalize(job_db_context.insert_rename_operations);
    sqlite3_finalize(job_db_context.insert_link_operations);
    sqlite3_finalize(job_db_context.insert_symlink_operations);
    sqlite3_finalize(job_db_context.insert_delete_operations);
    sqlite3_close(job_db_context.db);
    active_jobs_.erase(job_hash_id);
}

void DB::commit_job(const uint64_t& job_hash_id) {
    auto& job_db_context = active_jobs_[job_hash_id];
    sqlite3_exec(job_db_context.db, "COMMIT;", nullptr, nullptr, nullptr);
    sqlite3_exec(job_db_context.db, "BEGIN TRANSACTION;", nullptr, nullptr,
                 nullptr);
}

void DB::add_job(const uint64_t job_hash_id, const uint64_t slurm_id,
                 const std::string& cluster_name, const uint64_t start_time,
                 const std::string& path, const std::string& json) {
    auto& job_db_context = active_jobs_[job_hash_id];
    sqlite3_bind_int64(job_db_context.insert_job, 1, job_hash_id);
    sqlite3_bind_int64(job_db_context.insert_job, 2, slurm_id);
    sqlite3_bind_text(job_db_context.insert_job, 3, cluster_name.c_str(), -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(job_db_context.insert_job, 4, start_time);
    sqlite3_bind_text(job_db_context.insert_job, 6, path.c_str(), -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(job_db_context.insert_job, 7, json.c_str(), -1,
                      SQLITE_TRANSIENT);
    sqlite3_step(job_db_context.insert_job);
    sqlite3_reset(job_db_context.insert_job);
}
void DB::add_exec(const uint64_t job_hash_id, const uint64_t exec_hash_id,
                  const uint64_t start_time, const std::string& path,
                  const std::string& json, const std::string& command) {
    auto& job_db_context = active_jobs_[job_hash_id];
    sqlite3_bind_int64(job_db_context.insert_exec, 1, exec_hash_id);
    sqlite3_bind_int64(job_db_context.insert_exec, 2, job_hash_id);
    sqlite3_bind_int64(job_db_context.insert_exec, 3, start_time);
    sqlite3_bind_text(job_db_context.insert_exec, 4, path.c_str(), -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(job_db_context.insert_exec, 5, json.c_str(), -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(job_db_context.insert_exec, 6, command.c_str(), -1,
                      SQLITE_TRANSIENT);
    sqlite3_step(job_db_context.insert_exec);
    sqlite3_reset(job_db_context.insert_exec);
}
void DB::add_process_start(const uint64_t job_hash_id,
                           const uint64_t exec_hash_id, const int order_number,
                           const uint64_t pid) {
    auto& job_db_context = active_jobs_[job_hash_id];
    sqlite3_bind_int64(job_db_context.insert_process_start, 1, exec_hash_id);
    sqlite3_bind_int(job_db_context.insert_process_start, 2, order_number);
    sqlite3_bind_int(job_db_context.insert_process_start, 3, pid);
    sqlite3_step(job_db_context.insert_process_start);
    sqlite3_reset(job_db_context.insert_process_start);
}
void DB::add_read_operation(const uint64_t job_hash_id,
                            const uint64_t exec_hash_id, const int order_number,
                            const uint64_t pid, const std::string& path) {
    auto& job_db_context = active_jobs_[job_hash_id];
    sqlite3_bind_int64(job_db_context.insert_read_operations, 1, exec_hash_id);
    sqlite3_bind_int(job_db_context.insert_read_operations, 2, order_number);
    sqlite3_bind_int(job_db_context.insert_read_operations, 3, pid);
    sqlite3_bind_text(job_db_context.insert_read_operations, 4, path.c_str(),
                      -1, SQLITE_TRANSIENT);
    sqlite3_step(job_db_context.insert_read_operations);
    sqlite3_reset(job_db_context.insert_read_operations);
}
void DB::add_write_operation(const uint64_t job_hash_id,
                             const uint64_t exec_hash_id,
                             const int order_number, const uint64_t pid,
                             const std::string& path) {
    auto& job_db_context = active_jobs_[job_hash_id];
    sqlite3_bind_int64(job_db_context.insert_write_operations, 1, exec_hash_id);
    sqlite3_bind_int(job_db_context.insert_write_operations, 2, order_number);
    sqlite3_bind_int(job_db_context.insert_write_operations, 3, pid);
    sqlite3_bind_text(job_db_context.insert_write_operations, 4, path.c_str(),
                      -1, SQLITE_TRANSIENT);
    sqlite3_step(job_db_context.insert_write_operations);
    sqlite3_reset(job_db_context.insert_write_operations);
}
void DB::add_execute_operation(const uint64_t job_hash_id,
                               const uint64_t exec_hash_id,
                               const int order_number, const uint64_t pid,
                               const uint64_t child_pid,
                               const std::string& path) {
    auto& job_db_context = active_jobs_[job_hash_id];
    sqlite3_bind_int64(job_db_context.insert_execute_operations, 1,
                       exec_hash_id);
    sqlite3_bind_int(job_db_context.insert_execute_operations, 2, order_number);
    sqlite3_bind_int(job_db_context.insert_execute_operations, 3, pid);
    sqlite3_bind_int(job_db_context.insert_execute_operations, 4, child_pid);
    sqlite3_bind_text(job_db_context.insert_execute_operations, 5, path.c_str(),
                      -1, SQLITE_TRANSIENT);
    sqlite3_step(job_db_context.insert_execute_operations);
    sqlite3_reset(job_db_context.insert_execute_operations);
}
void DB::add_rename_operation(const uint64_t job_hash_id,
                              const uint64_t exec_hash_id,
                              const int order_number, const uint64_t pid,
                              const std::string& original_path,
                              const std::string& new_path) {
    auto& job_db_context = active_jobs_[job_hash_id];
    sqlite3_bind_int64(job_db_context.insert_rename_operations, 1,
                       exec_hash_id);
    sqlite3_bind_int(job_db_context.insert_rename_operations, 2, order_number);
    sqlite3_bind_int(job_db_context.insert_rename_operations, 3, pid);
    sqlite3_bind_text(job_db_context.insert_rename_operations, 4,
                      original_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(job_db_context.insert_rename_operations, 5,
                      new_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(job_db_context.insert_rename_operations);
    sqlite3_reset(job_db_context.insert_rename_operations);
}
void DB::add_link_operation(const uint64_t job_hash_id,
                            const uint64_t exec_hash_id, const int order_number,
                            const uint64_t pid, const std::string& source_path,
                            const std::string& link_path) {
    auto& job_db_context = active_jobs_[job_hash_id];
    sqlite3_bind_int64(job_db_context.insert_link_operations, 1, exec_hash_id);
    sqlite3_bind_int(job_db_context.insert_link_operations, 2, order_number);
    sqlite3_bind_int(job_db_context.insert_link_operations, 3, pid);
    sqlite3_bind_text(job_db_context.insert_link_operations, 4,
                      source_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(job_db_context.insert_link_operations, 5,
                      link_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(job_db_context.insert_link_operations);
    sqlite3_reset(job_db_context.insert_link_operations);
}
void DB::add_symlink_operation(const uint64_t job_hash_id,
                               const uint64_t exec_hash_id,
                               const int order_number, const uint64_t pid,
                               const std::string& source_path,
                               const std::string& symlink_path) {
    auto& job_db_context = active_jobs_[job_hash_id];
    sqlite3_bind_int64(job_db_context.insert_symlink_operations, 1,
                       exec_hash_id);
    sqlite3_bind_int(job_db_context.insert_symlink_operations, 2, order_number);
    sqlite3_bind_int(job_db_context.insert_symlink_operations, 3, pid);
    sqlite3_bind_text(job_db_context.insert_symlink_operations, 4,
                      source_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(job_db_context.insert_symlink_operations, 5,
                      symlink_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(job_db_context.insert_symlink_operations);
    sqlite3_reset(job_db_context.insert_symlink_operations);
}
void DB::add_delete_operation(const uint64_t job_hash_id,
                              const uint64_t exec_hash_id,
                              const int order_number, const uint64_t pid,
                              const std::string& path) {
    auto& job_db_context = active_jobs_[job_hash_id];
    sqlite3_bind_int64(job_db_context.insert_delete_operations, 1,
                       exec_hash_id);
    sqlite3_bind_int(job_db_context.insert_delete_operations, 2, order_number);
    sqlite3_bind_int(job_db_context.insert_delete_operations, 3, pid);
    sqlite3_bind_text(job_db_context.insert_delete_operations, 4, path.c_str(),
                      -1, SQLITE_TRANSIENT);
    sqlite3_step(job_db_context.insert_delete_operations);
    sqlite3_reset(job_db_context.insert_delete_operations);
}

DB::JobData DB::get_job_data(const uint64_t& job_hash_id) {
    sqlite3* db;
    sqlite3_open(db_file_.c_str(), &db);
    sqlite3_exec(db, "PRAGMA foreign_keys=ON;", nullptr, nullptr, nullptr);
    DB::JobData job_data;
    job_data.hash_id = job_hash_id;
    sqlite3_stmt* stmt_job;
    sqlite3_prepare_v2(db,
                       "SELECT start_time,end_time FROM jobs WHERE hash_id=?",
                       -1, &stmt_job, nullptr);
    sqlite3_bind_int64(stmt_job, 1, job_hash_id);
    if (sqlite3_step(stmt_job) == SQLITE_ROW) {
        job_data.start_time
            = static_cast<uint64_t>(sqlite3_column_int64(stmt_job, 0));
        job_data.end_time
            = static_cast<uint64_t>(sqlite3_column_int64(stmt_job, 1));
    }
    sqlite3_finalize(stmt_job);
    sqlite3_stmt* stmt_exec;
    sqlite3_prepare_v2(db,
                       "SELECT hash_id,start_time,path,json,command FROM execs "
                       "WHERE job_hash_id=?",
                       -1, &stmt_exec, nullptr);
    sqlite3_bind_int64(stmt_exec, 1, job_hash_id);
    while (sqlite3_step(stmt_exec) == SQLITE_ROW) {
        DB::ExecData exec_data;
        exec_data.hash_id
            = static_cast<uint64_t>(sqlite3_column_int64(stmt_exec, 0));
        exec_data.start_time
            = static_cast<uint64_t>(sqlite3_column_int64(stmt_exec, 1));
        exec_data.path = (const char*)sqlite3_column_text(stmt_exec, 2);
        exec_data.json = (const char*)sqlite3_column_text(stmt_exec, 3);
        exec_data.command = (const char*)sqlite3_column_text(stmt_exec, 4);
        auto add_operations = [&](const char* table) {
            sqlite3_stmt* stmt;
            std::string q = std::string("SELECT * FROM ") + table
                            + " WHERE exec_hash_id=? ORDER BY order_number";
            sqlite3_prepare_v2(db, q.c_str(), -1, &stmt, nullptr);
            sqlite3_bind_int64(stmt, 1, exec_data.hash_id);
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                std::string table_string = std::string(table);
                int order_number = sqlite3_column_int64(stmt, 1);
                uint64_t pid
                    = static_cast<uint64_t>(sqlite3_column_int64(stmt, 2));
                if (table_string == "process_starts")
                    exec_data.operations.push_back(
                        DB::ProcessStart{order_number, pid});
                if (table_string == "read_operations")
                    exec_data.operations.push_back(DB::ReadOperation{
                        order_number, pid,
                        (const char*)sqlite3_column_text(stmt, 3)});
                if (table_string == "write_operations")
                    exec_data.operations.push_back(DB::WriteOperation{
                        order_number, pid,
                        (const char*)sqlite3_column_text(stmt, 3)});
                if (table_string == "execute_operations")
                    exec_data.operations.push_back(DB::ExecuteOperation{
                        order_number, pid,
                        static_cast<int>(sqlite3_column_int64(stmt, 3)),
                        (const char*)sqlite3_column_text(stmt, 4)});
                if (table_string == "rename_operations")
                    exec_data.operations.push_back(DB::RenameOperation{
                        order_number, pid,
                        (const char*)sqlite3_column_text(stmt, 3),
                        (const char*)sqlite3_column_text(stmt, 4)});
                if (table_string == "link_operations")
                    exec_data.operations.push_back(DB::LinkOperation{
                        order_number, pid,
                        (const char*)sqlite3_column_text(stmt, 3),
                        (const char*)sqlite3_column_text(stmt, 4)});
                if (table_string == "symlink_operations")
                    exec_data.operations.push_back(DB::SymlinkOperation{
                        order_number, pid,
                        (const char*)sqlite3_column_text(stmt, 3),
                        (const char*)sqlite3_column_text(stmt, 4)});
                if (table_string == "delete_operations")
                    exec_data.operations.push_back(DB::DeleteOperation{
                        order_number, pid,
                        (const char*)sqlite3_column_text(stmt, 3)});
            }
            sqlite3_finalize(stmt);
        };
        add_operations("process_starts");
        add_operations("read_operations");
        add_operations("write_operations");
        add_operations("execute_operations");
        add_operations("rename_operations");
        add_operations("link_operations");
        add_operations("symlink_operations");
        add_operations("delete_operations");
        job_data.execs.push_back(std::move(exec_data));
    }
    sqlite3_finalize(stmt_exec);
    sqlite3_close(db);
    return job_data;
}
