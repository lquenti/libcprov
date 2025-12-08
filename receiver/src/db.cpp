#include <sqlite3.h>

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
          "  job_name TEXT NOT NULL,"
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

void DB::init_job(const int64_t& job_hash_id) {
    JobDBContext job_db_context;
    sqlite3_open(db_file_.c_str(), &job_db_context.db);
    sqlite3_exec(job_db_context.db, "PRAGMA foreign_keys = ON;", nullptr,
                 nullptr, nullptr);
    sqlite3_exec(job_db_context.db, "BEGIN TRANSACTION;", nullptr, nullptr,
                 nullptr);
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
void DB::finish_job(const int64_t& job_hash_id) {
    auto& job_db_context = active_jobs_[job_hash_id];
    sqlite3_exec(job_db_context.db, "COMMIT;", nullptr, nullptr, nullptr);
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

void DB::commit_job(const int64_t& job_hash_id) {
    auto& job_db_context = active_jobs_[job_hash_id];
    sqlite3_exec(job_db_context.db, "COMMIT;", nullptr, nullptr, nullptr);
    sqlite3_exec(job_db_context.db, "BEGIN TRANSACTION;", nullptr, nullptr,
                 nullptr);
}

void DB::add_process_start(const int64_t job_hash_id,
                           const int64_t exec_hash_id, const int order_number,
                           const int pid) {
    auto& job_db_context = active_jobs_[job_hash_id];
    sqlite3_bind_int64(job_db_context.insert_process_start, 1, exec_hash_id);
    sqlite3_bind_int(job_db_context.insert_process_start, 2, order_number);
    sqlite3_bind_int(job_db_context.insert_process_start, 3, pid);
    sqlite3_step(job_db_context.insert_process_start);
    sqlite3_reset(job_db_context.insert_process_start);
}
void DB::add_read_operation(const int64_t job_hash_id,
                            const int64_t exec_hash_id, const int order_number,
                            const int pid, const std::string& path) {
    auto& job_db_context = active_jobs_[job_hash_id];
    sqlite3_bind_int64(job_db_context.insert_read_operations, 1, exec_hash_id);
    sqlite3_bind_int(job_db_context.insert_read_operations, 2, order_number);
    sqlite3_bind_int(job_db_context.insert_read_operations, 3, pid);
    sqlite3_bind_text(job_db_context.insert_read_operations, 4, path.c_str(),
                      -1, SQLITE_TRANSIENT);
    sqlite3_step(job_db_context.insert_read_operations);
    sqlite3_reset(job_db_context.insert_read_operations);
}
void DB::add_write_operation(const int64_t job_hash_id,
                             const int64_t exec_hash_id, const int order_number,
                             const int pid, const std::string& path) {
    auto& job_db_context = active_jobs_[job_hash_id];
    sqlite3_bind_int64(job_db_context.insert_write_operations, 1, exec_hash_id);
    sqlite3_bind_int(job_db_context.insert_write_operations, 2, order_number);
    sqlite3_bind_int(job_db_context.insert_write_operations, 3, pid);
    sqlite3_bind_text(job_db_context.insert_write_operations, 4, path.c_str(),
                      -1, SQLITE_TRANSIENT);
    sqlite3_step(job_db_context.insert_write_operations);
    sqlite3_reset(job_db_context.insert_write_operations);
}
void DB::add_execute_operation(const int64_t job_hash_id,
                               const int64_t exec_hash_id,
                               const int order_number, const int pid,
                               const int child_pid, const std::string& path) {
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
void DB::add_rename_operation(const int64_t job_hash_id,
                              const int64_t exec_hash_id,
                              const int order_number, const int pid,
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
void DB::add_link_operation(const int64_t job_hash_id,
                            const int64_t exec_hash_id, const int order_number,
                            const int pid, const std::string& source_path,
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
void DB::add_symlink_operation(const int64_t job_hash_id,
                               const int64_t exec_hash_id,
                               const int order_number, const int pid,
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
void DB::add_delete_operation(const int64_t job_hash_id,
                              const int64_t exec_hash_id,
                              const int order_number, const int pid,
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
