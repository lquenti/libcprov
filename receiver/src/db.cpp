#include <sqlite3.h>

#include <algorithm>
#include <cstdint>
#include <db.hpp>
#include <string>

DB::DB() {
    db_file_ = "/dev/shm/libcprov/libcprov.db";
}

void DB::build_tables() {
    sqlite3* db = nullptr;
    int db_connection = sqlite3_open(db_file_.c_str(), &db);
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
                       "UPDATE jobs SET end_time = ? WHERE hash_id = ?;", -1,
                       &job_db_context.update_end_time_job, nullptr);
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
    sqlite3_finalize(job_db_context.update_end_time_job);
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
    sqlite3_bind_int64(job_db_context.insert_job, 5, -1);
    sqlite3_bind_text(job_db_context.insert_job, 6, path.c_str(), -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(job_db_context.insert_job, 7, json.c_str(), -1,
                      SQLITE_TRANSIENT);
    sqlite3_step(job_db_context.insert_job);
    sqlite3_reset(job_db_context.insert_job);
}
void DB::set_job_end_time(uint64_t job_hash_id, uint64_t end_time) {
    auto& job_db_context = active_jobs_[job_hash_id];
    sqlite3_bind_int64(job_db_context.update_end_time_job, 1, end_time);
    sqlite3_bind_int64(job_db_context.update_end_time_job, 2, job_hash_id);
    sqlite3_step(job_db_context.update_end_time_job);
    sqlite3_reset(job_db_context.update_end_time_job);
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
    sqlite3* db = nullptr;
    if (sqlite3_open(db_file_.c_str(), &db) != SQLITE_OK) {
        return {};
    }
    sqlite3_exec(db, "PRAGMA foreign_keys=ON;", nullptr, nullptr, nullptr);
    DB::JobData job_data{};
    job_data.hash_id = job_hash_id;
    sqlite3_stmt* stmt_job = nullptr;
    sqlite3_prepare_v2(db,
                       "SELECT start_time,end_time FROM jobs WHERE hash_id=?",
                       -1, &stmt_job, nullptr);
    sqlite3_bind_int64(stmt_job, 1, static_cast<sqlite3_int64>(job_hash_id));
    if (sqlite3_step(stmt_job) == SQLITE_ROW) {
        job_data.start_time
            = static_cast<uint64_t>(sqlite3_column_int64(stmt_job, 0));
        job_data.end_time
            = static_cast<uint64_t>(sqlite3_column_int64(stmt_job, 1));
    }
    sqlite3_finalize(stmt_job);
    sqlite3_stmt* stmt_exec = nullptr;
    sqlite3_prepare_v2(db,
                       "SELECT hash_id,start_time,path,json,command FROM execs "
                       "WHERE job_hash_id=?",
                       -1, &stmt_exec, nullptr);
    sqlite3_bind_int64(stmt_exec, 1, static_cast<sqlite3_int64>(job_hash_id));
    while (sqlite3_step(stmt_exec) == SQLITE_ROW) {
        DB::ExecDataDB exec{};
        exec.exec_hash_id
            = static_cast<uint64_t>(sqlite3_column_int64(stmt_exec, 0));
        exec.start_time
            = static_cast<uint64_t>(sqlite3_column_int64(stmt_exec, 1));
        {
            const unsigned char* p = sqlite3_column_text(stmt_exec, 2);
            exec.path = p ? reinterpret_cast<const char*>(p) : std::string{};
        }
        {
            const unsigned char* p = sqlite3_column_text(stmt_exec, 3);
            exec.json = p ? reinterpret_cast<const char*>(p) : std::string{};
        }
        {
            const unsigned char* p = sqlite3_column_text(stmt_exec, 4);
            exec.command = p ? reinterpret_cast<const char*>(p) : std::string{};
        }
        auto add_events = [&](const char* table) {
            std::string q = std::string("SELECT * FROM ") + table
                            + " WHERE exec_hash_id=? ORDER BY order_number";
            sqlite3_stmt* stmt = nullptr;
            sqlite3_prepare_v2(db, q.c_str(), -1, &stmt, nullptr);
            sqlite3_bind_int64(stmt, 1,
                               static_cast<sqlite3_int64>(exec.exec_hash_id));
            const std::string tname(table);
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                int order_number
                    = static_cast<int>(sqlite3_column_int64(stmt, 1));
                uint64_t pid
                    = static_cast<uint64_t>(sqlite3_column_int64(stmt, 2));
                Event ev{};
                ev.order_number = order_number;
                ev.pid = pid;
                if (tname == "process_starts") {
                    ev.operation_type = OperationType::ProcessStart;
                    ev.operation_data = ProcessStart{};
                } else if (tname == "read_operations") {
                    const unsigned char* c = sqlite3_column_text(stmt, 3);
                    std::string path_in
                        = c ? reinterpret_cast<const char*>(c) : std::string{};
                    ev.operation_type = OperationType::Read;
                    ev.operation_data = Read{std::move(path_in)};
                } else if (tname == "write_operations") {
                    const unsigned char* c = sqlite3_column_text(stmt, 3);
                    std::string path_out
                        = c ? reinterpret_cast<const char*>(c) : std::string{};
                    ev.operation_type = OperationType::Write;
                    ev.operation_data = Write{std::move(path_out)};
                } else if (tname == "execute_operations") {
                    uint64_t child_pid
                        = static_cast<uint64_t>(sqlite3_column_int64(stmt, 3));
                    const unsigned char* c = sqlite3_column_text(stmt, 4);
                    std::string path_exec
                        = c ? reinterpret_cast<const char*>(c) : std::string{};
                    ev.operation_type = OperationType::Execute;
                    ev.operation_data
                        = Execute{std::move(path_exec), child_pid};
                } else if (tname == "rename_operations") {
                    const unsigned char* c1 = sqlite3_column_text(stmt, 3);
                    const unsigned char* c2 = sqlite3_column_text(stmt, 4);
                    std::string orig = c1 ? reinterpret_cast<const char*>(c1)
                                          : std::string{};
                    std::string news = c2 ? reinterpret_cast<const char*>(c2)
                                          : std::string{};
                    ev.operation_type = OperationType::Rename;
                    ev.operation_data
                        = Rename{std::move(orig), std::move(news)};
                } else if (tname == "link_operations") {
                    const unsigned char* c1 = sqlite3_column_text(stmt, 3);
                    const unsigned char* c2 = sqlite3_column_text(stmt, 4);
                    std::string src = c1 ? reinterpret_cast<const char*>(c1)
                                         : std::string{};
                    std::string link = c2 ? reinterpret_cast<const char*>(c2)
                                          : std::string{};
                    ev.operation_type = OperationType::Link;
                    ev.operation_data = Link{std::move(src), std::move(link)};
                } else if (tname == "symlink_operations") {
                    const unsigned char* c1 = sqlite3_column_text(stmt, 3);
                    const unsigned char* c2 = sqlite3_column_text(stmt, 4);
                    std::string src = c1 ? reinterpret_cast<const char*>(c1)
                                         : std::string{};
                    std::string sym = c2 ? reinterpret_cast<const char*>(c2)
                                         : std::string{};
                    ev.operation_type = OperationType::Symlink;
                    ev.operation_data = Symlink{std::move(src), std::move(sym)};
                } else if (tname == "delete_operations") {
                    const unsigned char* c = sqlite3_column_text(stmt, 3);
                    std::string del
                        = c ? reinterpret_cast<const char*>(c) : std::string{};
                    ev.operation_type = OperationType::Delete;
                    ev.operation_data = Delete{std::move(del)};
                }
                exec.events.push_back(std::move(ev));
            }
            sqlite3_finalize(stmt);
        };
        add_events("process_starts");
        add_events("read_operations");
        add_events("write_operations");
        add_events("execute_operations");
        add_events("rename_operations");
        add_events("link_operations");
        add_events("symlink_operations");
        add_events("delete_operations");
        job_data.execs.push_back(std::move(exec));
    }
    sqlite3_finalize(stmt_exec);
    sqlite3_close(db);
    return job_data;
}
