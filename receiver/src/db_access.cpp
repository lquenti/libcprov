#include <algorithm>
#include <cstdint>
#include <db.hpp>
#include <sstream>
#include <stdexcept>
#include <string>
#include <variant>

#include "db.hpp"
#include "model.hpp"

void save_operations(DB db, const uint64_t& job_hash_id,
                     const ExecData& exec_data) {
    uint64_t exec_hash_id = exec_data.exec_hash_id;
    for (Event event : exec_data.events) {
        uint64_t pid = event.pid;
        int order_number = event.order_number;
        std::variant<ProcessStart, Read, Write, Execute, Rename, Link, Symlink,
                     Delete>
            operation_data = event.operation_data;
        switch (event.operation_type) {
            case OperationType::ProcessStart:
                db.add_process_start(job_hash_id, exec_hash_id, order_number,
                                     pid);
                break;
            case OperationType::Read: {
                Read read = std::get<Read>(operation_data);
                std::string path = read.path_in;
                db.add_read_operation(job_hash_id, exec_hash_id, order_number,
                                      pid, path);
                break;
            }
            case OperationType::Write: {
                Write write = std::get<Write>(operation_data);
                std::string path = write.path_out;
                db.add_write_operation(job_hash_id, exec_hash_id, order_number,
                                       pid, path);
                break;
            }
            case OperationType::Execute: {
                Execute execute = std::get<Execute>(operation_data);
                uint64_t child_pid = execute.child_pid;
                std::string path = execute.path_exec;
                db.add_execute_operation(job_hash_id, exec_hash_id,
                                         order_number, pid, child_pid, path);
                break;
            }
            case OperationType::Rename: {
                Rename rename = std::get<Rename>(operation_data);
                std::string original_path = rename.original_path;
                std::string new_path = rename.new_path;
                db.add_rename_operation(job_hash_id, exec_hash_id, order_number,
                                        pid, original_path, new_path);
                break;
            }
            case OperationType::Link: {
                Link link = std::get<Link>(operation_data);
                std::string original_path = link.original_path;
                std::string new_path = link.new_path;
                db.add_link_operation(job_hash_id, exec_hash_id, order_number,
                                      pid, original_path, new_path);
                break;
            }
            case OperationType::Symlink: {
                Symlink symlink = std::get<Symlink>(operation_data);
                std::string original_path = symlink.original_path;
                std::string new_path = symlink.new_path;
                db.add_symlink_operation(job_hash_id, exec_hash_id,
                                         order_number, pid, original_path,
                                         new_path);
                break;
            }
            case OperationType::Delete: {
                Delete delete_obj = std::get<Delete>(operation_data);
                std::string path = delete_obj.deleted_path;
                db.add_delete_operation(job_hash_id, exec_hash_id, order_number,
                                        pid, path);
                break;
            }
        }
    }
}

void handleExecCase(DB& db, const uint64_t& job_hash_id,
                    const uint64_t& timestamp, const ExecData& exec_data) {
    uint64_t exec_hash_id = exec_data.exec_hash_id;
    std::string path_exec = exec_data.path;
    std::string json_exec = exec_data.json;
    std::string command_exec = exec_data.command;
    db.add_exec(job_hash_id, exec_hash_id, timestamp, path_exec, json_exec,
                command_exec);
    save_operations(db, job_hash_id, exec_data);
    db.commit_job(job_hash_id);
}

void save_db_data(DB& db, const ParsedInjectorData& parsed_injector_data) {
    uint64_t job_hash_id = parsed_injector_data.job_hash_id;
    uint64_t timestamp = parsed_injector_data.timestamp;
    switch (parsed_injector_data.injector_data_type) {
        case InjectorDataType::End:
            db.set_job_end_time(job_hash_id, timestamp);
            db.commit_job(job_hash_id);
            db.finish_job(job_hash_id);
            break;
        case InjectorDataType::Start: {
            db.init_job(job_hash_id);
            StartData start_data
                = std::get<StartData>(parsed_injector_data.payload);
            uint64_t slurm_job_id = start_data.slurm_job_id;
            std::string slurm_cluster_name = start_data.slurm_cluster_name;
            std::string path_start = start_data.path;
            std::string json_start = start_data.json;
            ExecData exec_data = start_data.exec_data;
            db.add_job(job_hash_id, slurm_job_id, slurm_cluster_name, timestamp,
                       path_start, json_start);
            db.commit_job(job_hash_id);
            handleExecCase(db, job_hash_id, timestamp, exec_data);
            break;
        }
        case InjectorDataType::Exec: {
            ExecData exec_data
                = std::get<ExecData>(parsed_injector_data.payload);
            handleExecCase(db, job_hash_id, timestamp, exec_data);
        }
    }
}

void order_job_data(DB::JobData& job_data) {
    for (DB::ExecData& exec : job_data.execs) {
        std::sort(exec.operations.begin(), exec.operations.end(),
                  [](const auto& a, const auto& b) {
                      return std::visit(
                                 [](auto& operation) {
                                     return operation.order_number;
                                 },
                                 a)
                             < std::visit(
                                 [](auto& operation) {
                                     return operation.order_number;
                                 },
                                 b);
                  });
    }
    std::sort(job_data.execs.begin(), job_data.execs.end(),
              [](const DB::ExecData& a, const DB::ExecData& b) {
                  return a.start_time < b.start_time;
              });
}

std::string operation_to_json(const DB::OperationVariant& op) {
    return std::visit(
        [](const auto& o) -> std::string {
            std::ostringstream oss;
            using T = std::decay_t<decltype(o)>;
            if constexpr (std::is_same_v<T, DB::ProcessStart>) {
                oss << R"({"type":"ProcessStart","order_number":)"
                    << o.order_number << R"(,"pid":)" << o.pid << "}";
            } else if constexpr (std::is_same_v<T, DB::ReadOperation>) {
                oss << R"({"type":"ReadOperation","order_number":)"
                    << o.order_number << R"(,"pid":)" << o.pid << R"(,"path":")"
                    << o.path << R"("})";
            } else if constexpr (std::is_same_v<T, DB::WriteOperation>) {
                oss << R"({"type":"WriteOperation","order_number":)"
                    << o.order_number << R"(,"pid":)" << o.pid << R"(,"path":")"
                    << o.path << R"("})";
            } else if constexpr (std::is_same_v<T, DB::ExecuteOperation>) {
                oss << R"({"type":"ExecuteOperation","order_number":)"
                    << o.order_number << R"(,"pid":)" << o.pid
                    << R"(,"child_pid":)" << o.child_pid << R"(,"path":")"
                    << o.path << R"("})";
            } else if constexpr (std::is_same_v<T, DB::RenameOperation>) {
                oss << R"({"type":"RenameOperation","order_number":)"
                    << o.order_number << R"(,"pid":)" << o.pid
                    << R"(,"original_path":")" << o.original_path
                    << R"(","new_path":")" << o.new_path << R"("})";
            } else if constexpr (std::is_same_v<T, DB::LinkOperation>) {
                oss << R"({"type":"LinkOperation","order_number":)"
                    << o.order_number << R"(,"pid":)" << o.pid
                    << R"(,"source_path":")" << o.source_path
                    << R"(","link_path":")" << o.link_path << R"("})";
            } else if constexpr (std::is_same_v<T, DB::SymlinkOperation>) {
                oss << R"({"type":"SymlinkOperation","order_number":)"
                    << o.order_number << R"(,"pid":)" << o.pid
                    << R"(,"source_path":")" << o.source_path
                    << R"(","symlink_path":")" << o.symlink_path << R"("})";
            } else if constexpr (std::is_same_v<T, DB::DeleteOperation>) {
                oss << R"({"type":"DeleteOperation","order_number":)"
                    << o.order_number << R"(,"pid":)" << o.pid << R"(,"path":")"
                    << o.path << R"("})";
            }
            return oss.str();
        },
        op);
}

std::string convert_job_data_to_json(const DB::JobData& job_data) {
    std::ostringstream oss;
    oss << "{";
    oss << R"("hash_id":)" << job_data.hash_id << R"(,)";
    oss << R"("start_time":)" << job_data.start_time << R"(,)";
    oss << R"("end_time":)" << job_data.end_time << R"(,)";
    oss << R"("execs":[)";
    bool first_operation;
    bool first_exec = true;
    for (const DB::ExecData& exec_data : job_data.execs) {
        const DB::ExecData& exec = exec_data;
        if (first_exec) {
            first_exec = false;
        } else {
            oss << ",";
        }
        oss << "{";
        oss << R"("hash_id":)" << exec.hash_id << R"(,)";
        oss << R"("start_time":)" << exec.start_time << R"(,)";
        oss << R"("path":")" << exec.path << R"(",)";
        oss << R"("json":")" << exec.json << R"(",)";
        oss << R"("command":")" << exec.command << R"(",)";
        oss << R"("operations":[)";
        first_operation = true;
        for (const DB::OperationVariant& operation : exec.operations) {
            if (first_operation) {
                first_operation = false;
            } else {
                oss << ",";
            }
            oss << operation_to_json(operation);
        }
        oss << "]}";
    }
    oss << "]}";
    return oss.str();
}

std::string fetch_db_data(const std::string& request_body) {
    uint64_t hash_id = 0;
    try {
        hash_id = std::stoull(request_body);
    } catch (const std::invalid_argument& e) {
        return R"({"type":"error","payload":{"error":"invalid_argument"}})";
    } catch (const std::out_of_range& e) {
        return R"({"type":"error","payload":{"error":"out_of_range"}})";
    }
    DB db = DB();
    DB::JobData job_data = db.get_job_data(hash_id);
    order_job_data(job_data);
    std::string json_response_data = R"({"type":prov_data","payload":)"
                                     + convert_job_data_to_json(job_data)
                                     + R"(})";
    return json_response_data;
}
