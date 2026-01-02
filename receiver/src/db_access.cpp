#include <algorithm>
#include <cstdint>
#include <sstream>
#include <stdexcept>
#include <string>
#include <variant>

#include "db.hpp"
#include "model.hpp"

std::unordered_map<uint64_t, uint64_t> add_process(DB& db, uint64_t exec_id,
                                                   ProcessMap process_map) {
    std::unordered_map<uint64_t, uint64_t> process_hash_to_id;
    for (auto& [process_hash, process] : process_map) {
        process_hash_to_id[process_hash] = db.add_process(
            exec_id, process.process_command, process.env_variable_hash);
    }
    return process_hash_to_id;
}

void add_execute_mappings(
    DB& db, uint64_t exec_id, const ExecuteSetMap& execute_set_map,
    std::unordered_map<uint64_t, uint64_t> process_hash_to_id) {
    for (auto& [parent_process_id, child_process_ids] : execute_set_map) {
        for (uint64_t child_process_id : child_process_ids) {
            db.add_execute_mapping(exec_id, parent_process_id,
                                   child_process_id);
        }
    }
}

void add_operations(DB& db, uint64_t exec_id, ProcessMap process_map,
                    std::unordered_map<uint64_t, uint64_t> process_hash_to_id) {
    for (auto& [process_hash, process] : process_map) {
        uint64_t process_id = process_hash_to_id[process_hash];
        // db.add_process(exec_id, process.process_command,
        //                process.env_variable_hash);
        for (auto& [path, operations] : process.operation_map) {
            db.add_operations(process_id, path, operations.read,
                              operations.write, operations.deleted);
            // std::variant<Read, Write, Link, Symlink, Delete>
            // operation_payload
            /*
        std::variant<Read, Write, Delete> operation_payload
            = operation.operation_payload;
        switch (operation.operation_type) {
            case OperationType::Read: {
                Read read = std::get<Read>(operation_payload);
                db.add_operation("read", process_id, read.path_in);
                break;
            }
            case OperationType::Write: {
                Write write = std::get<Write>(operation_payload);
                db.add_operation("write", process_id, write.path_out);
                break;
            }
            case OperationType::Link: {
                Link link = std::get<Link>(operation_payload);
                db.add_operation("link", process_id, link.original_path,
                                 link.new_path);
                break;
            }
            case OperationType::Symlink: {
                Symlink symlink = std::get<Symlink>(operation_payload);
                db.add_operation("symlink", process_id,
                                 symlink.original_path, symlink.new_path);
                break;
            case OperationType::Delete: {
                Delete delete_obj = std::get<Delete>(operation_payload);
                db.add_operation("delete", process_id, write.path_out);
                break;
            }
            }
        }*/
        }
    }
}

void add_renames(DB& db, uint64_t exec_id, RenameMap rename_map) {
    for (auto& [original_path, new_path] : rename_map) {
        db.add_renames(exec_id, original_path, new_path);
    }
}

void add_variable_hash_pairs(DB& db,
                             EnvVariableHashPairs env_variable_hash_pairs) {
    for (auto& [env_variable_hash, env_variables_json] :
         env_variable_hash_pairs) {
        db.add_variable_hash_pair(env_variable_hash, env_variables_json);
    }
}

void handleExecCase(DB& db, uint64_t job_id, const std::string& cluster_name,
                    uint64_t timestamp, const ExecData& exec_data) {
}

void save_db_data(DB& db, const ParsedInjectorData& parsed_injector_data) {
    uint64_t job_id = parsed_injector_data.job_id;
    std::string cluster_name = parsed_injector_data.cluster_name;
    uint64_t timestamp = parsed_injector_data.timestamp;
    switch (parsed_injector_data.injector_data_type) {
        case InjectorDataType::End:
            db.set_current_job(job_id, cluster_name);
            db.set_job_end_time(job_id, cluster_name, timestamp);
            db.commit_job();
            db.finish_job(job_id, cluster_name);
            break;
        case InjectorDataType::Start: {
            db.init_job(job_id, cluster_name);
            StartData start_data
                = std::get<StartData>(parsed_injector_data.payload.value());
            std::string json_start = start_data.json;
            std::string path_start = start_data.path;
            db.set_current_job(job_id, cluster_name);
            db.add_job(job_id, cluster_name, timestamp, start_data.job_name,
                       start_data.username, path_start, json_start);
            db.commit_job();
            break;
        }
        case InjectorDataType::Exec: {
            ExecData exec_data
                = std::get<ExecData>(parsed_injector_data.payload.value());
            db.set_current_job(job_id, cluster_name);
            uint64_t exec_id
                = db.add_exec(job_id, cluster_name, timestamp, exec_data.path,
                              exec_data.json, exec_data.command);
            add_variable_hash_pairs(db,
                                    exec_data.env_variables_hash_to_variables);
            std::unordered_map<uint64_t, uint64_t> process_hash_to_id
                = add_process(db, exec_id, exec_data.process_map);
            add_execute_mappings(db, exec_id, exec_data.execute_set_map,
                                 process_hash_to_id);
            add_operations(db, exec_id, exec_data.process_map,
                           process_hash_to_id);
            add_renames(db, exec_id, exec_data.rename_map);
            db.commit_job();
        }
    }
}
/*
void order_job_data(DB::JobData& job_data) {
    for (auto& exec : job_data.execs) {
        std::sort(exec.events.begin(), exec.events.end(),
                  [](const Event& a, const Event& b) {
                      if (a.order_number != b.order_number)
                          return a.order_number < b.order_number;
                      if (a.process_hash != b.process_hash)
                          return a.process_hash < b.process_hash;
                      return static_cast<int>(a.operation_type)
                             < static_cast<int>(b.operation_type);
                  });
    }
    std::sort(job_data.execs.begin(), job_data.execs.end(),
              [](const DB::ExecDataDB& a, const DB::ExecDataDB& b) {
                  if (a.start_time != b.start_time)
                      return a.start_time < b.start_time;
                  return a.exec_hash_id < b.exec_hash_id;
              });
}

std::string event_to_json(const Event& event) {
    std::string operation_type_string;
    std::string event_data;
    auto operation_data = event.operation_data;
    switch (event.operation_type) {
        case OperationType::ProcessStart: {
            operation_type_string = "PROCESS_START";
            event_data = R"()";
            break;
        }
        case OperationType::Read: {
            operation_type_string = "READ";
            Read read = std::get<Read>(operation_data);
            event_data = R"("path_in":")" + read.path_in + R"(")";
            break;
        }
        case OperationType::Write: {
            operation_type_string = "WRITE";
            Write write = std::get<Write>(operation_data);
            event_data = R"("path_out":")" + write.path_out + R"(")";
            break;
        }
        case OperationType::Execute: {
            operation_type_string = "EXECUTE";
            Execute execute = std::get<Execute>(operation_data);
            event_data = R"("path_exec":")" + execute.path_exec
                         + R"(","child_process_hash":)"
                         + std::to_string(execute.child_process_hash);
            break;
        }
        case OperationType::Rename: {
            operation_type_string = "RENAME";
            Rename rename_obj = std::get<Rename>(operation_data);
            event_data = R"("original_path":")" + rename_obj.original_path
                         + R"(","new_path":")" + rename_obj.new_path +
R"(")"; break;
        }
        case OperationType::Link: {
            operation_type_string = "LINK";
            Link link = std::get<Link>(operation_data);
            event_data = R"("original_path":")" + link.original_path
                         + R"(","new_path":")" + link.new_path + R"(")";
            break;
        }
        case OperationType::Symlink: {
            operation_type_string = "SYMLINK";
            Symlink symlink = std::get<Symlink>(operation_data);
            event_data = R"("original_path":")" + symlink.original_path
                         + R"(","new_path":")" + symlink.new_path + R"(")";
            break;
        }
        case OperationType::Delete: {
            operation_type_string = "DELETE";
            Delete delete_obj = std::get<Delete>(operation_data);
            event_data
                = R"("deleted_path":")" + delete_obj.deleted_path + R"(")";
            break;
        }
    }
    return R"({"type":")" + operation_type_string + R"(","order_number":)"
           + std::to_string(event.order_number) + R"(,"process_hash":)"
           + std::to_string(event.process_hash) + R"(,"event_data":{)"
           + event_data + R"(}})";
}

std::string build_json_array(
    const std::vector<std::string>& json_object_vector) {
    std::ostringstream json_array;
    json_array << "[";
    bool first = true;
    for (const std::string& json_object : json_object_vector) {
        std::string maybe_comma = ",";
        if (first) {
            maybe_comma = "";
            first = false;
        }
        json_array << maybe_comma;
        json_array << json_object;
    }
    json_array << "]";
    return json_array.str();
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
    std::vector<std::string> json_env_variables_pairs;
    for (auto& [env_variables_hash, env_variables_json] :
         job_data.env_variabl_hash_pairs) {
        std::string json_env_variables_pairs_string
            = R"({"env_variables_hash":)" +
std::to_string(env_variables_hash)
              + R"(,"env_variables_array":)" + env_variables_json + R"(})";
        json_env_variables_pairs.push_back(json_env_variables_pairs_string);
    }
    for (const DB::ExecDataDB& exec_data : job_data.execs) {
        const DB::ExecDataDB& exec = exec_data;
        std::vector<std::string> json_events;
        for (const Event& event : exec.events) {
            json_events.push_back(event_to_json(event));
        }
        if (first_exec) {
            first_exec = false;
        } else {
            oss << ",";
        }
        oss << "{";
        oss << R"("hash_id":)" << exec.exec_hash_id << R"(,)";
        oss << R"("start_time":)" << exec.start_time << R"(,)";
        oss << R"("path":")" << exec.path << R"(",)";
        oss << R"("json":")" << exec.json << R"(",)";
        oss << R"("command":")" << exec.command << R"(",)";
        oss << R"("env_variable_hash_pair_array":)";
        oss << build_json_array(json_env_variables_pairs) << R"(,)";
        oss << R"("operations":)" << build_json_array(json_events);
        oss << "}";
        bool first_event = true;
        for (const Event& event : exec.events) {
            if (first_event) {
                first_event = false;
            } else {
                oss << ",";
            }
            oss << event_to_json(event);
        }
        oss << "]}";
    }
    oss << "]}";
    return oss.str();
}

*/
JobData fetch_graph_db_data(ParsedGraphRequestData parsed_graph_request_data) {
    DB db = DB();
    return db.get_job_data(parsed_graph_request_data.job_id,
                           parsed_graph_request_data.cluster_name);
}
