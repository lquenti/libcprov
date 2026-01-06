#include <cstdint>
#include <string>

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
    for (auto& [parent_process_hash, child_process_hashes] : execute_set_map) {
        uint64_t parent_process_id = process_hash_to_id[parent_process_hash];
        uint64_t child_process_id;
        for (uint64_t child_process_hash : child_process_hashes) {
            child_process_id = process_hash_to_id[child_process_hash];
            db.add_execute_mapping(exec_id, parent_process_id,
                                   child_process_id);
        }
    }
}

void add_operations(DB& db, uint64_t exec_id, ProcessMap process_map,
                    std::unordered_map<uint64_t, uint64_t> process_hash_to_id) {
    for (auto& [process_hash, process] : process_map) {
        uint64_t process_id = process_hash_to_id[process_hash];
        for (auto& [path, operations] : process.operation_map) {
            db.add_operations(process_id, path, operations.read,
                              operations.write, operations.deleted);
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
            add_operations(db, exec_id, exec_data.process_map,
                           process_hash_to_id);
            add_execute_mappings(db, exec_id, exec_data.execute_set_map,
                                 process_hash_to_id);
            add_renames(db, exec_id, exec_data.rename_map);
            db.commit_job();
        }
    }
}

JobData fetch_graph_db_data(ParsedGraphRequestData parsed_graph_request_data) {
    DB db = DB();
    return db.get_job_data(parsed_graph_request_data.job_id,
                           parsed_graph_request_data.cluster_name);
}
