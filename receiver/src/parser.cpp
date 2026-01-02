#include "parser.hpp"

#include <simdjson.h>
#include <xxhash.h>

#include <cstdint>
#include <string>

#include "model.hpp"

using namespace simdjson;

std::string get_string(ondemand::object& obj, const char* name) {
    simdjson_result<std::string_view> result
        = obj.find_field_unordered(name).get_string();
    return std::string(result.value());
}

uint64_t get_uint64(ondemand::object& obj, const char* name) {
    simdjson_result<uint64_t> result
        = obj.find_field_unordered(name).get_uint64();
    return result.value();
}

std::string get_array_json(simdjson::ondemand::object& obj,
                           const std::string_view& name) {
    simdjson::simdjson_result<simdjson::ondemand::value> v_res
        = obj.find_field_unordered(name);
    simdjson::ondemand::value v = v_res.value();
    simdjson::simdjson_result<simdjson::ondemand::json_type> t = v.type();
    simdjson::simdjson_result<std::string_view> raw = v.raw_json();
    return std::string(raw.value());
}

std::vector<std::string> parse_json_string_array(
    simdjson::ondemand::object& obj, const std::string_view& name) {
    std::vector<std::string> json_vector;
    auto field_res = obj.find_field_unordered(name);
    simdjson::ondemand::array arr = field_res.value().get_array();
    for (simdjson::ondemand::value element : arr) {
        json_vector.push_back(std::string(element.raw_json().value()));
    }
    return json_vector;
}

std::vector<uint64_t> parse_json_uint64_t_array(simdjson::ondemand::object& obj,
                                                const std::string_view& name) {
    std::vector<uint64_t> json_vector;
    auto field_res = obj.find_field_unordered(name);
    for (simdjson::ondemand::value element :
         field_res.value().get_array().value()) {
        json_vector.push_back(element.get_uint64().value());
    }
    return json_vector;
}

InjectorDataType get_injector_data_type(const std::string& type_string) {
    InjectorDataType result;
    if (type_string == "start") {
        result = InjectorDataType::Start;
    } else if (type_string == "end") {
        result = InjectorDataType::End;
    } else if (type_string == "exec") {
        result = InjectorDataType::Exec;
    }
    return result;
}

OperationType get_operation_type(const std::string& operation_string) {
    OperationType result;
    /*if (operation_string == "PROCESS_START") {
        result = OperationType::ProcessStart;
    }*/
    if (operation_string == "READ") {
        result = OperationType::Read;
    } else if (operation_string == "WRITE") {
        result = OperationType::Write;
    } /*else if (operation_string == "RENAME") {
        result = OperationType::Rename;
    } else if (operation_string == "LINK") {
        result = OperationType::Link;
    } else if (operation_string == "SYMLINK") {
        result = OperationType::Symlink;
    }*/
    else if (operation_string == "DELETE") {
        result = OperationType::Delete;
    }
    return result;
}

std::unordered_map<std::string, Operations> parse_operation_map(
    ondemand::object& json_operation_map) {
    std::unordered_map<std::string, Operations> operation_map;
    for (ondemand::field json_operation_mapping : json_operation_map) {
        std::string_view path_sv;
        (void)json_operation_mapping.unescaped_key().get(path_sv);
        std::string path(path_sv);
        ondemand::array ops_arr;
        (void)json_operation_mapping.value().get_array().get(ops_arr);
        Operations& ops = operation_map[path];
        for (simdjson::ondemand::value operation : ops_arr) {
            std::string_view operation_sv;
            (void)operation.get_string().get(operation_sv);
            std::string operation_string(operation_sv);
            if (operation_string == "read") {
                ops.read = true;
            } else if (operation_string == "write") {
                ops.write = true;
            } else if (operation_string == "deleted") {
                ops.deleted = true;
            }
        }
    }
    return operation_map;
}

/*std::unordered_map<std::string, Operations> parse_operations(
    ondemand::array simdjson_operations) {
    std::vector<Operation> parsed_operations;
    for (ondemand::value operation_value : simdjson_operations) {
        ondemand::object simdjson_operation
            = operation_value.get_object().value();
        Operation operation;
        operation.operation_type = get_operation_type(
            get_string(simdjson_operation, "operation_type"));
        ondemand::object operation_payload
            = simdjson_operation["operation_payload"].get_object();
        switch (operation.operation_type) {
            case OperationType::Read:
                operation.operation_payload
                    = Read{get_string(operation_payload, "path_in")};
                break;
            case OperationType::Write:
                operation.operation_payload
                    = Write{get_string(operation_payload, "path_out")};
                break;
            case OperationType::Delete:
                operation.operation_payload
                    = Delete{get_string(operation_payload, "deleted_path")};
                break;
        }
        parsed_operations.push_back(operation);
    }
    return parsed_operations;
}*/

ProcessMap parse_processes(ondemand::array simdjson_processes) {
    ProcessMap process_map;
    // std::vector<Process> parsed_processes;
    for (ondemand::value process_value : simdjson_processes) {
        ondemand::object simdjson_process = process_value.get_object().value();
        Process process;
        process.process_command
            = get_string(simdjson_process, "process_command");
        uint64_t process_hash = get_uint64(simdjson_process, "process_hash");
        process.env_variable_hash
            = get_uint64(simdjson_process, "env_variable_hash");
        // process.operations
        //     = parse_operations(simdjson_process["operations"].get_array());
        ondemand::object simdjson_operations
            = simdjson_process["operations"].get_object().value();
        process.operation_map = parse_operation_map(simdjson_operations);
        process_map[process_hash] = process;
    }
    return process_map;
}

ExecuteSetMap parse_execute_maps(ondemand::array simdjson_execute_maps) {
    ExecuteSetMap execute_set_map;
    for (ondemand::value execute_map_value : simdjson_execute_maps) {
        ondemand::object simdjson_execute_map
            = execute_map_value.get_object().value();
        uint64_t parent_process_id
            = get_uint64(simdjson_execute_map, "parent_process_id");
        std::vector<uint64_t> child_process_ids = parse_json_uint64_t_array(
            simdjson_execute_map, "child_process_id_array");
        std::unordered_set<uint64_t> child_process_ids_set(
            child_process_ids.begin(), child_process_ids.end());
        execute_set_map[parent_process_id] = child_process_ids_set;
    }
    return execute_set_map;
}

RenameMap parse_rename_map(ondemand::object& json_rename_map) {
    RenameMap rename_map;
    for (ondemand::field json_rename_mapping : json_rename_map) {
        std::string_view original_path_sv;
        (void)json_rename_mapping.unescaped_key().get(original_path_sv);
        std::string original_path(original_path_sv);
        std::string_view new_path_sv;
        (void)json_rename_mapping.value().get_string().get(new_path_sv);
        std::string new_path(new_path_sv);
        rename_map.emplace(std::move(original_path), std::move(new_path));
    }
    return rename_map;
}

EnvVariableHashPairs parse_env_variable_hash_pairs(
    ondemand::array simdjson_hash_pairs) {
    EnvVariableHashPairs env_variable_hash_pairs;
    uint64_t env_variables_hash;
    std::string env_variables;
    for (ondemand::value hash_pair : simdjson_hash_pairs) {
        ondemand::object simdjson_hash_pair = hash_pair.get_object().value();
        env_variables_hash
            = get_uint64(simdjson_hash_pair, "env_variables_hash");
        env_variables
            = get_array_json(simdjson_hash_pair, "env_variables_array");
        env_variable_hash_pairs[env_variables_hash] = env_variables;
    };
    return env_variable_hash_pairs;
}

ExecData get_exec_data(ondemand::object& payload) {
    ProcessMap process_map = parse_processes(payload["processes"].get_array());
    ExecuteSetMap execute_set_map
        = parse_execute_maps(payload["execute_map"].get_array());
    ondemand::object simdjson_rename_map
        = payload["rename_map"].get_object().value();
    RenameMap rename_map = parse_rename_map(simdjson_rename_map);
    EnvVariableHashPairs env_variable_hash_pairs
        = parse_env_variable_hash_pairs(
            payload["env_variable_hash_pair_array"].get_array());
    std::string json = get_string(payload, "json");
    std::string path = get_string(payload, "path");
    std::string command = get_string(payload, "command");
    return ExecData{.process_map = process_map,
                    .execute_set_map = execute_set_map,
                    .env_variables_hash_to_variables = env_variable_hash_pairs,
                    .json = json,
                    .path = path,
                    .command = command};
}

ParsedInjectorData parse_injector_data(const std::string& request_body) {
    ondemand::parser parser;
    padded_string padded_request_body_string(request_body);
    auto doc_res = parser.iterate(padded_request_body_string);
    auto doc = doc_res.get_object().value();
    ondemand::object header = doc["header"].get_object().value();
    ParsedInjectorData parsed_injector_data;
    std::string type = get_string(header, "type");
    InjectorDataType injector_data_type = get_injector_data_type(type);
    uint64_t job_id = get_uint64(header, "job_id");
    std::string cluster_name = get_string(header, "cluster_name");
    uint64_t timestamp = get_uint64(header, "timestamp");
    parsed_injector_data.injector_data_type = injector_data_type;
    parsed_injector_data.job_id = job_id;
    parsed_injector_data.cluster_name = cluster_name;
    parsed_injector_data.timestamp = timestamp;
    ondemand::object payload = doc["payload"].get_object().value();
    switch (parsed_injector_data.injector_data_type) {
        case InjectorDataType::End: {
            break;
        }
        case InjectorDataType::Start: {
            parsed_injector_data.payload = StartData{
                get_string(payload, "job_name"),
                get_string(payload, "username"), get_string(payload, "json"),
                get_string(payload, "path")};
            break;
        }
        case InjectorDataType::Exec: {
            parsed_injector_data.payload = get_exec_data(payload);
            break;
        }
    }
    return parsed_injector_data;
}

ParsedGraphRequestData parse_graph_request_data(std::string request_body) {
    ondemand::parser parser;
    padded_string padded_request_body_string(request_body);
    auto doc_res = parser.iterate(padded_request_body_string);
    auto doc = doc_res.get_object().value();
    uint64_t job_id = get_uint64(doc, "job_id");
    std::string cluster_name = get_string(doc, "cluster_name");
    return ParsedGraphRequestData{job_id, cluster_name};
}
