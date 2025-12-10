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
    if (operation_string == "PROCESS_START") {
        result = OperationType::ProcessStart;
    } else if (operation_string == "READ") {
        result = OperationType::Read;
    } else if (operation_string == "WRITE") {
        result = OperationType::Write;
    } else if (operation_string == "EXEC") {
        result = OperationType::Execute;
    } else if (operation_string == "RENAME") {
        result = OperationType::Rename;
    } else if (operation_string == "LINK") {
        result = OperationType::Link;
    } else if (operation_string == "SYMLINK") {
        result = OperationType::Symlink;
    } else if (operation_string == "DELETE") {
        result = OperationType::Delete;
    }
    return result;
}

std::vector<Event> parse_events(ondemand::array simdjson_events) {
    std::vector<Event> parsed_events;
    for (ondemand::value event_value : simdjson_events) {
        ondemand::object simdjson_event = event_value.get_object().value();
        Event event;
        OperationType operation_type
            = get_operation_type(get_string(simdjson_event, "operation"));
        uint64_t pid = get_uint64(simdjson_event, "pid");
        int order_number = get_uint64(simdjson_event, "order_number");
        ondemand::object event_data = simdjson_event["event_data"].get_object();
        event.pid = pid;
        event.order_number = order_number;
        event.operation_type = operation_type;
        switch (event.operation_type) {
            case OperationType::ProcessStart:
                event.operation_data = ProcessStart{};
                break;
            case OperationType::Read:
                event.operation_data = Read{get_string(event_data, "path_in")};
                break;
            case OperationType::Write:
                event.operation_data
                    = Write{get_string(event_data, "path_out")};
                break;
            case OperationType::Execute:
                event.operation_data
                    = Execute{get_string(event_data, "path_exec"),
                              get_uint64(event_data, "child_pid")};
                break;
            case OperationType::Rename:
                event.operation_data
                    = Rename{get_string(event_data, "original_path"),
                             get_string(event_data, "new_path")};
                break;
            case OperationType::Link:
                event.operation_data
                    = Link{get_string(event_data, "original_path"),
                           get_string(event_data, "new_path")};
                break;
            case OperationType::Symlink:
                event.operation_data
                    = Symlink{get_string(event_data, "original_path"),
                              get_string(event_data, "new_path")};
                break;
            case OperationType::Delete:
                event.operation_data
                    = Delete{get_string(event_data, "deleted_path")};
                break;
        }
        parsed_events.push_back(event);
    }
    return parsed_events;
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
    uint64_t job_hash_id = get_uint64(header, "hash_id");
    uint64_t timestamp = get_uint64(header, "timestamp");
    parsed_injector_data.injector_data_type = injector_data_type;
    parsed_injector_data.job_hash_id = job_hash_id;
    parsed_injector_data.timestamp = timestamp;
    ondemand::object payload = doc["payload"].get_object().value();
    switch (parsed_injector_data.injector_data_type) {
        case InjectorDataType::Start: {
            parsed_injector_data.payload = StartData{
                get_uint64(payload, "slurm_job_id"),
                get_string(payload, "slurm_cluster_name"),
                get_string(payload, "json"), get_string(payload, "path")};
            break;
        }
        case InjectorDataType::End:
            parsed_injector_data.payload = EndData{get_string(payload, "json")};
            break;
        case InjectorDataType::Exec:
            std::string exec_hash_source_string
                = std::to_string(job_hash_id) + std::to_string(timestamp);
            uint64_t exec_hash_id = XXH64(exec_hash_source_string.data(),
                                          exec_hash_source_string.size(), 0);
            std::vector<Event> events
                = parse_events(payload["events"].get_array());
            std::string json = get_string(payload, "json");
            std::string path = get_string(payload, "path");
            parsed_injector_data.payload
                = ExecData{exec_hash_id, events, json, path};
            break;
    }
    return parsed_injector_data;
}
