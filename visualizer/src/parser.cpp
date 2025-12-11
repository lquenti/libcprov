#include "parser.hpp"

#include <simdjson.h>

#include <cstdint>
#include <string>
#include <string_view>

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

ResponseType get_response_type(const std::string& response_type_string) {
    ResponseType response_type;
    if (response_type_string == "prov_data") {
        response_type = ResponseType::ProvData;
    } else if (response_type_string == "end") {
        response_type = ResponseType::Error;
    }
    return response_type;
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
            = get_operation_type(get_string(simdjson_event, "type"));
        int order_number = get_uint64(simdjson_event, "order_number");
        uint64_t pid = get_uint64(simdjson_event, "pid");
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

ExecData get_exec_data(ondemand::object& exec) {
    uint64_t exec_hash_id = get_uint64(exec, "hash_id");
    uint64_t start_time = get_uint64(exec, "start_time");
    std::string path = get_string(exec, "path");
    std::string json = get_string(exec, "json");
    std::string command = get_string(exec, "command");
    ondemand::array simdjson_events = exec["operations"].get_array().value();
    std::vector<Event> events = parse_events(simdjson_events);
    return ExecData{exec_hash_id, start_time, path, json, command, events};
}

ParsedLibcprovData parse_injector_data(const std::string& request_body) {
    ondemand::parser parser;
    padded_string padded_request_body_string(request_body);
    auto doc_res = parser.iterate(padded_request_body_string);
    auto doc = doc_res.get_object().value();
    std::string response_type_string = get_string(doc, "type");
    ResponseType response_type = get_response_type(response_type_string);
    ParsedLibcprovData parsed_libcprov_data = {response_type};
    if (response_type == ResponseType::Error) {
        return parsed_libcprov_data;
    }
    return parsed_libcprov_data;
    ondemand::object payload = doc["payload"].get_object().value();
    uint64_t job_hash_id = get_uint64(payload, "hash_id");
    uint64_t job_start_time = get_uint64(payload, "start_time");
    uint64_t job_end_time = get_uint64(payload, "end_time");
    ondemand::array execs = payload["execs"].get_array().value();
    std::vector<ExecData> exec_vector;
    for (ondemand::value exec_value : execs) {
        ondemand::object exec = exec_value.get_object().value();
        exec_vector.push_back(get_exec_data(exec));
    }
    parsed_libcprov_data.payload
        = Payload{job_hash_id, job_start_time, job_end_time, exec_vector};
    return parsed_libcprov_data;
}
