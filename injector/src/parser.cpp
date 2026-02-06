#include "parser.hpp"

#include <simdjson.h>

#include <cstdint>
#include <filesystem>
#include <iterator>
#include <string>
#include <vector>

using namespace simdjson;

std::string get_string(ondemand::object& obj, const char* name) {
    simdjson_result<std::string_view> result =
        obj.find_field_unordered(name).get_string();
    return std::string(result.value());
}

uint64_t get_uint64(ondemand::object& obj, const char* name) {
    simdjson_result<uint64_t> result =
        obj.find_field_unordered(name).get_uint64();
    return result.value();
}

std::string get_array_json(simdjson::ondemand::object& obj,
                           const std::string_view& name) {
    simdjson::simdjson_result<simdjson::ondemand::value> v_res =
        obj.find_field_unordered(name);
    simdjson::ondemand::value v = v_res.value();
    simdjson::simdjson_result<simdjson::ondemand::json_type> t = v.type();
    simdjson::simdjson_result<std::string_view> raw = v.raw_json();
    return std::string(raw.value());
}

bool one_of(std::string_view t, std::string_view a) { return t == a; }
template <class... Ss>
bool one_of(std::string_view t, std::string_view a, Ss... s) {
    return (t == a) || one_of(t, s...);
}

SysOp sysop_from(std::string_view operation_string) {
    using O = SysOp;
    O result;
    if (operation_string == "PROCESS_START") {
        result = O::ProcessStart;
    }
    if (operation_string == "PROCESS_END") {
        result = O::ProcessEnd;
    }
    if (operation_string == "READ") {
        result = O::Read;
    } else if (operation_string == "WRITE") {
        result = O::Write;
    } else if (operation_string == "TRANSFER") {
        result = O::Transfer;
    } else if (operation_string == "EXEC") {
        result = O::Exec;
    } else if (operation_string == "EXEC_FAIL") {
        result = O::ExecFail;
    } else if (operation_string == "RENAME") {
        result = O::Rename;
    } else if (operation_string == "UNLINK") {
        result = O::Unlink;
    }
    return result;
}

Event parse_event_object(ondemand::object event_obj) {
    auto hdr_res = event_obj.find_field_unordered("event_header").get_object();
    auto hdr = hdr_res.value();
    uint64_t ts = get_uint64(hdr, "ts");
    std::string op = get_string(hdr, "operation");
    ondemand::object event_data{};
    auto dr = event_obj.find_field_unordered("event_data").get_object();
    event_data = dr.value();
    EventPayload empty_payload;
    Event new_event = {
        .ts = ts, .operation = sysop_from(op), .event_payload = empty_payload};
    using O = SysOp;
    switch (new_event.operation) {
        case O::ProcessStart: {
            uint64_t pid = get_uint64(event_data, "pid");
            uint64_t ppid = get_uint64(event_data, "ppid");
            std::string process_name = get_string(event_data, "launch_command");
            std::string env_variables =
                get_array_json(event_data, "env_variables");
            new_event.event_payload =
                ProcessStart{.pid = pid,
                             .ppid = ppid,
                             .process_name = process_name,
                             .env_variables = env_variables};
            break;
        }
        case O::ProcessEnd:
            break;
        case O::Write:
        case O::Read:
        case O::Unlink: {
            new_event.event_payload = get_string(event_data, "path");
            break;
        }
        case O::Transfer:
            new_event.event_payload =
                Transfer{.path_read = get_string(event_data, "path_read"),
                         .path_write = get_string(event_data, "path_write")};
            break;
        case O::Rename:
            new_event.event_payload =
                Rename{.original_path = get_string(event_data, "original_path"),
                       .new_path = get_string(event_data, "new_path")};
            break;
        case O::Exec:
            break;
        case O::ExecFail:
            break;
    }
    return new_event;
}

std::vector<Event> parse_jsonl_file(const std::string& path,
                                    ondemand::parser& parser) {
    std::vector<Event> events;
    auto p_res = padded_string::load(path);
    padded_string p = std::move(p_res.value());
    auto stream_res = parser.iterate_many(p.data(), p.size(), size_t(1) << 20);
    for (auto doc : *stream_res) {
        auto obj_res = doc.get_object();
        auto ev_opt = parse_event_object(obj_res.value());
        events.push_back(std::move(ev_opt));
    }
    return events;
}

EventsByFile parse_all_jsonl_files(const std::string& path_access) {
    EventsByFile events_by_file;
    ondemand::parser parser;
    for (const auto& entry : std::filesystem::directory_iterator(path_access)) {
        events_by_file.push_back(
            parse_jsonl_file(entry.path().string(), parser));
    }
    return events_by_file;
}
