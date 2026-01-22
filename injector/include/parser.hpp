#pragma once
#include <simdjson.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "model.hpp"

std::string get_string(simdjson::ondemand::object& obj, const char* name);
uint64_t get_uint64(simdjson::ondemand::object& obj, const char* name);

inline bool one_of(std::string_view t, std::string_view a);
template <class... Ss>
inline bool one_of(std::string_view t, std::string_view a, Ss... s);
SysOp sysop_from(std::string_view t);
Event parse_event_object(simdjson::ondemand::object event_obj, uint64_t& pid);
std::vector<Event> parse_jsonl_file(const std::string& path,
                                    simdjson::ondemand::parser& parser);
EventsByFile parse_all_jsonl_files(const std::string& path_access);
