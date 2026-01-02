#pragma once

#include <optional>
#include <string>

#include "model.hpp"

ParsedInjectorData parse_injector_data(const std::string&);
ParsedGraphRequestData parse_graph_request_data(std::string request_body);
