#include <optional>
#include <string>

#include "db.hpp"
#include "model.hpp"

void save_db_data(DB& db, const ParsedInjectorData& parsed_injector_data);
// std::string fetch_db_data(const std::string& request_body);
JobData fetch_graph_db_data(ParsedGraphRequestData parsed_graph_request_data);
