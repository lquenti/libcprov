#include <string>

#include "db.hpp"
#include "model.hpp"

void save_db_data(DB db, const ParsedInjectorData& parsed_injector_data);
std::string fetch_db_data(const std::string& request_body);
