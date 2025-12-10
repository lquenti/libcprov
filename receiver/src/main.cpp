#include <iostream>
#include <mutex>
#include <string>

#include "db.hpp"
#include "db_access.hpp"
#include "logserver.hpp"
#include "model.hpp"
#include "parser.hpp"

int main() {
    std::mutex data_mutex;
    std::string url = "127.0.0.1";
    int port = 9000;
    LogServer server(url, port);
    DB db;
    db.build_tables();
    server.set_log_handlers(
        [&](const httplib::Request& req, httplib::Response& res) {
            ParsedInjectorData parsed_injector_data
                = parse_injector_data(req.body);
            // save_db_data(db, parsed_injector_data);
            std::cerr << "[http] POST /log size=" << req.body.size() << "\n";
            std::cerr << req.body << "\n";
            res.status = 200;
        },
        [&](const httplib::Request& req, httplib::Response& res) {
            std::cerr << "[http] POST /log size=" << req.body.size() << "\n";
            std::cerr << req.body << "\n";
            std::string json_response_data = fetch_db_data(req.body);
            res.set_content(json_response_data, "application/json");
        });
    server.run(4);
    return 0;
}
