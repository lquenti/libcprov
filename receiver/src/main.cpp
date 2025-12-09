#include <iostream>
#include <mutex>
#include <string>

#include "db_fetcher.hpp"
#include "logserver.hpp"

int main() {
    std::mutex data_mutex;
    std::string url = "127.0.0.1";
    int port = 9000;
    LogServer server(url, port);
    server.set_log_handlers(
        [&](const httplib::Request& req, httplib::Response& res) {
            // ParsedInjectorData parsed_injector_data
            //     = parse_injector_data(req.body);
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
