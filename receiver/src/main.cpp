#include <iostream>
#include <mutex>
#include <string>

#include "logserver.hpp"

int main() {
    std::mutex data_mutex;
    std::string url = "127.0.0.1";
    int port = 9000;
    LogServer server(url, port);
    server.set_log_handler(
        [&](const httplib::Request& req, httplib::Response& res) {
            // ParsedInjectorData parsed_injector_data =
            // parse_injector_data(req.body);
            std::cerr << "[http] POST /log size=" << req.body.size() << "\n";
            std::cerr << req.body << "\n";
            res.set_content("{\"status\":\"ok\"}", "application/json");
        });
    server.run(4);
    return 0;
}
