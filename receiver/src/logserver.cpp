#include "logserver.h"

#include <iostream>
#include <string>

LogServer::LogServer(std::string url, int port) : url(url), port(port) {
}

void LogServer::set_log_handler(Handler h) {
    log_handler = h;

    svr.Post("/log",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (log_handler) {
                     log_handler(req, res);
                 } else {
                     res.status = 500;
                     res.set_content("{\"error\":\"handler not set\"}",
                                     "application/json");
                 }
             });
}

void LogServer::run(int num_threads) {
    svr.listen(url, port, num_threads);
}
