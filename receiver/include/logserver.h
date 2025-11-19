#ifndef LOGSERVER_H
#define LOGSERVER_H

#include <functional>
#include <string>

#include "httplib.h"

class LogServer {
   public:
    using Handler
        = std::function<void(const httplib::Request&, httplib::Response&)>;
    LogServer(std::string url, int port);
    void set_log_handler(Handler h);
    void run(int num_threads);

   private:
    httplib::Server svr;
    std::string url;
    Handler log_handler;
    int port;
};

#endif
