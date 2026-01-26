#include <curl/curl.h>
#include <simdjson.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>

void set_env_variables(const std::string& path_exec,
                       const std::string& path_access);
void start_preload_process(const std::string& so_path, const std::string& cmd,
                           const std::string& path_access);
void send_json(const std::string& url, const std::string& header,
               const std::string& json);
void start_and_await_process(const std::string& injector_path,
                             const std::string& exec_command,
                             const std::string& injector_data_path);
