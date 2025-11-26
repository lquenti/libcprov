#include <curl/curl.h>
#include <simdjson.h>
#include <sys/wait.h>
#include <unistd.h>

#include <CLI/CLI.hpp>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

using namespace simdjson;

struct Event {
    uint64_t ts;
    uint64_t pid;
    std::string json;
};

void set_env_variables(const std::string& path_exec,
                       const std::string& path_access) {
    setenv("PROV_PATH_EXEC", path_exec.c_str(), 1);
    setenv("PROV_PATH_WRITE", path_access.c_str(), 1);
}

void start_preload_process(const std::string& so_path, const std::string& cmd,
                           const std::string& path_access) {
    std::filesystem::create_directory(path_access);
    pid_t pid = fork();
    if (pid == 0) {
        if (!so_path.empty()) {
            setenv("LD_PRELOAD", so_path.c_str(), 1);
        }
        execl("/bin/sh", "sh", "-c", cmd.c_str(), (char*)nullptr);
        _exit(127);
    } else {
        waitpid(pid, nullptr, 0);
    }
}

std::vector<Event> parse_injector_data(const std::string& path_access) {
    std::vector<Event> events;
    std::vector<std::string> filenames;
    ondemand::parser parser;
    for (const auto& entry : std::filesystem::directory_iterator(path_access)) {
        std::ifstream injector_data_file(entry.path());
        std::string json_object;
        bool first = true;
        uint64_t child_pid;
        while (std::getline(injector_data_file, json_object)) {
            ondemand::document doc = parser.iterate(json_object);
            if (first) {
                child_pid = doc["event_data"]["pid"].get_uint64().value();
                first = false;
            }
            uint64_t new_ts = doc["event_header"]["ts"].get_uint64().value();
            events.push_back({new_ts, child_pid, json_object});
        }
    }
    std::filesystem::remove_all(path_access);
    std::sort(events.begin(), events.end(),
              [](const Event& a, const Event& b) { return a.ts < b.ts; });
    return events;
}

void send_json(const std::string& url, const std::string& json) {
    CURL* curl = curl_easy_init();
    if (!curl) return;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json.c_str());
    curl_easy_setopt(
        curl, CURLOPT_WRITEFUNCTION,
        +[](void*, size_t s, size_t n, void*) { return s * n; });

    curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}

std::string build_start_json_output(const std::string& path_start,
                                    const std::string& slurm_job_id,
                                    const std::string& slurm_cluster_name,
                                    const std::string& json_start_extra) {
    std::string absolute_path_start = std::filesystem::canonical(path_start);
    return R"({"header":{"type":"start","slurm_job_id":")" + slurm_job_id
           + R"(","slurm_cluster_name":")" + slurm_cluster_name
           + R"("},"payload":{"json":)" + json_start_extra + R"(,"path":")"
           + absolute_path_start + R"("}})";
}

std::string build_end_json_output(const std::string& slurm_job_id,
                                  const std::string& slurm_cluster_name,
                                  const std::string& json_end_extra) {
    return R"({"header":{"type":"end","slurm_job_id":")" + slurm_job_id
           + R"(","slurm_cluster_name":")" + slurm_cluster_name
           + R"("},"payload":{"json":)" + json_end_extra + "}}";
}

std::string build_exec_json_output(const std::string& slurm_job_id,
                                   const std::string& slurm_cluster_name,
                                   const std::string& path_exec,
                                   const std::string& json_exec,
                                   const std::string& cmd,
                                   const std::vector<Event>& events) {
    std::string json_object;
    std::ostringstream event_array;
    event_array << "[";
    bool first = true;
    for (const Event& event : events) {
        if (!first) event_array << ",";
        std::string json_with_pid = event.json;
        size_t header_start = json_with_pid.find(R"("event_header":{)");
        size_t insert_pos = header_start + strlen("\"event_header\":{");
        std::string pid_field = R"("pid":)" + std::to_string(event.pid) + ",";
        json_with_pid.insert(insert_pos, pid_field);
        event_array << json_with_pid;
        first = false;
    }
    event_array << "]";
    std::string absolute_path_exec = std::filesystem::canonical(path_exec);
    std::string json_string = R"({"header":{"type":"exec","slurm_job_id":")"
                              + slurm_job_id + R"(","slurm_cluster_name":")"
                              + slurm_cluster_name
                              + R"("},"payload":{"events":)" + event_array.str()
                              + R"(,"json":)" + json_exec + R"(,"path":")"
                              + path_exec + R"(","command":")" + cmd + R"("}})";
    return json_string;
}

int main(int argc, char** argv) {
    const std::string endpoint_url = "http://127.0.0.1:9000/log";
    // const std::string injector_path =
    // std::filesystem::canonical("./injector.so");
    CLI::App app{"test"};
    auto start = app.add_subcommand("start", "start the service");
    bool mpi_start = false;
    std::string path_start = std::filesystem::current_path();
    std::string json_start_extra = "{}";
    start->add_flag("--mpi", mpi_start, "Enable MPI mode");
    start->add_option("--path", path_start, "Scefify path");
    start->add_option("--json", json_start_extra,
                      "Provide optional extra metadata");
    auto end = app.add_subcommand("end", "Stop service");
    std::string json_end_extra = "{}";
    end->add_option("--json", json_end_extra,
                    "Provide optional extra metadata");
    bool mpi_end = false;
    end->add_flag("--mpi", mpi_end, "Enable MPI mode");
    auto exec = app.add_subcommand("exec", "Execute command");
    std::string command = "";
    std::string path_exec = std::filesystem::current_path();
    std::string json_exec_extra = "{}";
    exec->add_option("command", command, "Specify Slurm command")->required();
    exec->add_option("--path", path_exec, "Spefify path")->required();
    exec->add_option("--json", json_exec_extra,
                     "Provide optional extra metadata");
    app.require_subcommand();
    CLI11_PARSE(app, argc, argv);

    const char* jid = std::getenv("SLURM_JOB_ID");
    const char* cname = std::getenv("SLURM_CLUSTER_NAME");
    /*
    if (!jid || !cname) {
        std::cerr << "Warning: SLURM_JOB_ID or SLURM_CLUSTER_NAME not set. "
                     "Exiting.\n";
        return 1;
    }
    std::string slurm_job_id = jid;
    std::string slurm_cluster_name = cname;*/

    std::string slurm_job_id = "1";
    std::string slurm_cluster_name = "cname1";

    if (*start) {
        std::string start_json_output = build_start_json_output(
            path_start, slurm_job_id, slurm_cluster_name, json_start_extra);
        send_json(endpoint_url, start_json_output);
    } else if (*end) {
        std::string end_json_output = build_end_json_output(
            slurm_job_id, slurm_cluster_name, json_end_extra);
        send_json(endpoint_url, end_json_output);
    } else if (*exec) {
        std::string absolute_path_exec = std::filesystem::canonical(path_exec);
        std::string path_access = "/dev/shm/prov_" + std::to_string(getpid());
        set_env_variables(absolute_path_exec, path_access);
        std::string injector_path = "./injector/build/libinjector.so";
        start_preload_process(injector_path, command, path_access);
        std::vector<Event> events = parse_injector_data(path_access);
        std::string exec_json_output = build_exec_json_output(
            slurm_job_id, slurm_cluster_name, absolute_path_exec,
            json_exec_extra, command, events);
        send_json(endpoint_url, exec_json_output);
    }
}
