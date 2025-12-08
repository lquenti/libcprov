#include <curl/curl.h>
#include <simdjson.h>
#include <sys/wait.h>
#include <unistd.h>

#include <CLI/CLI.hpp>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <string>

#include "model.hpp"
#include "parser.hpp"
#include "processor.hpp"

using namespace simdjson;

void set_env_variables(const std::string& path_exec,
                       const std::string& path_access) {
    setenv("PROV_PATH_EXEC", path_exec.c_str(), 1);
    setenv("PROV_PATH_WRITE", path_access.c_str(), 1);
}

std::string now_ns() {
    using namespace std::chrono;
    uint64_t ts
        = duration_cast<nanoseconds>(system_clock::now().time_since_epoch())
              .count();
    std::string ts_string = std::to_string(ts);
    return ts_string;
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

/*std::vector<Event> parse_injector_data(const std::string& path_access) {
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
}*/

ProcessedInjectorData extract_injector_data(const std::string& path_access) {
    std::vector<Event> events = parse_all_jsonl_files(path_access);
    std::filesystem::remove_all(path_access);
    std::sort(events.begin(), events.end(),
              [](const Event& a, const Event& b) { return a.ts < b.ts; });
    std::deque<Event> events_queue;
    std::ranges::move(events, std::back_inserter(events_queue));
    events.clear();
    ProcessedInjectorData processed_injector_data
        = process_events(events_queue);
    return processed_injector_data;
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

std::string build_header(const std::string& slurm_job_id,
                         const std::string& slurm_cluster_name,
                         const std::string& type) {
    return R"({"header":{"type":")" + type + R"(","slurm_job_id":")"
           + slurm_job_id + R"(","slurm_cluster_name":")" + slurm_cluster_name
           + R"(","timestamp":)" + now_ns() + R"(})";
}

std::string build_start_json_output(const std::string& path_start,
                                    const std::string& slurm_job_id,
                                    const std::string& slurm_cluster_name,
                                    const std::string& json_start_extra) {
    std::string absolute_path_start = std::filesystem::canonical(path_start);
    std::string header
        = build_header(slurm_job_id, slurm_cluster_name, "start");
    return header + R"(,"payload":{"json":)" + json_start_extra + R"(,"path":")"
           + absolute_path_start + R"("}})";
}

std::string build_end_json_output(const std::string& slurm_job_id,
                                  const std::string& slurm_cluster_name,
                                  const std::string& json_end_extra) {
    std::string header = build_header(slurm_job_id, slurm_cluster_name, "end");
    return header + R"(,"payload":{"json":)" + json_end_extra + "}}";
}

std::string build_exec_json_output(const std::string& slurm_job_id,
                                   const std::string& slurm_cluster_name,
                                   const std::string& path_exec,
                                   const std::string& json_exec,
                                   const std::string& cmd,
                                   const std::vector<std::string>& events) {
    std::ostringstream event_array;
    event_array << "[";
    bool first = true;
    for (const std::string& event : events) {
        if (!first) event_array << ",";
        /*std::string json_with_pid = event.json;
        size_t header_start = json_with_pid.find(R"("event_header":{)");
        size_t insert_pos = header_start + strlen("\"event_header\":{");
        std::string pid_field = R"("pid":)" + std::to_string(event.pid) +
        ","; json_with_pid.insert(insert_pos, pid_field);*/
        event_array << event;
        first = false;
    }
    event_array << "]";
    std::string absolute_path_exec = std::filesystem::canonical(path_exec);
    std::string header = build_header(slurm_job_id, slurm_cluster_name, "exec");
    std::string json_string = header + R"(,"payload":{"events":)"
                              + event_array.str() + R"(,"json":)" + json_exec
                              + R"(,"path":")" + path_exec + R"(","command":")"
                              + cmd + R"("}})";
    return json_string;
}

enum class Mode { Start, End, Exec };

struct StartOpts {
    bool mpi = false;
    std::string path;
    std::string json = "{}";
};
struct EndOpts {
    bool mpi = false;
    std::string json = "{}";
};
struct ExecOpts {
    std::string command;
    std::string path;
    std::string json = "{}";
};

struct Parsed {
    Mode mode;
    StartOpts start_opts;
    EndOpts end_opts;
    ExecOpts exec_opts;
};

Parsed parse_cli(int argc, char** argv) {
    CLI::App app{"test"};

    auto start = app.add_subcommand("start", "start the service");
    StartOpts start_opts;
    start_opts.path = std::filesystem::current_path().string();
    start->add_flag("--mpi", start_opts.mpi, "Enable MPI mode");
    start->add_option("--path", start_opts.path, "Specify path");
    start->add_option("--json", start_opts.json,
                      "Provide optional extra metadata");

    auto end = app.add_subcommand("end", "Stop service");
    EndOpts end_opts;
    end->add_option("--json", end_opts.json, "Provide optional extra metadata");
    end->add_flag("--mpi", end_opts.mpi, "Enable MPI mode");

    auto exec = app.add_subcommand("exec", "Execute command");
    ExecOpts exec_opts;
    exec_opts.path = std::filesystem::current_path().string();
    exec->add_option("command", exec_opts.command, "Specify Slurm command")
        ->required();
    exec->add_option("--path", exec_opts.path, "Specify path")->required();
    exec->add_option("--json", exec_opts.json,
                     "Provide optional extra metadata");

    app.require_subcommand();
    app.parse(argc, argv);
    Parsed parsed{};
    if (*start) {
        parsed.mode = Mode::Start;
        parsed.start_opts = std::move(start_opts);
    } else if (*end) {
        parsed.mode = Mode::End;
        parsed.end_opts = std::move(end_opts);
    } else {
        parsed.mode = Mode::Exec;
        parsed.exec_opts = std::move(exec_opts);
    }
    return parsed;
}

int main(int argc, char** argv) {
    const std::string endpoint_url = "http://127.0.0.1:9000/log";
    Parsed parsed = parse_cli(argc, argv);
    std::string slurm_job_id
        = std::getenv("SLURM_JOB_ID") ? std::getenv("SLURM_JOB_ID") : "1";
    std::string slurm_cluster_name = std::getenv("SLURM_CLUSTER_NAME")
                                         ? std::getenv("SLURM_CLUSTER_NAME")
                                         : "cname1";
    switch (parsed.mode) {
        case Mode::Start: {
            std::string start_json = build_start_json_output(
                parsed.start_opts.path, slurm_job_id, slurm_cluster_name,
                parsed.start_opts.json);
            send_json(endpoint_url, start_json);
            break;
        }
        case Mode::End: {
            std::string end_json = build_end_json_output(
                slurm_job_id, slurm_cluster_name, parsed.end_opts.json);
            send_json(endpoint_url, end_json);
            break;
        }
        case Mode::Exec: {
            std::string exec_path = parsed.exec_opts.path;
            std::string exec_json_input = parsed.exec_opts.json;
            std::string exec_command = parsed.exec_opts.command;
            std::string absolute_path_exec
                = std::filesystem::canonical(exec_path).string();
            std::string path_access
                = "/dev/shm/prov_" + std::to_string(getpid());
            set_env_variables(absolute_path_exec, path_access);
            std::string injector_path = "./injector/build/libinjector.so";
            start_preload_process(injector_path, exec_command, path_access);
            ProcessedInjectorData processed_injector_data
                = extract_injector_data(path_access);
            std::string exec_json_output = build_exec_json_output(
                slurm_job_id, slurm_cluster_name, absolute_path_exec,
                exec_json_input, exec_command,
                processed_injector_data.process_json_operation_objects);
            send_json(endpoint_url, exec_json_output);
            break;
        }
    }
    return 0;
}
