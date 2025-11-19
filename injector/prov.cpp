#include <curl/curl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <CLI/CLI.hpp>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

void send_data_to_preloade(const std::string slurm_job_id,
                           const std::string slurm_cluster_name,
                           const std::string path_exec) {
    std::string data_path
        = "/dev/shm/" + slurm_job_id + slurm_cluster_name + "_input";
    std::ofstream file(data_path);
    file << path_exec;
}

void start_preload_process(const std::string& so_path, const std::string& cmd) {
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

void send_json(const std::string& url, const std::string& json) {
    CURL* curl = curl_easy_init();
    if (!curl) return;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
        +[](void*, size_t s, size_t n, void*) { return s * n; });

    curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}

void send_injector_data(const std::string& slurm_job_id,
                        const std::string& slurm_cluster_name,
                        const std::string& path_exec,
                        const std::string& json_exec, const std::string& cmd,
                        const std::string& url) {
    const std::string basic_path
        = "/dev/shm/" + slurm_job_id + slurm_cluster_name;
    const std::string input_path = basic_path + "_input";
    const std::string injector_data_path = basic_path + "_output.jsonl";
    std::ifstream injector_data_file(injector_data_path);
    std::string json_object;
    std::string event_array = "[";
    bool first = true;
    while (std::getline(injector_data_file, json_object)) {
        if (!first) event_array += ",";
        event_array += json_object;
        first = false;
    }
    event_array += "]";
    std::string json_string = R"({"type":"exec" ,"header":{"slurm_job_id":")"
                              + slurm_job_id + R"(","slurm_cluster_name":")"
                              + slurm_cluster_name
                              + R"("},"payload":{"events":)" + event_array
                              + R"(,"json":)" + json_exec + R"(,"path":")"
                              + path_exec + R"(","command":")" + cmd + R"("}})";
    send_json(url, json_string);
    // std::filesystem::remove(input_path);
    // std::filesystem::remove(injector_data_path);
}

int main(int argc, char** argv) {
    const std::string endpoint_url = "http://127.0.0.1:9000/log";
    //const std::string injector_path = std::filesystem::canonical("./injector.so");
    const std::string injector_path = "./injector/injector.so";

    CLI::App app{"test"};
    auto start = app.add_subcommand("start", "start the service");
    bool mpi_start = false;
    std::string path_start = std::filesystem::current_path();
    std::string json_start = "{}";
    start->add_flag("--mpi", mpi_start, "Enable MPI mode");
    start->add_option("--path", path_start, "Scefify path");
    start->add_option("--json", json_start, "Provide optional extra metadata");
    auto end = app.add_subcommand("end", "Stop service");
    std::string json_end = "{}";
    end->add_option("--json", json_end, "Provide optional extra metadata");
    bool mpi_end = false;
    end->add_flag("--mpi", mpi_end, "Enable MPI mode");
    auto exec = app.add_subcommand("exec", "Execute command");
    std::string command = "";
    std::string path_exec = std::filesystem::current_path();
    std::string json_exec = "{}";
    exec->add_option("command", command, "Specify Slurm command")->required();
    exec->add_option("--path", path_exec, "Spefify path")->required();
    exec->add_option("--json", json_exec, "Provide optional extra metadata");
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
        std::string absolute_path_start = std::filesystem::canonical(path_start);
        std::string start_json = R"({"type":"start","header":{"slurm_job_id":")"
                                 + slurm_job_id + R"(","slurm_cluster_name":")"
                                 + slurm_cluster_name
                                 + R"("},"payload":{"json":)" + json_start
                                 + R"(,"path":")" + absolute_path_start + R"("}})";
        send_json(endpoint_url, start_json);
    } else if (*end) {
        std::string end_json = R"({"type":"end","header":{"slurm_job_id":")"
                               + slurm_job_id + R"(","slurm_cluster_name":")"
                               + slurm_cluster_name + R"("},"payload":{"json":)"
                               + json_end + "}}";
        send_json(endpoint_url, end_json);
    } else if (*exec) {
        std::string absolute_path_exec = std::filesystem::canonical(path_exec);
        send_data_to_preloade(slurm_job_id, slurm_cluster_name, absolute_path_exec);
        start_preload_process(injector_path, command);
        send_injector_data(slurm_job_id, slurm_cluster_name, absolute_path_exec,
                           json_exec, command, endpoint_url);
    }
}
