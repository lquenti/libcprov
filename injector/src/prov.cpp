#include <curl/curl.h>
#include <simdjson.h>
#include <sys/wait.h>
#include <unistd.h>
#include <xxhash.h>

#include <CLI/CLI.hpp>
#include <filesystem>
#include <string>

#include "data_backup.hpp"
#include "get_job_info.hpp"
#include "json_string_builders.hpp"
#include "model.hpp"
#include "parser.hpp"
#include "process_coordinator.hpp"
#include "processor.hpp"

ProcessedInjectorData extract_injector_data(const std::string& path_access) {
    EventsByFile events_by_file = parse_all_jsonl_files(path_access);
    std::filesystem::remove_all(path_access);
    ProcessedInjectorData processed_injector_data
        = process_events(events_by_file);
    return processed_injector_data;
}

enum class Mode { Start, End, Exec };

struct StartOpts {
    bool mpi = false;
    std::string path;
    std::string json = "{}";
};
struct EndOpts {
    std::string json = "{}";
};
struct ExecOpts {
    std::string command;
    std::string path;
    std::string json = "{}";
};

struct Parsed {
    Mode mode;
    std::variant<StartOpts, EndOpts, ExecOpts> opts;
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
        parsed.opts = std::move(start_opts);
    } else if (*end) {
        parsed.mode = Mode::End;
        parsed.opts = std::move(end_opts);
    } else {
        parsed.mode = Mode::Exec;
        parsed.opts = std::move(exec_opts);
    }
    return parsed;
}

int main(int argc, char** argv) {
    const std::string endpoint_url = "http://127.0.0.1:9000/prov_api";
    Parsed parsed = parse_cli(argc, argv);
    std::string job_id = get_job_id();
    std::string cluster_name = get_cluster_name();
    std::string base_path = "/dev/shm/libcprov/";
    std::string path_access = base_path + job_id + cluster_name;
    switch (parsed.mode) {
        case Mode::Start: {
            std::string header
                = build_header("start", path_access, job_id, cluster_name);
            std::filesystem::create_directories(base_path);
            std::filesystem::create_directories(path_access);
            std::filesystem::create_directories(path_access);
            std::string job_name = get_job_name();
            std::string username = get_username();
            StartOpts start_opts = std::get<StartOpts>(parsed.opts);
            std::string start_json = build_start_json_output(
                job_name, username, start_opts.path, start_opts.json);
            send_json(endpoint_url, header, start_json);
            break;
        }
        case Mode::End: {
            std::string header
                = build_header("end", path_access, job_id, cluster_name);
            EndOpts end_opts = std::get<EndOpts>(parsed.opts);
            std::string end_json = build_end_json_output(end_opts.json);
            std::filesystem::remove_all(path_access);
            send_json(endpoint_url, header, end_json);
            break;
        }
        case Mode::Exec: {
            std::string header
                = build_header("exec", path_access, job_id, cluster_name);
            ExecOpts exec_opts = std::get<ExecOpts>(parsed.opts);
            std::string exec_path = exec_opts.path;
            std::string absolute_path_exec
                = std::filesystem::canonical(exec_path).string();
            backup_data_pre_exec(absolute_path_exec);
            std::string exec_json_input = exec_opts.json;
            std::string exec_command = exec_opts.command;
            std::string injector_data_path = path_access;
            set_env_variables(absolute_path_exec, injector_data_path);
            std::string injector_path
                = "/home/hyperion/Documents/uni/ba_thesis/libcprov3/injector/"
                  "build/libinjector.so";
            start_preload_process(injector_path, exec_command,
                                  injector_data_path);
            ProcessedInjectorData processed_injector_data
                = extract_injector_data(injector_data_path);
            ingest_prov_data(
                processed_injector_data.operations_data_backup_format);
            std::string exec_json_output = build_exec_json_output(
                absolute_path_exec, exec_json_input, exec_command,
                std::move(processed_injector_data.processed_exec_data));
            send_json(endpoint_url, header, exec_json_output);
            break;
        }
    }
    return 0;
}
