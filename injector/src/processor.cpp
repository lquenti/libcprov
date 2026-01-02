#include "processor.hpp"

#include <algorithm>
#include <cstdint>
#include <string>

#include "event_recorder.hpp"
#include "model.hpp"

void sort_events(std::vector<Event>& events) {
    std::sort(events.begin(), events.end(),
              [](const Event& a, const Event& b) { return a.ts < b.ts; });
}

void set_device_process_id_to_process_hash(EventRecorder& event_recorder,
                                           const std::vector<Event>& events) {
    for (const Event& event : events) {
        SysOp op = event.operation;
        if (op == SysOp::ProcessStart) {
            const ProcessStart& process_start
                = std::get<ProcessStart>(event.event_payload);
            event_recorder.add_device_process_id_to_process_hash(
                event.pid, event.slurmd_nodename, process_start.process_name,
                process_start.env_variables);
        }
    }
}

ProcessedInjectorData process_events(std::vector<Event>& events) {
    sort_events(events);
    EventRecorder event_recorder;
    set_device_process_id_to_process_hash(event_recorder, events);
    bool first_event = true;
    for (const Event& event : events) {
        uint64_t pid = event.pid;
        std::string slurmd_nodename = event.slurmd_nodename;
        uint64_t ts = event.ts;
        SysOp op = event.operation;
        const EventPayload& payload = event.event_payload;
        event_recorder.set_current_process_hash(pid, slurmd_nodename);
        switch (op) {
            case SysOp::ProcessStart: {
                const auto& process_start = std::get<ProcessStart>(payload);
                event_recorder.log_process_start(process_start.process_name,
                                                 process_start.env_variables);
                break;
            }
            case SysOp::ProcessEnd: {
                break;
            }
            case SysOp::Write:
            case SysOp::Writev:
            case SysOp::Pwrite:
            case SysOp::Pwritev:
            case SysOp::Truncate:
            case SysOp::Fallocate: {
                const auto& write_event = std::get<AccessOut>(payload);
                event_recorder.log_write(write_event.path_out);
                break;
            }
            case SysOp::Read:
            case SysOp::Readv:
            case SysOp::Pread:
            case SysOp::Preadv: {
                const auto& read_event = std::get<AccessIn>(payload);
                event_recorder.log_read(read_event.path_in);
                break;
            }
            case SysOp::Transfer: {
                const auto& transfer_event = std::get<AccessInOut>(payload);
                event_recorder.log_write(transfer_event.path_out);
                event_recorder.log_read(transfer_event.path_in);
                break;
            }
            case SysOp::Rename: {
                const auto& rename_event = std::get<AccessInOut>(payload);
                event_recorder.rename(rename_event.path_in,
                                      rename_event.path_out);
                break;
            }
            case SysOp::Link: {
                const auto& link_event = std::get<AccessInOut>(payload);
                event_recorder.link(link_event.path_in, link_event.path_out);
                break;
            }
            case SysOp::SymLink: {
                const auto& symlink_event = std::get<AccessInOut>(payload);
                event_recorder.symlink(symlink_event.path_in,
                                       symlink_event.path_out);
                break;
            }
            case SysOp::Unlink: {
                const auto& unlink_event = std::get<AccessOut>(payload);
                event_recorder.delete_path(unlink_event.path_out);
                break;
            }
            case SysOp::Exec:
            case SysOp::System: {
                const auto& exec_event = std::get<ExecCall>(payload);
                event_recorder.log_exec(exec_event.target, 0, "");
                break;
            }
            case SysOp::Spawn: {
                const auto& spawn_event = std::get<SpawnCall>(payload);
                event_recorder.log_exec(spawn_event.target,
                                        spawn_event.child_pid, slurmd_nodename);
                break;
            }
            case SysOp::Fork: {
                const auto& fork_event = std::get<ForkCall>(payload);
                event_recorder.log_exec("", fork_event.child_pid,
                                        slurmd_nodename);
                break;
            }
            default:
                break;
        }
    }
    return event_recorder.consume_prov_data();
}
