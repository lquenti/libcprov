#include "processor.hpp"

#include <cstdint>
#include <deque>
#include <string>
#include <utility>
#include <variant>

#include "event_recorder.hpp"
#include "model.hpp"

ProcessedInjectorData process_events(std::deque<Event>& events) {
    EventRecorder event_recorder;
    while (!events.empty()) {
        Event event = std::move(events.front());
        events.pop_front();
        uint64_t pid = event.pid;
        uint64_t ts = event.ts;
        SysOp op = event.operation;
        const EventPayload& payload = event.event_payload;
        event_recorder.set_current_pid(pid);
        switch (op) {
            case SysOp::ProcessStart: {
                const auto& process_start_event
                    = std::get<ProcessStart>(payload);
                event_recorder.set_current_operation("PROCESS_START");
                event_recorder.log_exec("", process_start_event.ppid);
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
                event_recorder.set_current_operation("WRITE");
                event_recorder.log_write(write_event.path_out);
                break;
            }
            case SysOp::Read:
            case SysOp::Readv:
            case SysOp::Pread:
            case SysOp::Preadv: {
                const auto& read_event = std::get<AccessIn>(payload);
                event_recorder.set_current_operation("READ");
                event_recorder.log_read(read_event.path_in);
                break;
            }
            case SysOp::Transfer: {
                const auto& transfer_event = std::get<AccessInOut>(payload);
                event_recorder.set_current_operation("WRITE");
                event_recorder.log_write(transfer_event.path_out);
                event_recorder.set_current_operation("READ");
                event_recorder.log_read(transfer_event.path_in);
                break;
            }
            case SysOp::Rename: {
                const auto& rename_event = std::get<AccessInOut>(payload);
                event_recorder.set_current_operation("RENAME");
                event_recorder.rename(rename_event.path_in,
                                      rename_event.path_out);
                break;
            }
            case SysOp::Link: {
                const auto& link_event = std::get<AccessInOut>(payload);
                event_recorder.set_current_operation("LINK");
                event_recorder.link(link_event.path_in, link_event.path_out);
                break;
            }
            case SysOp::SymLink: {
                const auto& symlink_event = std::get<AccessInOut>(payload);
                event_recorder.set_current_operation("SYMLINK");
                event_recorder.link(symlink_event.path_in,
                                    symlink_event.path_out);
                break;
            }
            case SysOp::Unlink: {
                const auto& unlink_event = std::get<AccessOut>(payload);
                event_recorder.set_current_operation("UNLINK");
                event_recorder.delete_path(unlink_event.path_out);
                break;
            }
            case SysOp::Exec:
            case SysOp::System: {
                const auto& exec_event = std::get<ExecCall>(payload);
                event_recorder.set_current_operation("EXEC");
                event_recorder.log_exec(exec_event.target, 0);
                break;
            }
            case SysOp::Spawn: {
                const auto& spawn_event = std::get<SpawnCall>(payload);
                event_recorder.set_current_operation("SPAWN");
                event_recorder.log_exec(spawn_event.target,
                                        spawn_event.child_pid);
                break;
            }
            case SysOp::Fork: {
                const auto& fork_event = std::get<ForkCall>(payload);
                event_recorder.set_current_operation("FORK");
                event_recorder.log_exec("", fork_event.child_pid);
                break;
            }
            default:
                break;
        }
    }
    return event_recorder.consume_prov_data();
}
