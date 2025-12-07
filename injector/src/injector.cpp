#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

struct linux_dirent;
struct linux_dirent64;

static const char* endpoint_url = "http://127.0.0.1:9000/log";
#define LOG_STR_MAX 256

static std::string get_env(const char* name) {
    const char* val = std::getenv(name);
    return val ? std::string(val) : std::string();
}
// const std::string slurm_job_id = get_env("SLURM_JOB_ID");
// const std::string slurm_cluster_name = get_env("SLURM_CLUSTER_NAME");
static const std::string slurm_job_id = "1";
static const std::string slurm_cluster_name = "cname1";

static std::string path_exec = get_env("PROV_PATH_EXEC");
// static std::ostringstream aggregated_events_json;
static std::vector<std::string> aggregated_events;
static std::mutex events_mutex;

static std::string now_ns() {
    using namespace std::chrono;
    uint64_t ts
        = duration_cast<nanoseconds>(system_clock::now().time_since_epoch())
              .count();
    std::string ts_string = std::to_string(ts);
    return ts_string;
}

static char** build_argv_from_varargs(const char* first, va_list ap) {
    std::vector<char*> v;
    if (first) v.push_back(const_cast<char*>(first));
    const char* s;
    while ((s = va_arg(ap, const char*)) != nullptr) {
        v.push_back(const_cast<char*>(s));
    }
    v.push_back(nullptr);
    char** argv = (char**)malloc(v.size() * sizeof(char*));
    memcpy(argv, v.data(), v.size() * sizeof(char*));
    return argv;
}

static inline void add_event(const std::string& operation,
                             const std::string& ts,
                             const std::string& event_json) {
    std::lock_guard<std::mutex> guard(events_mutex);
    std::string event = R"({"event_header":{"operation":")" + operation
                        + R"(","ts":)" + ts + R"(},"event_data":)" + event_json
                        + "}\n";
    aggregated_events.push_back(event);
}

static std::string fd_path(const int& fd) {
    char link[64];
    std::snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);

    std::array<char, 256> buf{};
    ssize_t r = ::readlink(link, buf.data(), buf.size() - 1);

    if (r >= 0) {
        buf[r] = '\0';
        return std::string(buf.data());
    } else {
        return "fd=" + std::to_string(fd);
    }
}

static void log_input_event(const std::string operation,
                            const std::string path_in) {
    // if (!path_in.starts_with(path_exec)) return;

    std::string ts = now_ns();
    std::string json = R"({"path_in":")" + path_in + R"("})";
    add_event(operation, ts, json);
}

static void log_output_event(const std::string operation,
                             const std::string path_out) {
    // if (!path_out.starts_with(path_exec)) return;

    std::string ts = now_ns();
    std::string json = R"({"path_out":")" + path_out + R"("})";
    add_event(operation, ts, json);
}

static void log_input_output_event(const std::string operation,
                                   const std::string path_in,
                                   const std::string path_out) {
    // if (!(path_in.starts_with(path_exec)
    //       || path_out.starts_with(path_exec)))
    //     return;

    std::string ts = now_ns();
    std::string json = R"({"path_in":")" + path_in + R"(","path_out":")"
                       + path_out + R"("})";
    add_event(operation, ts, json);
}

static void log_input_event_fd(const std::string operation, int path_in_fd) {
    std::string path_in = fd_path(path_in_fd);
    // if (!path_in.starts_with(path_exec)) return;

    std::string ts = now_ns();
    std::string json = R"({"path_in":")" + path_in + R"("})";
    add_event(operation, ts, json);
}

static void log_output_event_fd(const std::string operation, int path_out_fd) {
    std::string path_out = fd_path(path_out_fd);
    // if (!path_out.starts_with(path_exec)) return;

    std::string ts = now_ns();
    std::string json = R"({"path_out":")" + path_out + R"("})";
    add_event(operation, ts, json);
}

static void log_input_output_event_fd(const std::string operation,
                                      int path_in_fd, int path_out_fd) {
    std::string path_in = fd_path(path_in_fd);
    std::string path_out = fd_path(path_out_fd);

    // if (!(path_in.starts_with(path_exec)
    //       || path_out.starts_with(path_exec)))
    //     return;

    std::string ts = now_ns();
    std::string json = R"({"path_in":")" + path_in + R"(","path_out":")"
                       + path_out + R"("})";
    add_event(operation, ts, json);
}

static void log_fork_event(const std::string operation, pid_t child_pid) {
    std::string ts = now_ns();
    std::string json = R"({"child_pid":)" + std::to_string(child_pid) + R"(})";
    add_event(operation, ts, json);
}

static void log_spawn_event(const std::string operation, pid_t child_pid,
                            const std::string target) {
    // if (!target.starts_with(path_exec)) return;

    std::string ts = now_ns();
    std::string json = R"({"child_pid":)" + std::to_string(child_pid)
                       + R"(,"path":")" + target + R"("})";
    add_event(operation, ts, json);
}

static void log_exec_event(const std::string operation,
                           const std::string target) {
    // if (!target.starts_with(path_exec)) return;

    std::string ts = now_ns();
    std::string json = R"({"path":")" + target + R"("})";
    add_event(operation, ts, json);
}

static void log_exec_fd_event(const std::string operation, int path_target_fd) {
    std::string target_string = fd_path(path_target_fd);
    // if (!target_string.starts_with(path_exec)) return;

    std::string ts = now_ns();
    std::string json = R"({"path":")" + target_string + R"("})";
    add_event(operation, ts, json);
}

static void log_exec_fail_event(const std::string operation,
                                const std::string target, int err) {
    // if (!target.starts_with(path_exec)) return;

    std::string ts = now_ns();
    std::string json = R"({"path":")" + target + R"(","error":)"
                       + std::to_string(err) + R"(})";
    add_event(operation, ts, json);
}

static void log_net_send_event(const std::string& operation, int sockfd,
                               const struct sockaddr* sa, socklen_t salen,
                               unsigned count) {
    std::string ts = now_ns();
    std::string addr_str;
    if (sa && salen > 0) {
        char buf[128] = {0};
        getnameinfo(sa, salen, buf, sizeof(buf), nullptr, 0, NI_NUMERICHOST);
        addr_str = buf;
    }

    std::string json
        = R"({"fd":)" + std::to_string(sockfd) + R"(,"count":)"
          + std::to_string(count)
          + (addr_str.empty() ? "" : R"(,"addr":")" + addr_str + R"(")")
          + R"(})";
    add_event(operation, ts, json);
}

static void log_net_recv_event(const std::string& operation, int sockfd,
                               const struct sockaddr* sa, socklen_t salen,
                               unsigned count) {
    std::string ts = now_ns();
    std::string addr_str;
    if (sa && salen > 0) {
        char buf[128] = {0};
        getnameinfo(sa, salen, buf, sizeof(buf), nullptr, 0, NI_NUMERICHOST);
        addr_str = buf;
    }

    std::string json
        = R"({"fd":)" + std::to_string(sockfd) + R"(,"count":)"
          + std::to_string(count)
          + (addr_str.empty() ? "" : R"(,"addr":")" + addr_str + R"(")")
          + R"(})";
    add_event(operation, ts, json);
}

static void log_process_start() {
    pid_t pid = getpid();
    pid_t ppid = getppid();
    std::string ts = now_ns();
    std::string operation = "PROCESS_START";
    std::string json = R"({"pid":)" + std::to_string(pid) + R"(,"ppid":)"
                       + std::to_string(ppid) + R"(})";
    add_event(operation, ts, json);
}

static void log_process_end() {
    std::string ts = now_ns();
    std::string operation = "PROCESS_END";
    std::string json = "{}";
    add_event(operation, ts, json);
}

static void save_events_clean() {
    std::string all_events;
    size_t total_size = 0;
    for (const auto& event : aggregated_events) {
        total_size += event.size();
    }
    all_events.reserve(total_size);
    for (const auto& event : aggregated_events) {
        all_events.append(event.data(), event.size());
    }
    std::string path_write = get_env("PROV_PATH_WRITE") + "/"
                             + std::to_string(getpid()) + ".jsonl";
    int fd = syscall(SYS_open, path_write.c_str(),
                     O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        syscall(SYS_write, fd, all_events.data(), all_events.size());
        syscall(SYS_close, fd);
    }
}

__attribute__((constructor)) static void preload_init(void) {
    log_process_start();
}

__attribute__((destructor)) static void preload_fini(void) {
    log_process_end();
    save_events_clean();
}

static inline const struct sockaddr* msg_name_sa(const struct msghdr* msg,
                                                 socklen_t* len_out) {
    if (!msg) return nullptr;
    if (len_out) *len_out = msg->msg_namelen;
    return (const struct sockaddr*)msg->msg_name;
}

static inline const struct sockaddr* mmsg0_name_sa(const struct mmsghdr* vec,
                                                   unsigned vlen,
                                                   socklen_t* len_out) {
    if (!vec || vlen == 0) return nullptr;
    if (len_out) *len_out = vec[0].msg_hdr.msg_namelen;
    return (const struct sockaddr*)vec[0].msg_hdr.msg_name;
}

extern "C" {
// ---------- WRITE HOOKS ----------
ssize_t write(int fd, const void* buf, size_t count) {
    static ssize_t (*real_write)(int, const void*, size_t) = nullptr;
    if (!real_write) {
        real_write = (ssize_t (*)(int, const void*, size_t))dlsym(
            RTLD_NEXT, "__libc_write");
        if (!real_write) {
            real_write = (ssize_t (*)(int, const void*, size_t))dlsym(RTLD_NEXT,
                                                                      "write");
        }
        if (!real_write) return -1;
    }
    ssize_t ret = real_write(fd, buf, count);
    int saved_errno = errno;
    log_output_event_fd("WRITE", fd);
    errno = saved_errno;
    return ret;
}

size_t fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream) {
    static size_t (*real_fwrite)(const void*, size_t, size_t, FILE*) = nullptr;
    if (!real_fwrite) {
        real_fwrite = (size_t (*)(const void*, size_t, size_t, FILE*))dlsym(
            RTLD_NEXT, "__libc_fwrite");
        if (!real_fwrite) {
            real_fwrite = (size_t (*)(const void*, size_t, size_t, FILE*))dlsym(
                RTLD_NEXT, "fwrite");
        }
        if (!real_fwrite) return 0;
    }
    size_t ret = real_fwrite(ptr, size, nmemb, stream);
    int saved_errno = errno;
    int fd = stream ? fileno(stream) : -1;
    log_output_event_fd("FWRITE", fd);
    errno = saved_errno;
    return ret;
}

ssize_t writev(int fd, const struct iovec* iov, int iovcnt) {
    static ssize_t (*real_writev)(int, const struct iovec*, int) = nullptr;
    if (!real_writev) {
        real_writev = (ssize_t (*)(int, const struct iovec*, int))dlsym(
            RTLD_NEXT, "__libc_writev");
        if (!real_writev) {
            real_writev = (ssize_t (*)(int, const struct iovec*, int))dlsym(
                RTLD_NEXT, "writev");
        }
        if (!real_writev) return -1;
    }
    ssize_t ret = real_writev(fd, iov, iovcnt);
    int saved_errno = errno;
    log_output_event_fd("WRITEV", fd);
    errno = saved_errno;
    return ret;
}

ssize_t pwrite(int fd, const void* buf, size_t count, off_t offset) {
    static ssize_t (*real_pwrite)(int, const void*, size_t, off_t) = nullptr;
    if (!real_pwrite) {
        real_pwrite = (ssize_t (*)(int, const void*, size_t, off_t))dlsym(
            RTLD_NEXT, "__libc_pwrite");
        if (!real_pwrite) {
            real_pwrite = (ssize_t (*)(int, const void*, size_t, off_t))dlsym(
                RTLD_NEXT, "pwrite");
        }
        if (!real_pwrite) return -1;
    }
    ssize_t ret = real_pwrite(fd, buf, count, offset);
    int saved_errno = errno;
    log_output_event_fd("PWRITE", fd);
    errno = saved_errno;
    return ret;
}

ssize_t pwrite64(int fd, const void* buf, size_t count, off64_t offset) {
    static ssize_t (*real_pwrite64)(int, const void*, size_t, off64_t)
        = nullptr;
    if (!real_pwrite64) {
        real_pwrite64 = (ssize_t (*)(int, const void*, size_t, off64_t))dlsym(
            RTLD_NEXT, "__libc_pwrite64");
        if (!real_pwrite64) {
            real_pwrite64 = (ssize_t (*)(int, const void*, size_t,
                                         off64_t))dlsym(RTLD_NEXT, "pwrite64");
        }
        if (!real_pwrite64) return -1;
    }
    ssize_t ret = real_pwrite64(fd, buf, count, offset);
    int saved_errno = errno;
    log_output_event_fd("PWRITE64", fd);
    errno = saved_errno;
    return ret;
}

int fputs(const char* s, FILE* stream) {
    static int (*real_fputs)(const char*, FILE*) = nullptr;
    if (!real_fputs) {
        real_fputs
            = (int (*)(const char*, FILE*))dlsym(RTLD_NEXT, "__libc_fputs");
        if (!real_fputs) {
            real_fputs = (int (*)(const char*, FILE*))dlsym(RTLD_NEXT, "fputs");
        }
        if (!real_fputs) return -1;
    }
    int ret = real_fputs(s, stream);
    int saved_errno = errno;
    int fd = stream ? fileno(stream) : -1;
    log_output_event_fd("FPUTS", fd);
    errno = saved_errno;
    return ret;
}

int fprintf(FILE* stream, const char* fmt, ...) {
    static int (*real_vfprintf)(FILE*, const char*, va_list) = nullptr;
    if (!real_vfprintf) {
        real_vfprintf = (int (*)(FILE*, const char*, va_list))dlsym(
            RTLD_NEXT, "__libc_vfprintf");
        if (!real_vfprintf) {
            real_vfprintf = (int (*)(FILE*, const char*, va_list))dlsym(
                RTLD_NEXT, "vfprintf");
        }
        if (!real_vfprintf) return -1;
    }
    va_list ap;
    va_start(ap, fmt);
    int ret = real_vfprintf(stream, fmt, ap);
    va_end(ap);
    int saved_errno = errno;
    int fd = stream ? fileno(stream) : -1;
    log_output_event_fd("FPRINTF", fd);
    errno = saved_errno;
    return ret;
}

int vfprintf(FILE* stream, const char* fmt, va_list ap) {
    static int (*real_vfprintf)(FILE*, const char*, va_list) = nullptr;
    if (!real_vfprintf) {
        real_vfprintf = (int (*)(FILE*, const char*, va_list))dlsym(
            RTLD_NEXT, "__libc_vfprintf");
        if (!real_vfprintf) {
            real_vfprintf = (int (*)(FILE*, const char*, va_list))dlsym(
                RTLD_NEXT, "vfprintf");
        }
        if (!real_vfprintf) return -1;
    }
    int ret = real_vfprintf(stream, fmt, ap);
    int saved_errno = errno;
    int fd = stream ? fileno(stream) : -1;
    log_output_event_fd("VFPRINTF", fd);
    errno = saved_errno;
    return ret;
}

int dprintf(int fd, const char* fmt, ...) {
    static int (*real_vdprintf)(int, const char*, va_list) = nullptr;
    if (!real_vdprintf) {
        real_vdprintf = (int (*)(int, const char*, va_list))dlsym(
            RTLD_NEXT, "__libc_vdprintf");
        if (!real_vdprintf) {
            real_vdprintf = (int (*)(int, const char*, va_list))dlsym(
                RTLD_NEXT, "vdprintf");
        }
        if (!real_vdprintf) return -1;
    }
    va_list ap;
    va_start(ap, fmt);
    int ret = real_vdprintf(fd, fmt, ap);
    va_end(ap);
    int saved_errno = errno;
    log_output_event_fd("DPRINTF", fd);
    errno = saved_errno;
    return ret;
}

int vdprintf(int fd, const char* fmt, va_list ap) {
    static int (*real_vdprintf)(int, const char*, va_list) = nullptr;
    if (!real_vdprintf) {
        real_vdprintf = (int (*)(int, const char*, va_list))dlsym(
            RTLD_NEXT, "__libc_vdprintf");
        if (!real_vdprintf) {
            real_vdprintf = (int (*)(int, const char*, va_list))dlsym(
                RTLD_NEXT, "vdprintf");
        }
        if (!real_vdprintf) return -1;
    }
    int ret = real_vdprintf(fd, fmt, ap);
    int saved_errno = errno;
    log_output_event_fd("VDPRINTF", fd);
    errno = saved_errno;
    return ret;
}

int fputc(int c, FILE* stream) {
    static int (*real_fputc)(int, FILE*) = nullptr;
    if (!real_fputc) {
        real_fputc = (int (*)(int, FILE*))dlsym(RTLD_NEXT, "__libc_fputc");
        if (!real_fputc) {
            real_fputc = (int (*)(int, FILE*))dlsym(RTLD_NEXT, "fputc");
        }
        if (!real_fputc) return -1;
    }
    int ret = real_fputc(c, stream);
    int saved_errno = errno;
    int fd = stream ? fileno(stream) : -1;
    log_output_event_fd("FPUTC", fd);
    errno = saved_errno;
    return ret;
}

int fputs_unlocked(const char* s, FILE* stream) {
    static int (*real_fputs_unlocked)(const char*, FILE*) = nullptr;
    if (!real_fputs_unlocked) {
        real_fputs_unlocked = (int (*)(const char*, FILE*))dlsym(
            RTLD_NEXT, "__libc_fputs_unlocked");
        if (!real_fputs_unlocked) {
            real_fputs_unlocked = (int (*)(const char*, FILE*))dlsym(
                RTLD_NEXT, "fputs_unlocked");
        }
        if (!real_fputs_unlocked) return -1;
    }
    int ret = real_fputs_unlocked(s, stream);
    int saved_errno = errno;
    int fd = stream ? fileno(stream) : -1;
    log_output_event_fd("FPUTS_UNLOCKED", fd);
    errno = saved_errno;
    return ret;
}

size_t fwrite_unlocked(const void* ptr, size_t size, size_t nmemb,
                       FILE* stream) {
    static size_t (*real_fwrite_unlocked)(const void*, size_t, size_t, FILE*)
        = nullptr;
    if (!real_fwrite_unlocked) {
        real_fwrite_unlocked
            = (size_t (*)(const void*, size_t, size_t, FILE*))dlsym(
                RTLD_NEXT, "__libc_fwrite_unlocked");
        if (!real_fwrite_unlocked) {
            real_fwrite_unlocked
                = (size_t (*)(const void*, size_t, size_t, FILE*))dlsym(
                    RTLD_NEXT, "fwrite_unlocked");
        }
        if (!real_fwrite_unlocked) return 0;
    }
    size_t ret = real_fwrite_unlocked(ptr, size, nmemb, stream);
    int saved_errno = errno;
    int fd = stream ? fileno(stream) : -1;
    log_output_event_fd("FWRITE_UNLOCKED", fd);
    errno = saved_errno;
    return ret;
}

ssize_t pwritev(int fd, const struct iovec* iov, int iovcnt, off_t offset) {
    static ssize_t (*real_pwritev)(int, const struct iovec*, int, off_t)
        = nullptr;
    if (!real_pwritev) {
        real_pwritev = (ssize_t (*)(int, const struct iovec*, int, off_t))dlsym(
            RTLD_NEXT, "__libc_pwritev");
        if (!real_pwritev) {
            real_pwritev = (ssize_t (*)(int, const struct iovec*, int,
                                        off_t))dlsym(RTLD_NEXT, "pwritev");
        }
        if (!real_pwritev) return -1;
    }
    ssize_t ret = real_pwritev(fd, iov, iovcnt, offset);
    int saved_errno = errno;
    log_output_event_fd("PWRITEV", fd);
    errno = saved_errno;
    return ret;
}

ssize_t pwritev2(int fd, const struct iovec* iov, int iovcnt, off_t offset,
                 int flags) {
    static ssize_t (*real_pwritev2)(int, const struct iovec*, int, off_t, int)
        = nullptr;
    if (!real_pwritev2) {
        real_pwritev2 = (ssize_t (*)(int, const struct iovec*, int, off_t,
                                     int))dlsym(RTLD_NEXT, "__libc_pwritev2");
        if (!real_pwritev2) {
            real_pwritev2 = (ssize_t (*)(int, const struct iovec*, int, off_t,
                                         int))dlsym(RTLD_NEXT, "pwritev2");
        }
        if (!real_pwritev2) return -1;
    }
    ssize_t ret = real_pwritev2(fd, iov, iovcnt, offset, flags);
    int saved_errno = errno;
    log_output_event_fd("PWRITEV2", fd);
    errno = saved_errno;
    return ret;
}

// --------------- SEND HOOKS -----------------
ssize_t sendto(int sockfd, const void* buf, size_t len, int flags,
               const struct sockaddr* dest_addr, socklen_t addrlen) {
    static ssize_t (*real_sendto)(int, const void*, size_t, int,
                                  const struct sockaddr*, socklen_t)
        = nullptr;
    if (!real_sendto) {
        real_sendto = (ssize_t (*)(int, const void*, size_t, int,
                                   const struct sockaddr*,
                                   socklen_t))dlsym(RTLD_NEXT, "__libc_sendto");
        if (!real_sendto) {
            real_sendto = (ssize_t (*)(int, const void*, size_t, int,
                                       const struct sockaddr*,
                                       socklen_t))dlsym(RTLD_NEXT, "sendto");
        }
        if (!real_sendto) return -1;
    }
    ssize_t ret = real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    int saved_errno = errno;
    log_net_send_event("SENDTO", sockfd, dest_addr, addrlen, 1);
    errno = saved_errno;
    return ret;
}

ssize_t sendmsg(int sockfd, const struct msghdr* msg, int flags) {
    static ssize_t (*real_sendmsg)(int, const struct msghdr*, int) = nullptr;
    if (!real_sendmsg) {
        real_sendmsg = (ssize_t (*)(int, const struct msghdr*, int))dlsym(
            RTLD_NEXT, "__libc_sendmsg");
        if (!real_sendmsg) {
            real_sendmsg = (ssize_t (*)(int, const struct msghdr*, int))dlsym(
                RTLD_NEXT, "sendmsg");
        }
        if (!real_sendmsg) return -1;
    }
    ssize_t ret = real_sendmsg(sockfd, msg, flags);
    int saved_errno = errno;
    socklen_t alen = 0;
    const struct sockaddr* sa = msg_name_sa(msg, &alen);
    log_net_send_event("SENDMSG", sockfd, sa, alen, 1);
    errno = saved_errno;
    return ret;
}

int sendmmsg(int sockfd, struct mmsghdr* msgvec, unsigned int vlen, int flags) {
    static int (*real_sendmmsg)(int, struct mmsghdr*, unsigned int, int)
        = nullptr;
    if (!real_sendmmsg) {
        real_sendmmsg = (int (*)(int, struct mmsghdr*, unsigned int, int))dlsym(
            RTLD_NEXT, "__libc_sendmmsg");
        if (!real_sendmmsg) {
            real_sendmmsg = (int (*)(int, struct mmsghdr*, unsigned int,
                                     int))dlsym(RTLD_NEXT, "sendmmsg");
        }
        if (!real_sendmmsg) return -1;
    }
    int ret = real_sendmmsg(sockfd, msgvec, vlen, flags);
    int saved_errno = errno;
    socklen_t alen = 0;
    const struct sockaddr* sa = mmsg0_name_sa(msgvec, vlen, &alen);
    log_net_send_event("SENDMMSG", sockfd, sa, alen, vlen);
    errno = saved_errno;
    return ret;
}

ssize_t sendfile(int out_fd, int in_fd, off_t* offset, size_t count) {
    static ssize_t (*real_sendfile)(int, int, off_t*, size_t) = nullptr;
    if (!real_sendfile) {
        real_sendfile = (ssize_t (*)(int, int, off_t*, size_t))dlsym(
            RTLD_NEXT, "__libc_sendfile");
        if (!real_sendfile) {
            real_sendfile = (ssize_t (*)(int, int, off_t*, size_t))dlsym(
                RTLD_NEXT, "sendfile");
        }
        if (!real_sendfile) return -1;
    }
    ssize_t ret = real_sendfile(out_fd, in_fd, offset, count);
    int saved_errno = errno;
    log_input_output_event_fd("SENDFILE", in_fd, out_fd);
    errno = saved_errno;
    return ret;
}

ssize_t sendfile64(int out_fd, int in_fd, off64_t* offset, size_t count) {
    static ssize_t (*real_sendfile64)(int, int, off64_t*, size_t) = nullptr;
    if (!real_sendfile64) {
        real_sendfile64 = (ssize_t (*)(int, int, off64_t*, size_t))dlsym(
            RTLD_NEXT, "__libc_sendfile64");
        if (!real_sendfile64) {
            real_sendfile64 = (ssize_t (*)(int, int, off64_t*, size_t))dlsym(
                RTLD_NEXT, "sendfile64");
        }
        if (!real_sendfile64) return -1;
    }
    ssize_t ret = real_sendfile64(out_fd, in_fd, offset, count);
    int saved_errno = errno;
    log_input_output_event_fd("SENDFILE64", in_fd, out_fd);
    errno = saved_errno;
    return ret;
}

ssize_t copy_file_range(int fd_in, off64_t* off_in, int fd_out,
                        off64_t* off_out, size_t len, unsigned int flags) {
    static ssize_t (*real_copy_file_range)(int, off64_t*, int, off64_t*, size_t,
                                           unsigned int)
        = nullptr;
    if (!real_copy_file_range) {
        real_copy_file_range = (ssize_t (*)(
            int, off64_t*, int, off64_t*, size_t,
            unsigned int))dlsym(RTLD_NEXT, "__libc_copy_file_range");
        if (!real_copy_file_range) {
            real_copy_file_range = (ssize_t (*)(
                int, off64_t*, int, off64_t*, size_t,
                unsigned int))dlsym(RTLD_NEXT, "copy_file_range");
        }
        if (!real_copy_file_range) return -1;
    }
    ssize_t ret
        = real_copy_file_range(fd_in, off_in, fd_out, off_out, len, flags);
    int saved_errno = errno;
    log_input_output_event_fd("COPY_FILE_RANGE", fd_in, fd_out);
    errno = saved_errno;
    return ret;
}

ssize_t splice(int fd_in, off64_t* off_in, int fd_out, off64_t* off_out,
               size_t len, unsigned int flags) {
    static ssize_t (*real_splice)(int, off64_t*, int, off64_t*, size_t,
                                  unsigned int)
        = nullptr;
    if (!real_splice) {
        real_splice
            = (ssize_t (*)(int, off64_t*, int, off64_t*, size_t,
                           unsigned int))dlsym(RTLD_NEXT, "__libc_splice");
        if (!real_splice) {
            real_splice = (ssize_t (*)(int, off64_t*, int, off64_t*, size_t,
                                       unsigned int))dlsym(RTLD_NEXT, "splice");
        }
        if (!real_splice) return -1;
    }
    ssize_t ret = real_splice(fd_in, off_in, fd_out, off_out, len, flags);
    int saved_errno = errno;
    log_input_output_event_fd("SPLICE", fd_in, fd_out);
    errno = saved_errno;
    return ret;
}

// --------------------- READ HOOKS -----------------------
ssize_t read(int fd, void* buf, size_t count) {
    static ssize_t (*real_read)(int, void*, size_t) = nullptr;
    if (!real_read) {
        real_read
            = (ssize_t (*)(int, void*, size_t))dlsym(RTLD_NEXT, "__libc_read");
        if (!real_read) {
            real_read
                = (ssize_t (*)(int, void*, size_t))dlsym(RTLD_NEXT, "read");
        }
        if (!real_read) return -1;
    }
    ssize_t ret = real_read(fd, buf, count);
    int saved_errno = errno;
    log_input_event_fd("READ", fd);
    errno = saved_errno;
    return ret;
}

ssize_t pread(int fd, void* buf, size_t count, off_t offset) {
    static ssize_t (*real_pread)(int, void*, size_t, off_t) = nullptr;
    if (!real_pread) {
        real_pread = (ssize_t (*)(int, void*, size_t, off_t))dlsym(
            RTLD_NEXT, "__libc_pread");
        if (!real_pread) {
            real_pread = (ssize_t (*)(int, void*, size_t, off_t))dlsym(
                RTLD_NEXT, "pread");
        }
        if (!real_pread) return -1;
    }
    ssize_t ret = real_pread(fd, buf, count, offset);
    int saved_errno = errno;
    log_input_event_fd("PREAD", fd);
    errno = saved_errno;
    return ret;
}

ssize_t pread64(int fd, void* buf, size_t count, off64_t offset) {
    static ssize_t (*real_pread64)(int, void*, size_t, off64_t) = nullptr;
    if (!real_pread64) {
        real_pread64 = (ssize_t (*)(int, void*, size_t, off64_t))dlsym(
            RTLD_NEXT, "__libc_pread64");
        if (!real_pread64) {
            real_pread64 = (ssize_t (*)(int, void*, size_t, off64_t))dlsym(
                RTLD_NEXT, "pread64");
        }
        if (!real_pread64) return -1;
    }
    ssize_t ret = real_pread64(fd, buf, count, offset);
    int saved_errno = errno;
    log_input_event_fd("PREAD64", fd);
    errno = saved_errno;
    return ret;
}

ssize_t readv(int fd, const struct iovec* iov, int iovcnt) {
    static ssize_t (*real_readv)(int, const struct iovec*, int) = nullptr;
    if (!real_readv) {
        real_readv = (ssize_t (*)(int, const struct iovec*, int))dlsym(
            RTLD_NEXT, "__libc_readv");
        if (!real_readv) {
            real_readv = (ssize_t (*)(int, const struct iovec*, int))dlsym(
                RTLD_NEXT, "readv");
        }
        if (!real_readv) return -1;
    }
    ssize_t ret = real_readv(fd, iov, iovcnt);
    int saved_errno = errno;
    log_input_event_fd("READV", fd);
    errno = saved_errno;
    return ret;
}

ssize_t preadv(int fd, const struct iovec* iov, int iovcnt, off_t offset) {
    static ssize_t (*real_preadv)(int, const struct iovec*, int, off_t)
        = nullptr;
    if (!real_preadv) {
        real_preadv = (ssize_t (*)(int, const struct iovec*, int, off_t))dlsym(
            RTLD_NEXT, "__libc_preadv");
        if (!real_preadv) {
            real_preadv = (ssize_t (*)(int, const struct iovec*, int,
                                       off_t))dlsym(RTLD_NEXT, "preadv");
        }
        if (!real_preadv) return -1;
    }
    ssize_t ret = real_preadv(fd, iov, iovcnt, offset);
    int saved_errno = errno;
    log_input_event_fd("PREADV", fd);
    errno = saved_errno;
    return ret;
}

ssize_t preadv2(int fd, const struct iovec* iov, int iovcnt, off_t offset,
                int flags) {
    static ssize_t (*real_preadv2)(int, const struct iovec*, int, off_t, int)
        = nullptr;
    if (!real_preadv2) {
        real_preadv2 = (ssize_t (*)(int, const struct iovec*, int, off_t,
                                    int))dlsym(RTLD_NEXT, "__libc_preadv2");
        if (!real_preadv2) {
            real_preadv2 = (ssize_t (*)(int, const struct iovec*, int, off_t,
                                        int))dlsym(RTLD_NEXT, "preadv2");
        }
        if (!real_preadv2) return -1;
    }
    ssize_t ret = real_preadv2(fd, iov, iovcnt, offset, flags);
    int saved_errno = errno;
    log_input_event_fd("PREADV2", fd);
    errno = saved_errno;
    return ret;
}

ssize_t recvfrom(int sockfd, void* buf, size_t len, int flags,
                 struct sockaddr* src_addr, socklen_t* addrlen) {
    static ssize_t (*real_recvfrom)(int, void*, size_t, int, struct sockaddr*,
                                    socklen_t*)
        = nullptr;
    if (!real_recvfrom) {
        real_recvfrom
            = (ssize_t (*)(int, void*, size_t, int, struct sockaddr*,
                           socklen_t*))dlsym(RTLD_NEXT, "__libc_recvfrom");
        if (!real_recvfrom) {
            real_recvfrom
                = (ssize_t (*)(int, void*, size_t, int, struct sockaddr*,
                               socklen_t*))dlsym(RTLD_NEXT, "recvfrom");
        }
        if (!real_recvfrom) return -1;
    }
    ssize_t ret = real_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    int saved_errno = errno;
    log_net_recv_event("RECVFROM", sockfd, src_addr, (addrlen ? *addrlen : 0),
                       1);
    errno = saved_errno;
    return ret;
}

ssize_t recvmsg(int sockfd, struct msghdr* msg, int flags) {
    static ssize_t (*real_recvmsg)(int, struct msghdr*, int) = nullptr;
    if (!real_recvmsg) {
        real_recvmsg = (ssize_t (*)(int, struct msghdr*, int))dlsym(
            RTLD_NEXT, "__libc_recvmsg");
        if (!real_recvmsg) {
            real_recvmsg = (ssize_t (*)(int, struct msghdr*, int))dlsym(
                RTLD_NEXT, "recvmsg");
        }
        if (!real_recvmsg) return -1;
    }
    ssize_t ret = real_recvmsg(sockfd, msg, flags);
    int saved_errno = errno;
    socklen_t alen = 0;
    const struct sockaddr* sa = msg_name_sa(msg, &alen);
    log_net_recv_event("RECVMSG", sockfd, sa, alen, 1);
    errno = saved_errno;
    return ret;
}

int recvmmsg(int sockfd, struct mmsghdr* msgvec, unsigned int vlen, int flags,
             struct timespec* timeout) {
    static int (*real_recvmmsg)(int, struct mmsghdr*, unsigned int, int,
                                struct timespec*)
        = nullptr;
    if (!real_recvmmsg) {
        real_recvmmsg
            = (int (*)(int, struct mmsghdr*, unsigned int, int,
                       struct timespec*))dlsym(RTLD_NEXT, "__libc_recvmmsg");
        if (!real_recvmmsg) {
            real_recvmmsg
                = (int (*)(int, struct mmsghdr*, unsigned int, int,
                           struct timespec*))dlsym(RTLD_NEXT, "recvmmsg");
        }
        if (!real_recvmmsg) return -1;
    }
    int ret = real_recvmmsg(sockfd, msgvec, vlen, flags, timeout);
    int saved_errno = errno;
    socklen_t alen = 0;
    const struct sockaddr* sa = mmsg0_name_sa(msgvec, vlen, &alen);
    log_net_recv_event("RECVMMSG", sockfd, sa, alen, vlen);
    errno = saved_errno;
    return ret;
}

// Directory reads
int getdents(unsigned int fd, struct linux_dirent* dirp, unsigned int count) {
    static int (*real_getdents)(unsigned int, struct linux_dirent*,
                                unsigned int)
        = nullptr;
    if (!real_getdents) {
        real_getdents
            = (int (*)(unsigned int, struct linux_dirent*, unsigned int))dlsym(
                RTLD_NEXT, "__libc_getdents");
        if (!real_getdents) {
            real_getdents = (int (*)(unsigned int, struct linux_dirent*,
                                     unsigned int))dlsym(RTLD_NEXT, "getdents");
        }
        if (!real_getdents) return -1;
    }
    int ret = real_getdents(fd, dirp, count);
    int saved_errno = errno;
    log_input_event_fd("GETDENTS", (int)fd);
    errno = saved_errno;
    return ret;
}

int getdents64(unsigned int fd, struct linux_dirent64* dirp,
               unsigned int count) {
    static int (*real_getdents64)(unsigned int, struct linux_dirent64*,
                                  unsigned int)
        = nullptr;
    if (!real_getdents64) {
        real_getdents64
            = (int (*)(unsigned int, struct linux_dirent64*,
                       unsigned int))dlsym(RTLD_NEXT, "__libc_getdents64");
        if (!real_getdents64) {
            real_getdents64
                = (int (*)(unsigned int, struct linux_dirent64*,
                           unsigned int))dlsym(RTLD_NEXT, "getdents64");
        }
        if (!real_getdents64) return -1;
    }
    int ret = real_getdents64(fd, dirp, count);
    int saved_errno = errno;
    log_input_event_fd("GETDENTS64", (int)fd);
    errno = saved_errno;
    return ret;
}

// --------------------- EXEC HOOKS -----------------------
int execve(const char* pathname, char* const argv[], char* const envp[]) {
    static int (*real_execve)(const char*, char* const[], char* const[])
        = nullptr;
    if (!real_execve) {
        real_execve = (int (*)(const char*, char* const[], char* const[]))dlsym(
            RTLD_NEXT, "__libc_execve");
        if (!real_execve) {
            real_execve = (int (*)(const char*, char* const[],
                                   char* const[]))dlsym(RTLD_NEXT, "execve");
        }
        if (!real_execve) return -1;
    }
    log_exec_event("EXECVE", pathname ? pathname : "");
    int rc = real_execve(pathname, argv, envp);
    if (rc < 0)
        log_exec_fail_event("EXECVE_FAIL", pathname ? pathname : "", errno);
    return rc;
}

int execveat(int dirfd, const char* pathname, char* const argv[],
             char* const envp[], int flags) {
    static int (*real_execveat)(int, const char*, char* const[], char* const[],
                                int)
        = nullptr;
    if (!real_execveat) {
        real_execveat = (int (*)(int, const char*, char* const[], char* const[],
                                 int))dlsym(RTLD_NEXT, "__libc_execveat");
        if (!real_execveat) {
            real_execveat
                = (int (*)(int, const char*, char* const[], char* const[],
                           int))dlsym(RTLD_NEXT, "execveat");
        }
        if (!real_execveat) return -1;
    }
    log_exec_event("EXECVEAT", pathname ? pathname : "");
    int rc = real_execveat(dirfd, pathname, argv, envp, flags);
    if (rc < 0)
        log_exec_fail_event("EXECVEAT_FAIL", pathname ? pathname : "", errno);
    return rc;
}

int fexecve(int fd, char* const argv[], char* const envp[]) {
    static int (*real_fexecve)(int, char* const[], char* const[]) = nullptr;
    if (!real_fexecve) {
        real_fexecve = (int (*)(int, char* const[], char* const[]))dlsym(
            RTLD_NEXT, "__libc_fexecve");
        if (!real_fexecve) {
            real_fexecve = (int (*)(int, char* const[], char* const[]))dlsym(
                RTLD_NEXT, "fexecve");
        }
        if (!real_fexecve) return -1;
    }
    log_exec_fd_event("FEXECVE", fd);
    int rc = real_fexecve(fd, argv, envp);
    if (rc < 0) log_exec_fail_event("FEXECVE_FAIL", fd_path(fd), errno);
    return rc;
}

int execv(const char* path, char* const argv[]) {
    static int (*real_execv)(const char*, char* const[]) = nullptr;
    if (!real_execv) {
        real_execv = (int (*)(const char*, char* const[]))dlsym(RTLD_NEXT,
                                                                "__libc_execv");
        if (!real_execv) {
            real_execv = (int (*)(const char*, char* const[]))dlsym(RTLD_NEXT,
                                                                    "execv");
        }
        if (!real_execv) return -1;
    }
    log_exec_event("EXECV", path ? path : "");
    int rc = real_execv(path, argv);
    if (rc < 0) log_exec_fail_event("EXECV_FAIL", path ? path : "", errno);
    return rc;
}

int execvp(const char* file, char* const argv[]) {
    static int (*real_execvp)(const char*, char* const[]) = nullptr;
    if (!real_execvp) {
        real_execvp = (int (*)(const char*, char* const[]))dlsym(
            RTLD_NEXT, "__libc_execvp");
        if (!real_execvp) {
            real_execvp = (int (*)(const char*, char* const[]))dlsym(RTLD_NEXT,
                                                                     "execvp");
        }
        if (!real_execvp) return -1;
    }
    log_exec_event("EXECPVP", file ? file : "");
    int rc = real_execvp(file, argv);
    if (rc < 0) log_exec_fail_event("EXECPVP_FAIL", file ? file : "", errno);
    return rc;
}

int execvpe(const char* file, char* const argv[], char* const envp[]) {
    static int (*real_execvpe)(const char*, char* const[], char* const[])
        = nullptr;
    if (!real_execvpe) {
        real_execvpe
            = (int (*)(const char*, char* const[], char* const[]))dlsym(
                RTLD_NEXT, "__libc_execvpe");
        if (!real_execvpe) {
            real_execvpe = (int (*)(const char*, char* const[],
                                    char* const[]))dlsym(RTLD_NEXT, "execvpe");
        }
        if (!real_execvpe) return -1;
    }
    log_exec_event("EXECPVE", file ? file : "");
    int rc = real_execvpe(file, argv, envp);
    if (rc < 0) log_exec_fail_event("EXECPVE_FAIL", file ? file : "", errno);
    return rc;
}

int execl(const char* path, const char* arg, ...) {
    static int (*real_execv)(const char*, char* const[]) = nullptr;
    if (!real_execv) {
        real_execv = (int (*)(const char*, char* const[]))dlsym(RTLD_NEXT,
                                                                "__libc_execv");
        if (!real_execv) {
            real_execv = (int (*)(const char*, char* const[]))dlsym(RTLD_NEXT,
                                                                    "execv");
        }
        if (!real_execv) return -1;
    }
    log_exec_event("EXECL", path ? path : "");
    va_list ap;
    va_start(ap, arg);
    char** argv = build_argv_from_varargs(arg, ap);
    va_end(ap);
    if (!argv) {
        errno = ENOMEM;
        return -1;
    }
    int rc = real_execv(path, argv);
    if (rc < 0) log_exec_fail_event("EXECL_FAIL", path ? path : "", errno);
    free(argv);
    return rc;
}

int execlp(const char* file, const char* arg, ...) {
    static int (*real_execvp)(const char*, char* const[]) = nullptr;
    if (!real_execvp) {
        real_execvp = (int (*)(const char*, char* const[]))dlsym(
            RTLD_NEXT, "__libc_execvp");
        if (!real_execvp) {
            real_execvp = (int (*)(const char*, char* const[]))dlsym(RTLD_NEXT,
                                                                     "execvp");
        }
        if (!real_execvp) return -1;
    }
    log_exec_event("EXECLP", file ? file : "");
    va_list ap;
    va_start(ap, arg);
    char** argv = build_argv_from_varargs(arg, ap);
    va_end(ap);
    if (!argv) {
        errno = ENOMEM;
        return -1;
    }
    int rc = real_execvp(file, argv);
    if (rc < 0) log_exec_fail_event("EXECLP_FAIL", file ? file : "", errno);
    free(argv);
    return rc;
}

int execle(const char* path, const char* arg, ...) {
    static int (*real_execve)(const char*, char* const[], char* const[])
        = nullptr;
    if (!real_execve) {
        real_execve = (int (*)(const char*, char* const[], char* const[]))dlsym(
            RTLD_NEXT, "__libc_execve");
        if (!real_execve) {
            real_execve = (int (*)(const char*, char* const[],
                                   char* const[]))dlsym(RTLD_NEXT, "execve");
        }
        if (!real_execve) return -1;
    }
    log_exec_event("EXECLE", path ? path : "");
    va_list ap;
    va_start(ap, arg);
    char** argv = build_argv_from_varargs(arg, ap);
    char* const* envp = va_arg(ap, char* const*);
    va_end(ap);
    if (!argv) {
        errno = ENOMEM;
        return -1;
    }
    int rc = real_execve(path, argv, (char* const*)envp);
    if (rc < 0) log_exec_fail_event("EXECLE_FAIL", path ? path : "", errno);
    free(argv);
    return rc;
}

int posix_spawn(pid_t* pid, const char* path,
                const posix_spawn_file_actions_t* file_actions,
                const posix_spawnattr_t* attrp, char* const argv[],
                char* const envp[]) {
    static int (*real_posix_spawn)(
        pid_t*, const char*, const posix_spawn_file_actions_t*,
        const posix_spawnattr_t*, char* const[], char* const[])
        = nullptr;
    if (!real_posix_spawn) {
        real_posix_spawn
            = (int (*)(pid_t*, const char*, const posix_spawn_file_actions_t*,
                       const posix_spawnattr_t*, char* const[],
                       char* const[]))dlsym(RTLD_NEXT, "__libc_posix_spawn");
        if (!real_posix_spawn) {
            real_posix_spawn = (int (*)(
                pid_t*, const char*, const posix_spawn_file_actions_t*,
                const posix_spawnattr_t*, char* const[],
                char* const[]))dlsym(RTLD_NEXT, "posix_spawn");
        }
        if (!real_posix_spawn) return -1;
    }
    int rc = real_posix_spawn(pid, path, file_actions, attrp, argv, envp);
    int saved_errno = errno;
    if (rc == 0 && pid) log_spawn_event("POSIX_SPAWN", *pid, path ? path : "");
    errno = saved_errno;
    return rc;
}

int posix_spawnp(pid_t* pid, const char* file,
                 const posix_spawn_file_actions_t* file_actions,
                 const posix_spawnattr_t* attrp, char* const argv[],
                 char* const envp[]) {
    static int (*real_posix_spawnp)(
        pid_t*, const char*, const posix_spawn_file_actions_t*,
        const posix_spawnattr_t*, char* const[], char* const[])
        = nullptr;
    if (!real_posix_spawnp) {
        real_posix_spawnp
            = (int (*)(pid_t*, const char*, const posix_spawn_file_actions_t*,
                       const posix_spawnattr_t*, char* const[],
                       char* const[]))dlsym(RTLD_NEXT, "__libc_posix_spawnp");
        if (!real_posix_spawnp) {
            real_posix_spawnp = (int (*)(
                pid_t*, const char*, const posix_spawn_file_actions_t*,
                const posix_spawnattr_t*, char* const[],
                char* const[]))dlsym(RTLD_NEXT, "posix_spawnp");
        }
        if (!real_posix_spawnp) return -1;
    }
    int rc = real_posix_spawnp(pid, file, file_actions, attrp, argv, envp);
    int saved_errno = errno;
    if (rc == 0 && pid) log_spawn_event("POSIX_SPAWNP", *pid, file ? file : "");
    errno = saved_errno;
    return rc;
}

int system(const char* command) {
    static int (*real_system)(const char*) = nullptr;
    if (!real_system) {
        real_system = (int (*)(const char*))dlsym(RTLD_NEXT, "__libc_system");
        if (!real_system) {
            real_system = (int (*)(const char*))dlsym(RTLD_NEXT, "system");
        }
        if (!real_system) return -1;
    }
    log_input_event("SYSTEM", command ? command : "");
    return real_system(command);
}

pid_t fork(void) {
    static pid_t (*real)(void) = nullptr;
    if (!real) {
        real = (pid_t (*)(void))dlsym(RTLD_NEXT, "__libc_fork");
        if (!real) {
            real = (pid_t (*)(void))dlsym(RTLD_NEXT, "fork");
        }
        if (!real) return -1;
    }
    pid_t cpid = real();
    if (cpid > 0) {
        int saved_errno = errno;
        log_fork_event("FORK", cpid);
        errno = saved_errno;
    }
    return cpid;
}

pid_t vfork(void) {
    static pid_t (*real)(void) = nullptr;
    if (!real) {
        real = (pid_t (*)(void))dlsym(RTLD_NEXT, "__libc_vfork");
        if (!real) {
            real = (pid_t (*)(void))dlsym(RTLD_NEXT, "vfork");
        }
        if (!real) return -1;
    }
    pid_t cpid = real();
    if (cpid > 0) {
        int saved_errno = errno;
        log_fork_event("VFORK", cpid);
        errno = saved_errno;
    }
    return cpid;
}

// --------------------- RENAME HOOKS -----------------------
int rename(const char* oldpath, const char* newpath) {
    static int (*real_rename)(const char*, const char*) = nullptr;
    if (!real_rename) {
        real_rename = (int (*)(const char*, const char*))dlsym(RTLD_NEXT,
                                                               "__libc_rename");
        if (!real_rename) {
            real_rename
                = (int (*)(const char*, const char*))dlsym(RTLD_NEXT, "rename");
        }
        if (!real_rename) return -1;
    }
    int rc = real_rename(oldpath, newpath);
    int saved_errno = errno;
    log_input_output_event("RENAME", oldpath ? oldpath : "",
                           newpath ? newpath : "");
    errno = saved_errno;
    return rc;
}

int renameat(int olddirfd, const char* oldpath, int newdirfd,
             const char* newpath) {
    static int (*real_renameat)(int, const char*, int, const char*) = nullptr;
    if (!real_renameat) {
        real_renameat = (int (*)(int, const char*, int, const char*))dlsym(
            RTLD_NEXT, "__libc_renameat");
        if (!real_renameat) {
            real_renameat = (int (*)(int, const char*, int, const char*))dlsym(
                RTLD_NEXT, "renameat");
        }
        if (!real_renameat) return -1;
    }
    int rc = real_renameat(olddirfd, oldpath, newdirfd, newpath);
    int saved_errno = errno;
    log_input_output_event("RENAMEAT", oldpath ? oldpath : "",
                           newpath ? newpath : "");
    errno = saved_errno;
    return rc;
}

int renameat2(int olddirfd, const char* oldpath, int newdirfd,
              const char* newpath, unsigned int flags) {
    static int (*real_renameat2)(int, const char*, int, const char*,
                                 unsigned int)
        = nullptr;
    if (!real_renameat2) {
        real_renameat2
            = (int (*)(int, const char*, int, const char*, unsigned int))dlsym(
                RTLD_NEXT, "__libc_renameat2");
        if (!real_renameat2) {
            real_renameat2
                = (int (*)(int, const char*, int, const char*,
                           unsigned int))dlsym(RTLD_NEXT, "renameat2");
        }
        if (!real_renameat2) return -1;
    }
    int rc = real_renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
    int saved_errno = errno;
    log_input_output_event("RENAMEAT2", oldpath ? oldpath : "",
                           newpath ? newpath : "");
    errno = saved_errno;
    return rc;
}

// clone: minimal logging (no specialized helper yet)
int clone(int (*fn)(void*), void* stack, int flags, void* arg, ...) {
    static int (*real)(int (*)(void*), void*, int, void*, ...) = nullptr;
    if (!real) {
        real = (int (*)(int (*)(void*), void*, int, void*, ...))dlsym(
            RTLD_NEXT, "__libc_clone");
        if (!real) {
            real = (int (*)(int (*)(void*), void*, int, void*, ...))dlsym(
                RTLD_NEXT, "clone");
        }
        if (!real) return -1;
    }
    log_output_event("CLONE", "");
    va_list ap;
    va_start(ap, arg);
    void* ptid = va_arg(ap, void*);
    void* tls = va_arg(ap, void*);
    void* ctid = va_arg(ap, void*);
    va_end(ap);
    return real(fn, stack, flags, arg, ptid, tls, ctid);
}

void exit(int status) {
    static void (*real)(int) = nullptr;
    if (!real) {
        real = (void (*)(int))dlsym(RTLD_NEXT, "exit");
    }
    log_output_event("EXIT", "");
    if (real) {
        real(status);
        __builtin_unreachable();
    }
    syscall(SYS_exit_group, status);
    __builtin_unreachable();
}

void _exit(int status) {
    static void (*real)(int) = nullptr;
    if (!real) {
        real = (void (*)(int))dlsym(RTLD_NEXT, "_exit");
    }
    log_output_event("_EXIT", "");
    if (real) {
        real(status);
        __builtin_unreachable();
    }
    syscall(SYS_exit, status);
    __builtin_unreachable();
}

void _Exit(int status) {
    static void (*real)(int) = nullptr;
    if (!real) {
        real = (void (*)(int))dlsym(RTLD_NEXT, "_Exit");
    }
    log_output_event("_Exit", "");
    if (real) {
        real(status);
        __builtin_unreachable();
    }
    syscall(SYS_exit, status);
    __builtin_unreachable();
}

// --------------------- OPEN/CLOSE/DUP/PIPE HOOKS ------------------
int open(const char* pathname, int flags, ...) {
    static int (*real)(const char*, int, ...) = nullptr;
    if (!real) {
        real = (int (*)(const char*, int, ...))dlsym(RTLD_NEXT, "__libc_open");
        if (!real) {
            real = (int (*)(const char*, int, ...))dlsym(RTLD_NEXT, "open");
        }
        if (!real) return -1;
    }
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    int fd = real(pathname, flags, mode);
    int saved = errno;
    log_output_event("OPEN", pathname ? pathname : "");
    errno = saved;
    return fd;
}

int open64(const char* pathname, int flags, ...) {
    static int (*real)(const char*, int, ...) = nullptr;
    if (!real) {
        real
            = (int (*)(const char*, int, ...))dlsym(RTLD_NEXT, "__libc_open64");
        if (!real) {
            real = (int (*)(const char*, int, ...))dlsym(RTLD_NEXT, "open64");
        }
        if (!real) return -1;
    }
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    int fd = real(pathname, flags, mode);
    int saved = errno;
    log_output_event("OPEN64", pathname ? pathname : "");
    errno = saved;
    return fd;
}

int creat(const char* pathname, mode_t mode) {
    static int (*real)(const char*, mode_t) = nullptr;
    if (!real) {
        real = (int (*)(const char*, mode_t))dlsym(RTLD_NEXT, "__libc_creat");
        if (!real) {
            real = (int (*)(const char*, mode_t))dlsym(RTLD_NEXT, "creat");
        }
        if (!real) return -1;
    }
    int fd = real(pathname, mode);
    int saved = errno;
    log_output_event("CREAT", pathname ? pathname : "");
    errno = saved;
    return fd;
}

int openat(int dirfd, const char* pathname, int flags, ...) {
    static int (*real)(int, const char*, int, ...) = nullptr;
    if (!real) {
        real = (int (*)(int, const char*, int, ...))dlsym(RTLD_NEXT,
                                                          "__libc_openat");
        if (!real) {
            real = (int (*)(int, const char*, int, ...))dlsym(RTLD_NEXT,
                                                              "openat");
        }
        if (!real) return -1;
    }
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    int fd = real(dirfd, pathname, flags, mode);
    int saved = errno;
    log_output_event("OPENAT", pathname ? pathname : "");
    errno = saved;
    return fd;
}

int openat2(int dirfd, const char* pathname, void* how, size_t size) {
    static int (*real)(int, const char*, void*, size_t) = nullptr;
    if (!real) {
        real = (int (*)(int, const char*, void*, size_t))dlsym(
            RTLD_NEXT, "__libc_openat2");
        if (!real) {
            real = (int (*)(int, const char*, void*, size_t))dlsym(RTLD_NEXT,
                                                                   "openat2");
        }
        if (!real) return -1;
    }
    int fd = real(dirfd, pathname, how, size);
    int saved = errno;
    log_output_event("OPENAT2", pathname ? pathname : "");
    errno = saved;
    return fd;
}

int close(int fd) {
    static int (*real)(int) = nullptr;
    if (!real) {
        real = (int (*)(int))dlsym(RTLD_NEXT, "__libc_close");
        if (!real) {
            real = (int (*)(int))dlsym(RTLD_NEXT, "close");
        }
        if (!real) return -1;
    }
    std::string in = fd_path(fd);
    const char* in_c = in.c_str();
    int rc = real(fd);
    int saved = errno;
    log_input_event("CLOSE", in);
    errno = saved;
    return rc;
}

int close_range(unsigned int first, unsigned int last, int flags) {
    static int (*real)(unsigned int, unsigned int, int) = nullptr;
    if (!real) {
        real = (int (*)(unsigned int, unsigned int, int))dlsym(
            RTLD_NEXT, "__libc_close_range");
        if (!real) {
            real = (int (*)(unsigned int, unsigned int, int))dlsym(
                RTLD_NEXT, "close_range");
        }
        if (!real) return -1;
    }
    int rc = real(first, last, flags);
    int saved = errno;
    log_output_event("CLOSE_RANGE", "");
    errno = saved;
    return rc;
}

int fclose(FILE* stream) {
    static int (*real)(FILE*) = nullptr;
    if (!real) {
        real = (int (*)(FILE*))dlsym(RTLD_NEXT, "__libc_fclose");
        if (!real) {
            real = (int (*)(FILE*))dlsym(RTLD_NEXT, "fclose");
        }
        if (!real) return -1;
    }
    int fd = stream ? fileno(stream) : -1;
    std::string in = fd_path(fd);
    const char* in_c = in.c_str();
    int rc = real(stream);
    int saved = errno;
    log_input_event("FCLOSE", in);
    errno = saved;
    return rc;
}

int pipe(int pipefd[2]) {
    static int (*real)(int[2]) = nullptr;
    if (!real) {
        real = (int (*)(int[2]))dlsym(RTLD_NEXT, "__libc_pipe");
        if (!real) {
            real = (int (*)(int[2]))dlsym(RTLD_NEXT, "pipe");
        }
        if (!real) return -1;
    }
    int rc = real(pipefd);
    int saved = errno;
    if (rc == 0) log_input_output_event_fd("PIPE", pipefd[0], pipefd[1]);
    errno = saved;
    return rc;
}

int pipe2(int pipefd[2], int flags) {
    static int (*real)(int[2], int) = nullptr;
    if (!real) {
        real = (int (*)(int[2], int))dlsym(RTLD_NEXT, "__libc_pipe2");
        if (!real) {
            real = (int (*)(int[2], int))dlsym(RTLD_NEXT, "pipe2");
        }
        if (!real) return -1;
    }
    int rc = real(pipefd, flags);
    int saved = errno;
    if (rc == 0) log_input_output_event_fd("PIPE2", pipefd[0], pipefd[1]);
    errno = saved;
    return rc;
}

int dup(int oldfd) {
    static int (*real)(int) = nullptr;
    if (!real) {
        real = (int (*)(int))dlsym(RTLD_NEXT, "__libc_dup");
        if (!real) {
            real = (int (*)(int))dlsym(RTLD_NEXT, "dup");
        }
        if (!real) return -1;
    }
    int newfd = real(oldfd);
    int saved = errno;
    log_input_output_event_fd("DUP", oldfd, newfd);
    errno = saved;
    return newfd;
}

int dup2(int oldfd, int newfd) {
    static int (*real)(int, int) = nullptr;
    if (!real) {
        real = (int (*)(int, int))dlsym(RTLD_NEXT, "__libc_dup2");
        if (!real) {
            real = (int (*)(int, int))dlsym(RTLD_NEXT, "dup2");
        }
        if (!real) return -1;
    }
    int rc = real(oldfd, newfd);
    int saved = errno;
    log_input_output_event_fd("DUP2", oldfd, rc >= 0 ? rc : newfd);
    errno = saved;
    return rc;
}

int dup3(int oldfd, int newfd, int flags) {
    static int (*real)(int, int, int) = nullptr;
    if (!real) {
        real = (int (*)(int, int, int))dlsym(RTLD_NEXT, "__libc_dup3");
        if (!real) {
            real = (int (*)(int, int, int))dlsym(RTLD_NEXT, "dup3");
        }
        if (!real) return -1;
    }
    int rc = real(oldfd, newfd, flags);
    int saved = errno;
    log_input_output_event_fd("DUP3", oldfd, rc >= 0 ? rc : newfd);
    errno = saved;
    return rc;
}

// ------------------- MMAP/MUNMAP/MSYNC HOOKS ----------------
void* mmap(void* addr, size_t length, int prot, int flags, int fd,
           off_t offset) {
    static void* (*real)(void*, size_t, int, int, int, off_t) = nullptr;
    if (!real) {
        real = (void* (*)(void*, size_t, int, int, int, off_t))dlsym(
            RTLD_NEXT, "__libc_mmap");
        if (!real) {
            real = (void* (*)(void*, size_t, int, int, int, off_t))dlsym(
                RTLD_NEXT, "mmap");
        }
        if (!real) return MAP_FAILED;
    }
    void* ret = real(addr, length, prot, flags, fd, offset);
    int saved = errno;
    log_input_event_fd("MMAP", fd);
    errno = saved;
    return ret;
}

void* mmap64(void* addr, size_t length, int prot, int flags, int fd,
             off64_t offset) {
    static void* (*real)(void*, size_t, int, int, int, off64_t) = nullptr;
    if (!real) {
        real = (void* (*)(void*, size_t, int, int, int, off64_t))dlsym(
            RTLD_NEXT, "__libc_mmap64");
        if (!real) {
            real = (void* (*)(void*, size_t, int, int, int, off64_t))dlsym(
                RTLD_NEXT, "mmap64");
        }
        if (!real) return MAP_FAILED;
    }
    void* ret = real(addr, length, prot, flags, fd, offset);
    int saved = errno;
    log_input_event_fd("MMAP64", fd);
    errno = saved;
    return ret;
}

int munmap(void* addr, size_t length) {
    static int (*real)(void*, size_t) = nullptr;
    if (!real) {
        real = (int (*)(void*, size_t))dlsym(RTLD_NEXT, "__libc_munmap");
        if (!real) {
            real = (int (*)(void*, size_t))dlsym(RTLD_NEXT, "munmap");
        }
        if (!real) return -1;
    }
    int rc = real(addr, length);
    int saved = errno;
    log_input_event("MUNMAP", "");
    errno = saved;
    return rc;
}

int msync(void* addr, size_t length, int flags) {
    static int (*real)(void*, size_t, int) = nullptr;
    if (!real) {
        real = (int (*)(void*, size_t, int))dlsym(RTLD_NEXT, "__libc_msync");
        if (!real) {
            real = (int (*)(void*, size_t, int))dlsym(RTLD_NEXT, "msync");
        }
        if (!real) return -1;
    }
    int rc = real(addr, length, flags);
    int saved = errno;
    log_input_event("MSYNC", "");
    errno = saved;
    return rc;
}

// ------------------- SIZE/SPACE METADATA HOOKS ----------------
int ftruncate(int fd, off_t length) {
    static int (*real)(int, off_t) = nullptr;
    if (!real) {
        real = (int (*)(int, off_t))dlsym(RTLD_NEXT, "__libc_ftruncate");
        if (!real) {
            real = (int (*)(int, off_t))dlsym(RTLD_NEXT, "ftruncate");
        }
        if (!real) return -1;
    }
    int rc = real(fd, length);
    int saved = errno;
    log_output_event_fd("FTRUNCATE", fd);
    errno = saved;
    return rc;
}

int truncate(const char* path, off_t length) {
    static int (*real)(const char*, off_t) = nullptr;
    if (!real) {
        real = (int (*)(const char*, off_t))dlsym(RTLD_NEXT, "__libc_truncate");
        if (!real) {
            real = (int (*)(const char*, off_t))dlsym(RTLD_NEXT, "truncate");
        }
        if (!real) return -1;
    }
    int rc = real(path, length);
    int saved = errno;
    log_output_event("TRUNCATE", path ? path : "");
    errno = saved;
    return rc;
}

int posix_fadvise(int fd, off_t offset, off_t len, int advice) {
    static int (*real)(int, off_t, off_t, int) = nullptr;
    if (!real) {
        real = (int (*)(int, off_t, off_t, int))dlsym(RTLD_NEXT,
                                                      "__libc_posix_fadvise");
        if (!real) {
            real = (int (*)(int, off_t, off_t, int))dlsym(RTLD_NEXT,
                                                          "posix_fadvise");
        }
        if (!real) return -1;
    }
    int rc = real(fd, offset, len, advice);
    int saved = errno;
    log_output_event_fd("POSIX_FADVISE", fd);
    errno = saved;
    return rc;
}

int posix_fallocate(int fd, off_t offset, off_t len) {
    static int (*real)(int, off_t, off_t) = nullptr;
    if (!real) {
        real = (int (*)(int, off_t, off_t))dlsym(RTLD_NEXT,
                                                 "__libc_posix_fallocate");
        if (!real) {
            real = (int (*)(int, off_t, off_t))dlsym(RTLD_NEXT,
                                                     "posix_fallocate");
        }
        if (!real) return -1;
    }
    int rc = real(fd, offset, len);
    int saved = errno;
    log_output_event_fd("POSIX_FALLOCATE", fd);
    errno = saved;
    return rc;
}

//--------------- METADATA HOOKS -------------------------
int link(const char* oldpath, const char* newpath) {
    static int (*real)(const char*, const char*) = nullptr;
    if (!real) {
        real = (int (*)(const char*, const char*))dlsym(RTLD_NEXT,
                                                        "__libc_link");
        if (!real) {
            real = (int (*)(const char*, const char*))dlsym(RTLD_NEXT, "link");
        }
        if (!real) return -1;
    }
    int rc = real(oldpath, newpath);
    int saved_errno = errno;
    log_input_output_event("LINK", oldpath ? oldpath : "",
                           newpath ? newpath : "");
    errno = saved_errno;
    return rc;
}

int linkat(int olddirfd, const char* oldpath, int newdirfd, const char* newpath,
           int flags) {
    static int (*real)(int, const char*, int, const char*, int) = nullptr;
    if (!real) {
        real = (int (*)(int, const char*, int, const char*, int))dlsym(
            RTLD_NEXT, "__libc_linkat");
        if (!real) {
            real = (int (*)(int, const char*, int, const char*, int))dlsym(
                RTLD_NEXT, "linkat");
        }
        if (!real) return -1;
    }
    int rc = real(olddirfd, oldpath, newdirfd, newpath, flags);
    int saved_errno = errno;
    log_input_output_event("LINKAT", oldpath ? oldpath : "",
                           newpath ? newpath : "");
    errno = saved_errno;
    return rc;
}

int symlink(const char* target, const char* linkpath) {
    static int (*real)(const char*, const char*) = nullptr;
    if (!real) {
        real = (int (*)(const char*, const char*))dlsym(RTLD_NEXT,
                                                        "__libc_symlink");
        if (!real) {
            real = (int (*)(const char*, const char*))dlsym(RTLD_NEXT,
                                                            "symlink");
        }
        if (!real) return -1;
    }
    int rc = real(target, linkpath);
    int saved_errno = errno;
    log_input_output_event("SYMLINK", target ? target : "",
                           linkpath ? linkpath : "");
    errno = saved_errno;
    return rc;
}

int symlinkat(const char* target, int newdirfd, const char* linkpath) {
    static int (*real)(const char*, int, const char*) = nullptr;
    if (!real) {
        real = (int (*)(const char*, int, const char*))dlsym(
            RTLD_NEXT, "__libc_symlinkat");
        if (!real) {
            real = (int (*)(const char*, int, const char*))dlsym(RTLD_NEXT,
                                                                 "symlinkat");
        }
        if (!real) return -1;
    }
    int rc = real(target, newdirfd, linkpath);
    int saved_errno = errno;
    log_input_output_event("SYMLINKAT", target ? target : "",
                           linkpath ? linkpath : "");
    errno = saved_errno;
    return rc;
}

int unlink(const char* pathname) {
    static int (*real)(const char*) = nullptr;
    if (!real) {
        real = (int (*)(const char*))dlsym(RTLD_NEXT, "__libc_unlink");
        if (!real) {
            real = (int (*)(const char*))dlsym(RTLD_NEXT, "unlink");
        }
        if (!real) return -1;
    }
    int rc = real(pathname);
    int saved_errno = errno;
    log_input_event("UNLINK", pathname ? pathname : "");
    errno = saved_errno;
    return rc;
}

int unlinkat(int dirfd, const char* pathname, int flags) {
    static int (*real)(int, const char*, int) = nullptr;
    if (!real) {
        real = (int (*)(int, const char*, int))dlsym(RTLD_NEXT,
                                                     "__libc_unlinkat");
        if (!real) {
            real = (int (*)(int, const char*, int))dlsym(RTLD_NEXT, "unlinkat");
        }
        if (!real) return -1;
    }
    int rc = real(dirfd, pathname, flags);
    int saved_errno = errno;
    log_input_event("UNLINKAT", pathname ? pathname : "");
    errno = saved_errno;
    return rc;
}

int remove(const char* pathname) {
    static int (*real)(const char*) = nullptr;
    if (!real) {
        real = (int (*)(const char*))dlsym(RTLD_NEXT, "__libc_remove");
        if (!real) {
            real = (int (*)(const char*))dlsym(RTLD_NEXT, "remove");
        }
        if (!real) return -1;
    }
    int rc = real(pathname);
    int saved_errno = errno;
    log_input_event("REMOVE", pathname ? pathname : "");
    errno = saved_errno;
    return rc;
}

int rmdir(const char* pathname) {
    static int (*real)(const char*) = nullptr;
    if (!real) {
        real = (int (*)(const char*))dlsym(RTLD_NEXT, "__libc_rmdir");
        if (!real) {
            real = (int (*)(const char*))dlsym(RTLD_NEXT, "rmdir");
        }
        if (!real) return -1;
    }
    int rc = real(pathname);
    int saved_errno = errno;
    log_input_event("RMDIR", pathname ? pathname : "");
    errno = saved_errno;
    return rc;
}

// IPC name unlinks
int shm_unlink(const char* name) {
    static int (*real)(const char*) = nullptr;
    if (!real) {
        real = (int (*)(const char*))dlsym(RTLD_NEXT, "__libc_shm_unlink");
        if (!real) {
            real = (int (*)(const char*))dlsym(RTLD_NEXT, "shm_unlink");
        }
        if (!real) return -1;
    }
    int rc = real(name);
    int saved_errno = errno;
    log_input_event("SHM_UNLINK", name ? name : "");
    errno = saved_errno;
    return rc;
}

int mq_unlink(const char* name) {
    static int (*real)(const char*) = nullptr;
    if (!real) {
        real = (int (*)(const char*))dlsym(RTLD_NEXT, "__libc_mq_unlink");
        if (!real) {
            real = (int (*)(const char*))dlsym(RTLD_NEXT, "mq_unlink");
        }
        if (!real) return -1;
    }
    int rc = real(name);
    int saved_errno = errno;
    log_input_event("MQ_UNLINK", name ? name : "");
    errno = saved_errno;
    return rc;
}

int sem_unlink(const char* name) {
    static int (*real)(const char*) = nullptr;
    if (!real) {
        real = (int (*)(const char*))dlsym(RTLD_NEXT, "__libc_sem_unlink");
        if (!real) {
            real = (int (*)(const char*))dlsym(RTLD_NEXT, "sem_unlink");
        }
        if (!real) return -1;
    }
    int rc = real(name);
    int saved_errno = errno;
    log_input_event("SEM_UNLINK", name ? name : "");
    errno = saved_errno;
    return rc;
}
}
