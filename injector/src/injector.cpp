#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdatomic.h>
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

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <queue>
#include <random>
#include <string>
#include <unordered_set>
#include <vector>

struct linux_dirent;
struct linux_dirent64;

static const char* endpoint_url = "http://127.0.0.1:9000/log";
#define LOG_STR_MAX 256

extern "C" char** environ;

std::queue<std::pair<std::string, std::string>> get_env_pairs_environ() {
    const std::unordered_set<std::string> excl = {};
    std::queue<std::pair<std::string, std::string>> out;
    for (char** p = environ; p && *p; ++p) {
        const char* kv = *p;
        const char* eq = std::strchr(kv, '=');
        if (!eq) continue;
        std::string key(kv, eq - kv);
        if (excl.find(key) != excl.end()) continue;
        out.emplace(std::move(key), std::string(eq + 1));
    }
    return out;
}

static std::string get_env(const char* name) {
    const char* val = std::getenv(name);
    return val ? std::string(val) : std::string();
}

std::string get_full_cmd() {
    char exe_path[PATH_MAX];
    if (!realpath("/proc/self/exe", exe_path)) return "";
    std::ifstream cmdline("/proc/self/cmdline");
    if (!cmdline) return exe_path;
    std::string cmd, arg;
    while (std::getline(cmdline, arg, '\0')) {
        if (!cmd.empty()) cmd += ' ';
        cmd += arg;
    }
    return cmd;
}

uint64_t random_id() {
    static thread_local std::mt19937_64 gen{std::random_device{}()};
    static thread_local std::uniform_int_distribution<uint64_t> dist;
    return dist(gen);
}

static const std::string slurm_job_id = "1";
static const std::string slurm_cluster_name = "cname1";

static std::string path_exec = get_env("PROV_PATH_EXEC");
static std::vector<std::string> aggregated_events;
static std::mutex events_mutex;
static atomic_bool after_failed_execv = ATOMIC_VAR_INIT(false);
static std::string nodename = std::to_string(random_id());

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

static inline void add_operation(const std::string& operation,
                                 const std::string& ts,
                                 const std::string& event_json,
                                 bool add_first = false) {
    std::lock_guard<std::mutex> guard(events_mutex);
    std::string event = R"({"event_header":{"operation":")" + operation
                        + R"(","ts":)" + ts + R"(},"event_data":)" + event_json
                        + "}\n";
    if (add_first) {
        aggregated_events.insert(aggregated_events.begin(), event);
    } else {
        aggregated_events.push_back(event);
    }
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

/*static void log_unlink(const std::string operation,
                            const std::string path_in) {
    std::string ts = now_ns();
    std::string json = R"({"path_in":")" + path_in + R"("})";
    add_operation(operation, ts, json);
}

static void log_output_event(const std::string operation,
                             const std::string path_out) {
    std::string ts = now_ns();
    std::string json = R"({"path_out":")" + path_out + R"("})";
    add_operation(operation, ts, json);
}*/

static void log_rename(const std::string original_path,
                       const std::string new_path) {
    std::string ts = now_ns();
    std::string json = R"({"original_path":")" + original_path
                       + R"(","new_path":")" + new_path + R"("})";
    add_operation("RENAME", ts, json);
}

static void log_read_fd(int path_in_fd) {
    std::string path_in = fd_path(path_in_fd);
    std::string ts = now_ns();
    std::string json = R"({"path":")" + path_in + R"("})";
    add_operation("READ", ts, json);
}

static void log_write_fd(int path_out_fd) {
    std::string path_out = fd_path(path_out_fd);
    std::string ts = now_ns();
    std::string json = R"({"path":")" + path_out + R"("})";
    add_operation("WRITE", ts, json);
}

static void log_transfer_fd(int path_read_fd, int path_write_fd) {
    std::string path_read = fd_path(path_read_fd);
    std::string path_write = fd_path(path_write_fd);
    std::string ts = now_ns();
    std::string json = R"({"path_read":")" + path_read + R"(","path_write":")"
                       + path_write + R"("})";
    add_operation("TRANSFER", ts, json);
}

static void log_exec() {
    std::string ts = now_ns();
    std::string json = R"({})";
    add_operation("EXEC", ts, json);
}

static void log_exec_fail() {
    std::string ts = now_ns();
    std::string json = R"({})";
    add_operation("EXEC_FAIL", ts, json);
}

static void log_unlink(std::string path) {
    std::string ts = now_ns();
    std::string json = R"({"path":")" + path + R"("})";
    add_operation("UNLINK", ts, json);
}
/*
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
    add_operation(operation, ts, json);
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
    add_operation(operation, ts, json);
}
*/
static std::string get_env_variables_string() {
    const std::unordered_set<std::string> exclude = {"_", "SHLVL"};
    std::queue<std::pair<std::string, std::string>> env_variables
        = get_env_pairs_environ();
    std::vector<std::pair<std::string, std::string>> items;
    items.reserve(env_variables.size());
    size_t payload_len = 0;
    while (!env_variables.empty()) {
        auto [name, value] = std::move(env_variables.front());
        env_variables.pop();
        if (exclude.find(name) != exclude.end()) continue;
        payload_len += 7 + name.size() + value.size();
        items.emplace_back(std::move(name), std::move(value));
    }
    std::sort(items.begin(), items.end(), [](const auto& a, const auto& b) {
        if (a.first != b.first) return a.first < b.first;
        return a.second < b.second;
    });
    std::string out;
    out.reserve(payload_len + 2 + (items.size() ? items.size() - 1 : 0));
    out.push_back('[');
    bool first = true;
    for (auto& kv : items) {
        if (!first) out.push_back(',');
        first = false;
        out += "{\"";
        out += kv.first;
        out += "\":\"";
        out += kv.second;
        out += "\"}";
    }
    out.push_back(']');
    return out;
}

static void log_process_start() {
    std::string ts = now_ns();
    std::string slurmd_nodename = "node1";
    pid_t pid = getpid();
    pid_t ppid = getppid();
    std::string operation = "PROCESS_START";
    std::string launch_command = get_full_cmd();
    std::string env_variables_string = get_env_variables_string();
    std::string json = R"({"slurmd_nodename":")" + slurmd_nodename
                       + R"(","pid":)" + std::to_string(pid) + R"(,"ppid":)"
                       + std::to_string(ppid) + R"(,"launch_command":")"
                       + launch_command + R"(","env_variables":)"
                       + env_variables_string + R"(})";
    add_operation(operation, ts, json, true);
}

static void log_process_end() {
    std::string ts = now_ns();
    std::string operation = "PROCESS_END";
    std::string json = "{}";
    add_operation(operation, ts, json);
}

bool get_after_failed_execv(void) {
    return atomic_load_explicit(&after_failed_execv, memory_order_relaxed);
}

struct ProvSaveData {
    std::string path_write;
    std::string all_events;
};

ProvSaveData prepare_save_events() {
    // std::ifstream file("/etc/machine-id");
    // std::getline(file, nodename);
    std::string path_write = get_env("PROV_PATH_WRITE") + "/" + nodename + "_"
                             + std::to_string(getpid()) + ".jsonl";
    std::string all_events;
    size_t total_size = 0;
    for (const auto& event : aggregated_events) {
        total_size += event.size();
    }
    all_events.reserve(total_size);
    for (const auto& event : aggregated_events) {
        all_events.append(event.data(), event.size());
    }
    aggregated_events.clear();
    return ProvSaveData{std::move(path_write), std::move(all_events)};
}

void save_events_clean(ProvSaveData& prov_save_data) {
    std::string path_write = std::move(prov_save_data.path_write);
    int fd = syscall(SYS_open, path_write.c_str(),
                     O_WRONLY | O_CREAT | O_APPEND, 0644);
    std::string all_events = std::move(prov_save_data.all_events);
    if (fd >= 0) {
        syscall(SYS_write, fd, all_events.data(), all_events.size());
        syscall(SYS_close, fd);
    }
}

off_t find_trunc_pos_remove_last_line(int fd) {
    off_t end = (off_t)syscall(SYS_lseek, fd, 0, SEEK_END);
    const size_t CHUNK = 4096;
    char buf[CHUNK];
    off_t pos = end;
    while (pos > 0) {
        size_t to_read = (pos >= (off_t)CHUNK) ? CHUNK : (size_t)pos;
        pos -= (off_t)to_read;
        ssize_t r = (ssize_t)syscall(SYS_read, fd, buf, to_read);
        for (ssize_t i = r - 1; i >= 0; --i) {
            if (buf[i] == '\n') {
                return pos + i + 1;
            }
        }
    }
    return pos;
}

void append_events_clean(ProvSaveData& prov_save_data) {
    std::string path_write = std::move(prov_save_data.path_write);
    std::string all_events = std::move(prov_save_data.all_events);
    int fd = (int)syscall(SYS_open, path_write.c_str(), O_RDWR, 0644);
    if (fd < 0) return;
    off_t trunc_pos = find_trunc_pos_remove_last_line(fd);
    syscall(SYS_ftruncate, fd, trunc_pos);
    syscall(SYS_lseek, fd, 0, SEEK_END);
    syscall(SYS_write, fd, all_events.data(), all_events.size());
    syscall(SYS_close, fd);
}

void run_destructor_code() {
    log_process_end();
    ProvSaveData prov_save_data = prepare_save_events();
    if (!get_after_failed_execv()) {
        save_events_clean(prov_save_data);
    } else {
        append_events_clean(prov_save_data);
    }
}

__attribute__((constructor)) static void preload_init(void) {
    log_process_start();
}

__attribute__((destructor)) static void preload_fini(void) {
    run_destructor_code();
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

static inline void set_after_failed_execv_true(void) {
    atomic_store_explicit(&after_failed_execv, true, memory_order_relaxed);
}

extern "C" {
#define SAVE_ERRNO int saved_errno = errno
#define RESTORE_ERRNO errno = saved_errno
#define RESOLVE_REAL(real_fn, sym1, sym2, failret)                       \
    do {                                                                 \
        if (!(real_fn)) {                                                \
            (real_fn) = decltype(real_fn)(dlsym(RTLD_NEXT, (sym1)));     \
            if (!(real_fn))                                              \
                (real_fn) = decltype(real_fn)(dlsym(RTLD_NEXT, (sym2))); \
            if (!(real_fn)) return (failret);                            \
        }                                                                \
    } while (0)
// ---------- WRITE HOOKS ----------
ssize_t write(int fd, const void* buf, size_t count) {
    static auto real_write = (ssize_t (*)(int, const void*, size_t)) nullptr;
    RESOLVE_REAL(real_write, "__libc_write", "write", (ssize_t)-1);
    ssize_t ret = real_write(fd, buf, count);
    SAVE_ERRNO;
    log_write_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
size_t fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream) {
    static auto real_fwrite
        = (size_t (*)(const void*, size_t, size_t, FILE*)) nullptr;
    RESOLVE_REAL(real_fwrite, "__libc_fwrite", "fwrite", (size_t)0);
    size_t ret = real_fwrite(ptr, size, nmemb, stream);
    SAVE_ERRNO;
    int fd = stream ? fileno(stream) : -1;
    log_write_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
ssize_t writev(int fd, const struct iovec* iov, int iovcnt) {
    static auto real_writev
        = (ssize_t (*)(int, const struct iovec*, int)) nullptr;
    RESOLVE_REAL(real_writev, "__libc_writev", "writev", (ssize_t)-1);
    ssize_t ret = real_writev(fd, iov, iovcnt);
    SAVE_ERRNO;
    log_write_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
ssize_t pwrite(int fd, const void* buf, size_t count, off_t offset) {
    static auto real_pwrite
        = (ssize_t (*)(int, const void*, size_t, off_t)) nullptr;
    RESOLVE_REAL(real_pwrite, "__libc_pwrite", "pwrite", (ssize_t)-1);
    ssize_t ret = real_pwrite(fd, buf, count, offset);
    SAVE_ERRNO;
    log_write_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
ssize_t pwrite64(int fd, const void* buf, size_t count, off64_t offset) {
    static auto real_pwrite64
        = (ssize_t (*)(int, const void*, size_t, off64_t)) nullptr;
    RESOLVE_REAL(real_pwrite64, "__libc_pwrite64", "pwrite64", (ssize_t)-1);
    ssize_t ret = real_pwrite64(fd, buf, count, offset);
    SAVE_ERRNO;
    log_write_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
int fputs(const char* s, FILE* stream) {
    static auto real_fputs = (int (*)(const char*, FILE*)) nullptr;
    RESOLVE_REAL(real_fputs, "__libc_fputs", "fputs", -1);
    int ret = real_fputs(s, stream);
    SAVE_ERRNO;
    int fd = stream ? fileno(stream) : -1;
    log_write_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
int fprintf(FILE* stream, const char* fmt, ...) {
    static auto real_vfprintf = (int (*)(FILE*, const char*, va_list)) nullptr;
    RESOLVE_REAL(real_vfprintf, "__libc_vfprintf", "vfprintf", -1);
    va_list ap;
    va_start(ap, fmt);
    int ret = real_vfprintf(stream, fmt, ap);
    va_end(ap);
    SAVE_ERRNO;
    int fd = stream ? fileno(stream) : -1;
    log_write_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
int vfprintf(FILE* stream, const char* fmt, va_list ap) {
    static auto real_vfprintf = (int (*)(FILE*, const char*, va_list)) nullptr;
    RESOLVE_REAL(real_vfprintf, "__libc_vfprintf", "vfprintf", -1);
    int ret = real_vfprintf(stream, fmt, ap);
    SAVE_ERRNO;
    int fd = stream ? fileno(stream) : -1;
    log_write_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
int dprintf(int fd, const char* fmt, ...) {
    static auto real_vdprintf = (int (*)(int, const char*, va_list)) nullptr;
    RESOLVE_REAL(real_vdprintf, "__libc_vdprintf", "vdprintf", -1);
    va_list ap;
    va_start(ap, fmt);
    int ret = real_vdprintf(fd, fmt, ap);
    va_end(ap);
    SAVE_ERRNO;
    log_write_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
int vdprintf(int fd, const char* fmt, va_list ap) {
    static auto real_vdprintf = (int (*)(int, const char*, va_list)) nullptr;
    RESOLVE_REAL(real_vdprintf, "__libc_vdprintf", "vdprintf", -1);
    int ret = real_vdprintf(fd, fmt, ap);
    SAVE_ERRNO;
    log_write_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
int fputc(int c, FILE* stream) {
    static auto real_fputc = (int (*)(int, FILE*)) nullptr;
    RESOLVE_REAL(real_fputc, "__libc_fputc", "fputc", -1);
    int ret = real_fputc(c, stream);
    SAVE_ERRNO;
    int fd = stream ? fileno(stream) : -1;
    log_write_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
int fputs_unlocked(const char* s, FILE* stream) {
    static auto real_fputs_unlocked = (int (*)(const char*, FILE*)) nullptr;
    RESOLVE_REAL(real_fputs_unlocked, "__libc_fputs_unlocked", "fputs_unlocked",
                 -1);
    int ret = real_fputs_unlocked(s, stream);
    SAVE_ERRNO;
    int fd = stream ? fileno(stream) : -1;
    log_write_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
size_t fwrite_unlocked(const void* ptr, size_t size, size_t nmemb,
                       FILE* stream) {
    static auto real_fwrite_unlocked
        = (size_t (*)(const void*, size_t, size_t, FILE*)) nullptr;
    RESOLVE_REAL(real_fwrite_unlocked, "__libc_fwrite_unlocked",
                 "fwrite_unlocked", (size_t)0);
    size_t ret = real_fwrite_unlocked(ptr, size, nmemb, stream);
    SAVE_ERRNO;
    int fd = stream ? fileno(stream) : -1;
    log_write_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
ssize_t pwritev(int fd, const struct iovec* iov, int iovcnt, off_t offset) {
    static auto real_pwritev
        = (ssize_t (*)(int, const struct iovec*, int, off_t)) nullptr;
    RESOLVE_REAL(real_pwritev, "__libc_pwritev", "pwritev", (ssize_t)-1);
    ssize_t ret = real_pwritev(fd, iov, iovcnt, offset);
    SAVE_ERRNO;
    log_write_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
ssize_t pwritev2(int fd, const struct iovec* iov, int iovcnt, off_t offset,
                 int flags) {
    static auto real_pwritev2
        = (ssize_t (*)(int, const struct iovec*, int, off_t, int)) nullptr;
    RESOLVE_REAL(real_pwritev2, "__libc_pwritev2", "pwritev2", (ssize_t)-1);
    ssize_t ret = real_pwritev2(fd, iov, iovcnt, offset, flags);
    SAVE_ERRNO;
    log_write_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
// --------------- SEND HOOKS -----------------
/*ssize_t sendto(int sockfd, const void* buf, size_t len, int flags,
               const struct sockaddr* dest_addr, socklen_t addrlen) {
    static auto real_sendto
        = (ssize_t (*)(int, const void*, size_t, int, const struct sockaddr*,
                       socklen_t)) nullptr;
    RESOLVE_REAL(real_sendto, "__libc_sendto", "sendto", (ssize_t)-1);
    ssize_t ret = real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    SAVE_ERRNO;
    log_net_send_event("WRITE", sockfd, dest_addr, addrlen, 1);
    RESTORE_ERRNO;
    return ret;
}
ssize_t sendmsg(int sockfd, const struct msghdr* msg, int flags) {
    static auto real_sendmsg
        = (ssize_t (*)(int, const struct msghdr*, int)) nullptr;
    RESOLVE_REAL(real_sendmsg, "__libc_sendmsg", "sendmsg", (ssize_t)-1);
    ssize_t ret = real_sendmsg(sockfd, msg, flags);
    SAVE_ERRNO;
    socklen_t alen = 0;
    const struct sockaddr* sa = msg_name_sa(msg, &alen);
    log_net_send_event("WRITE", sockfd, sa, alen, 1);
    RESTORE_ERRNO;
    return ret;
}
int sendmmsg(int sockfd, struct mmsghdr* msgvec, unsigned int vlen, int flags) {
    static auto real_sendmmsg
        = (int (*)(int, struct mmsghdr*, unsigned int, int)) nullptr;
    RESOLVE_REAL(real_sendmmsg, "__libc_sendmmsg", "sendmmsg", -1);
    int ret = real_sendmmsg(sockfd, msgvec, vlen, flags);
    SAVE_ERRNO;
    socklen_t alen = 0;
    const struct sockaddr* sa = mmsg0_name_sa(msgvec, vlen, &alen);
    log_net_send_event("WRITE", sockfd, sa, alen, vlen);
    RESTORE_ERRNO;
    return ret;
}*/
ssize_t sendfile(int out_fd, int in_fd, off_t* offset, size_t count) {
    static auto real_sendfile = (ssize_t (*)(int, int, off_t*, size_t)) nullptr;
    RESOLVE_REAL(real_sendfile, "__libc_sendfile", "sendfile", (ssize_t)-1);
    ssize_t ret = real_sendfile(out_fd, in_fd, offset, count);
    SAVE_ERRNO;
    log_transfer_fd(in_fd, out_fd);
    RESTORE_ERRNO;
    return ret;
}
ssize_t sendfile64(int out_fd, int in_fd, off64_t* offset, size_t count) {
    static auto real_sendfile64
        = (ssize_t (*)(int, int, off64_t*, size_t)) nullptr;
    RESOLVE_REAL(real_sendfile64, "__libc_sendfile64", "sendfile64",
                 (ssize_t)-1);
    ssize_t ret = real_sendfile64(out_fd, in_fd, offset, count);
    SAVE_ERRNO;
    log_transfer_fd(in_fd, out_fd);
    RESTORE_ERRNO;
    return ret;
}

ssize_t copy_file_range(int fd_in, off64_t* off_in, int fd_out,
                        off64_t* off_out, size_t len, unsigned int flags) {
    static auto real_copy_file_range = (ssize_t (*)(
        int, off64_t*, int, off64_t*, size_t, unsigned int)) nullptr;
    RESOLVE_REAL(real_copy_file_range, "__libc_copy_file_range",
                 "copy_file_range", (ssize_t)-1);
    ssize_t ret
        = real_copy_file_range(fd_in, off_in, fd_out, off_out, len, flags);
    SAVE_ERRNO;
    log_transfer_fd(fd_in, fd_out);
    RESTORE_ERRNO;
    return ret;
}
ssize_t splice(int fd_in, off64_t* off_in, int fd_out, off64_t* off_out,
               size_t len, unsigned int flags) {
    static auto real_splice = (ssize_t (*)(int, off64_t*, int, off64_t*, size_t,
                                           unsigned int)) nullptr;
    RESOLVE_REAL(real_splice, "__libc_splice", "splice", (ssize_t)-1);
    ssize_t ret = real_splice(fd_in, off_in, fd_out, off_out, len, flags);
    SAVE_ERRNO;
    log_transfer_fd(fd_in, fd_out);
    RESTORE_ERRNO;
    return ret;
}
// --------------------- READ HOOKS -----------------------
ssize_t read(int fd, void* buf, size_t count) {
    static auto real_read = (ssize_t (*)(int, void*, size_t)) nullptr;
    RESOLVE_REAL(real_read, "__libc_read", "read", (ssize_t)-1);
    ssize_t ret = real_read(fd, buf, count);
    SAVE_ERRNO;
    log_read_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
ssize_t pread(int fd, void* buf, size_t count, off_t offset) {
    static auto real_pread = (ssize_t (*)(int, void*, size_t, off_t)) nullptr;
    RESOLVE_REAL(real_pread, "__libc_pread", "pread", (ssize_t)-1);
    ssize_t ret = real_pread(fd, buf, count, offset);
    SAVE_ERRNO;
    log_read_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
ssize_t pread64(int fd, void* buf, size_t count, off64_t offset) {
    static auto real_pread64
        = (ssize_t (*)(int, void*, size_t, off64_t)) nullptr;
    RESOLVE_REAL(real_pread64, "__libc_pread64", "pread64", (ssize_t)-1);
    ssize_t ret = real_pread64(fd, buf, count, offset);
    SAVE_ERRNO;
    log_read_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
ssize_t readv(int fd, const struct iovec* iov, int iovcnt) {
    static auto real_readv
        = (ssize_t (*)(int, const struct iovec*, int)) nullptr;
    RESOLVE_REAL(real_readv, "__libc_readv", "readv", (ssize_t)-1);
    ssize_t ret = real_readv(fd, iov, iovcnt);
    SAVE_ERRNO;
    log_read_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
ssize_t preadv(int fd, const struct iovec* iov, int iovcnt, off_t offset) {
    static auto real_preadv
        = (ssize_t (*)(int, const struct iovec*, int, off_t)) nullptr;
    RESOLVE_REAL(real_preadv, "__libc_preadv", "preadv", (ssize_t)-1);
    ssize_t ret = real_preadv(fd, iov, iovcnt, offset);
    SAVE_ERRNO;
    log_read_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
ssize_t preadv2(int fd, const struct iovec* iov, int iovcnt, off_t offset,
                int flags) {
    static auto real_preadv2
        = (ssize_t (*)(int, const struct iovec*, int, off_t, int)) nullptr;
    RESOLVE_REAL(real_preadv2, "__libc_preadv2", "preadv2", (ssize_t)-1);
    ssize_t ret = real_preadv2(fd, iov, iovcnt, offset, flags);
    SAVE_ERRNO;
    log_read_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
/*
ssize_t recvfrom(int sockfd, void* buf, size_t len, int flags,
                 struct sockaddr* src_addr, socklen_t* addrlen) {
    static auto real_recvfrom = (ssize_t (*)(
        int, void*, size_t, int, struct sockaddr*, socklen_t*)) nullptr;
    RESOLVE_REAL(real_recvfrom, "__libc_recvfrom", "recvfrom", (ssize_t)-1);
    ssize_t ret = real_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    SAVE_ERRNO;
    log_net_recv_event("READ", sockfd, src_addr, (addrlen ? *addrlen : 0), 1);
    RESTORE_ERRNO;
    return ret;
}
ssize_t recvmsg(int sockfd, struct msghdr* msg, int flags) {
    static auto real_recvmsg = (ssize_t (*)(int, struct msghdr*, int)) nullptr;
    RESOLVE_REAL(real_recvmsg, "__libc_recvmsg", "recvmsg", (ssize_t)-1);
    ssize_t ret = real_recvmsg(sockfd, msg, flags);
    SAVE_ERRNO;
    socklen_t alen = 0;
    const struct sockaddr* sa = msg_name_sa(msg, &alen);
    log_net_recv_event("READ", sockfd, sa, alen, 1);
    RESTORE_ERRNO;
    return ret;
}
int recvmmsg(int sockfd, struct mmsghdr* msgvec, unsigned int vlen, int flags,
             struct timespec* timeout) {
    static auto real_recvmmsg = (int (*)(int, struct mmsghdr*, unsigned int,
                                         int, struct timespec*)) nullptr;
    RESOLVE_REAL(real_recvmmsg, "__libc_recvmmsg", "recvmmsg", -1);
    int ret = real_recvmmsg(sockfd, msgvec, vlen, flags, timeout);
    SAVE_ERRNO;
    socklen_t alen = 0;
    const struct sockaddr* sa = mmsg0_name_sa(msgvec, vlen, &alen);
    log_net_recv_event("READ", sockfd, sa, alen, vlen);
    RESTORE_ERRNO;
    return ret;
}*/
int getdents(unsigned int fd, struct linux_dirent* dirp, unsigned int count) {
    static auto real_getdents
        = (int (*)(unsigned int, struct linux_dirent*, unsigned int)) nullptr;
    RESOLVE_REAL(real_getdents, "__libc_getdents", "getdents", -1);
    int ret = real_getdents(fd, dirp, count);
    SAVE_ERRNO;
    log_read_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
int getdents64(unsigned int fd, struct linux_dirent64* dirp,
               unsigned int count) {
    static auto real_getdents64
        = (int (*)(unsigned int, struct linux_dirent64*, unsigned int)) nullptr;
    RESOLVE_REAL(real_getdents64, "__libc_getdents64", "getdents64", -1);
    int ret = real_getdents64(fd, dirp, count);
    SAVE_ERRNO;
    log_read_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
size_t fread(void* ptr, size_t size, size_t nmemb, FILE* stream) {
    static auto real_fread = (size_t (*)(void*, size_t, size_t, FILE*)) nullptr;
    RESOLVE_REAL(real_fread, "__libc_fread", "fread", (size_t)0);
    size_t ret = real_fread(ptr, size, nmemb, stream);
    SAVE_ERRNO;
    int fd = stream ? fileno(stream) : -1;
    log_read_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
char* fgets(char* s, int size, FILE* stream) {
    static auto real_fgets = (char* (*)(char*, int, FILE*)) nullptr;
    RESOLVE_REAL(real_fgets, "__libc_fgets", "fgets", NULL);
    char* ret = real_fgets(s, size, stream);
    SAVE_ERRNO;
    int fd = stream ? fileno(stream) : -1;
    log_read_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
int fgetc(FILE* stream) {
    static auto real_fgetc = (int (*)(FILE*)) nullptr;
    RESOLVE_REAL(real_fgetc, "__libc_fgetc", "fgetc", EOF);
    int ret = real_fgetc(stream);
    SAVE_ERRNO;
    int fd = stream ? fileno(stream) : -1;
    log_read_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
int getc(FILE* stream) {
    static auto real_getc = (int (*)(FILE*)) nullptr;
    RESOLVE_REAL(real_getc, "__libc_getc", "getc", EOF);
    int ret = real_getc(stream);
    SAVE_ERRNO;
    int fd = stream ? fileno(stream) : -1;
    log_read_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
/*
int getchar(void) {
    static auto real_getchar = (int (*)(void)) nullptr;
    RESOLVE_REAL(real_getchar, "__libc_getchar", "getchar", EOF);
    int ret = real_getchar();
    SAVE_ERRNO;
    log_unlink("READ", "");
    RESTORE_ERRNO;
    return ret;
}
*/
int fscanf(FILE* stream, const char* format, ...) {
    static auto real_fscanf = (int (*)(FILE*, const char*, ...)) nullptr;
    RESOLVE_REAL(real_fscanf, "__libc_fscanf", "fscanf", -1);
    va_list ap;
    va_start(ap, format);
    int ret = real_fscanf(stream, format, ap);
    va_end(ap);
    SAVE_ERRNO;
    int fd = stream ? fileno(stream) : -1;
    log_read_fd(fd);
    RESTORE_ERRNO;
    return ret;
}
/*
int scanf(const char* format, ...) {
    static auto real_scanf = (int (*)(const char*, ...)) nullptr;
    RESOLVE_REAL(real_scanf, "__libc_scanf", "scanf", -1);
    va_list ap;
    va_start(ap, format);
    int ret = real_scanf(format, ap);
    va_end(ap);
    SAVE_ERRNO;
    log_unlink("READ", "");
    RESTORE_ERRNO;
    return ret;
}
int sscanf(const char* s, const char* format, ...) {
    static auto real_sscanf = (int (*)(const char*, const char*, ...)) nullptr;
    RESOLVE_REAL(real_sscanf, "__libc_sscanf", "sscanf", -1);
    va_list ap;
    va_start(ap, format);
    int ret = real_sscanf(s, format, ap);
    va_end(ap);
    SAVE_ERRNO;
    log_unlink("READ", "");
    RESTORE_ERRNO;
    return ret;
}
int vsscanf(const char* s, const char* format, va_list ap) {
    static auto real_vsscanf
        = (int (*)(const char*, const char*, va_list)) nullptr;
    RESOLVE_REAL(real_vsscanf, "__libc_vsscanf", "vsscanf", -1);
    int ret = real_vsscanf(s, format, ap);
    SAVE_ERRNO;
    log_unlink("READ", "");
    RESTORE_ERRNO;
    return ret;
}
*/
// --------------------- EXEC HOOKS -----------------------
int execve(const char* pathname, char* const argv[], char* const envp[]) {
    static auto real_execve
        = (int (*)(const char*, char* const[], char* const[])) nullptr;
    RESOLVE_REAL(real_execve, "__libc_execve", "execve", -1);
    log_exec();
    run_destructor_code();
    real_execve(pathname, argv, envp);
    int e = errno;
    set_after_failed_execv_true();
    log_exec_fail();
    errno = e;
    return -1;
}

int execveat(int dirfd, const char* pathname, char* const argv[],
             char* const envp[], int flags) {
    static auto real_execveat = (int (*)(int, const char*, char* const[],
                                         char* const[], int)) nullptr;
    RESOLVE_REAL(real_execveat, "__libc_execveat", "execveat", -1);
    log_exec();
    run_destructor_code();
    real_execveat(dirfd, pathname, argv, envp, flags);
    int e = errno;
    set_after_failed_execv_true();
    log_exec_fail();
    errno = e;
    return -1;
}

int fexecve(int fd, char* const argv[], char* const envp[]) {
    static auto real_fexecve
        = (int (*)(int, char* const[], char* const[])) nullptr;
    RESOLVE_REAL(real_fexecve, "__libc_fexecve", "fexecve", -1);
    log_exec();
    run_destructor_code();
    real_fexecve(fd, argv, envp);
    int e = errno;
    set_after_failed_execv_true();
    log_exec_fail();
    errno = e;
    return -1;
}

int execv(const char* path, char* const argv[]) {
    static auto real_execv = (int (*)(const char*, char* const[])) nullptr;
    RESOLVE_REAL(real_execv, "__libc_execv", "execv", -1);
    log_exec();
    run_destructor_code();
    real_execv(path, argv);
    int e = errno;
    set_after_failed_execv_true();
    log_exec_fail();
    errno = e;
    return -1;
}

int execvp(const char* file, char* const argv[]) {
    static auto real_execvp = (int (*)(const char*, char* const[])) nullptr;
    RESOLVE_REAL(real_execvp, "__libc_execvp", "execvp", -1);
    log_exec();
    run_destructor_code();
    real_execvp(file, argv);
    int e = errno;
    set_after_failed_execv_true();
    log_exec_fail();
    errno = e;
    return -1;
}

int execvpe(const char* file, char* const argv[], char* const envp[]) {
    static auto real_execvpe
        = (int (*)(const char*, char* const[], char* const[])) nullptr;
    RESOLVE_REAL(real_execvpe, "__libc_execvpe", "execvpe", -1);
    log_exec();
    run_destructor_code();
    real_execvpe(file, argv, envp);
    int e = errno;
    set_after_failed_execv_true();
    log_exec_fail();
    errno = e;
    return -1;
}

int execl(const char* path, const char* arg, ...) {
    static auto real_execv = (int (*)(const char*, char* const[])) nullptr;
    RESOLVE_REAL(real_execv, "__libc_execv", "execv", -1);
    log_exec();
    run_destructor_code();
    va_list ap;
    va_start(ap, arg);
    char** argv = build_argv_from_varargs(arg, ap);
    va_end(ap);
    if (!argv) {
        errno = ENOMEM;
        return -1;
    }
    real_execv(path, argv);
    int e = errno;
    free(argv);
    set_after_failed_execv_true();
    log_exec_fail();
    errno = e;
    return -1;
}

int execlp(const char* file, const char* arg, ...) {
    static auto real_execvp = (int (*)(const char*, char* const[])) nullptr;
    RESOLVE_REAL(real_execvp, "__libc_execvp", "execvp", -1);
    log_exec();
    run_destructor_code();
    va_list ap;
    va_start(ap, arg);
    char** argv = build_argv_from_varargs(arg, ap);
    va_end(ap);
    if (!argv) {
        errno = ENOMEM;
        return -1;
    }
    real_execvp(file, argv);
    int e = errno;
    free(argv);
    set_after_failed_execv_true();
    log_exec_fail();
    errno = e;
    return -1;
}

int execle(const char* path, const char* arg, ...) {
    static auto real_execve
        = (int (*)(const char*, char* const[], char* const[])) nullptr;
    RESOLVE_REAL(real_execve, "__libc_execve", "execve", -1);
    log_exec();
    run_destructor_code();
    va_list ap;
    va_start(ap, arg);
    char** argv = build_argv_from_varargs(arg, ap);
    char* const* envp = va_arg(ap, char* const*);
    va_end(ap);
    if (!argv) {
        errno = ENOMEM;
        return -1;
    }
    real_execve(path, argv, (char* const*)envp);
    int e = errno;
    free(argv);
    set_after_failed_execv_true();
    log_exec_fail();
    errno = e;
    return -1;
}
/*int posix_spawn(pid_t* pid, const char* path,
                const posix_spawn_file_actions_t* file_actions,
                const posix_spawnattr_t* attrp, char* const argv[],
                char* const envp[]) {
    static auto real_posix_spawn = (int (*)(
        pid_t*, const char*, const posix_spawn_file_actions_t*,
        const posix_spawnattr_t*, char* const[], char* const[])) nullptr;
    RESOLVE_REAL(real_posix_spawn, "__libc_posix_spawn", "posix_spawn", -1);
    int rc = real_posix_spawn(pid, path, file_actions, attrp, argv, envp);
    SAVE_ERRNO;
    if (rc == 0 && pid) log_spawn_event("POSIX_SPAWN", *pid, path ? path : "");
    RESTORE_ERRNO;
    return rc;
}
int posix_spawnp(pid_t* pid, const char* file,
                 const posix_spawn_file_actions_t* file_actions,
                 const posix_spawnattr_t* attrp, char* const argv[],
                 char* const envp[]) {
    static auto real_posix_spawnp = (int (*)(
        pid_t*, const char*, const posix_spawn_file_actions_t*,
        const posix_spawnattr_t*, char* const[], char* const[])) nullptr;
    RESOLVE_REAL(real_posix_spawnp, "__libc_posix_spawnp", "posix_spawnp", -1);
    int rc = real_posix_spawnp(pid, file, file_actions, attrp, argv, envp);
    SAVE_ERRNO;
    if (rc == 0 && pid) log_spawn_event("POSIX_SPAWNP", *pid, file ? file : "");
    RESTORE_ERRNO;
    return rc;
}
int system(const char* command) {
    static auto real_system = (int (*)(const char*)) nullptr;
    RESOLVE_REAL(real_system, "__libc_system", "system", -1);
    log_unlink("SYSTEM", command ? command : "");
    return real_system(command);
}
pid_t fork(void) {
    static auto real_fork = (pid_t (*)(void)) nullptr;
    RESOLVE_REAL(real_fork, "__libc_fork", "fork", (pid_t)-1);
    pid_t cpid = real_fork();
    if (cpid > 0) {
        SAVE_ERRNO;
        log_fork_event("FORK", cpid);
        RESTORE_ERRNO;
    }
    return cpid;
}
pid_t vfork(void) {
    static auto real_vfork = (pid_t (*)(void)) nullptr;
    RESOLVE_REAL(real_vfork, "__libc_vfork", "vfork", (pid_t)-1);
    pid_t cpid = real_vfork();
    if (cpid > 0) {
        SAVE_ERRNO;
        log_fork_event("VFORK", cpid);
        RESTORE_ERRNO;
    }
    return cpid;
}
*/
// --------------------- RENAME HOOKS -----------------------
int rename(const char* oldpath, const char* newpath) {
    static auto real_rename = (int (*)(const char*, const char*)) nullptr;
    RESOLVE_REAL(real_rename, "__libc_rename", "rename", -1);
    int rc = real_rename(oldpath, newpath);
    SAVE_ERRNO;
    log_rename(oldpath ? oldpath : "", newpath ? newpath : "");
    RESTORE_ERRNO;
    return rc;
}
int renameat(int olddirfd, const char* oldpath, int newdirfd,
             const char* newpath) {
    static auto real_renameat
        = (int (*)(int, const char*, int, const char*)) nullptr;
    RESOLVE_REAL(real_renameat, "__libc_renameat", "renameat", -1);
    int rc = real_renameat(olddirfd, oldpath, newdirfd, newpath);
    SAVE_ERRNO;
    log_rename(oldpath ? oldpath : "", newpath ? newpath : "");
    RESTORE_ERRNO;
    return rc;
}
int renameat2(int olddirfd, const char* oldpath, int newdirfd,
              const char* newpath, unsigned int flags) {
    static auto real_renameat2
        = (int (*)(int, const char*, int, const char*, unsigned int)) nullptr;
    RESOLVE_REAL(real_renameat2, "__libc_renameat2", "renameat2", -1);
    int rc = real_renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
    SAVE_ERRNO;
    log_rename(oldpath ? oldpath : "", newpath ? newpath : "");
    RESTORE_ERRNO;
    return rc;
}
/*
int clone(int (*fn)(void*), void* stack, int flags, void* arg, ...) {
    static auto real_clone
        = (int (*)(int (*)(void*), void*, int, void*, ...)) nullptr;
    RESOLVE_REAL(real_clone, "__libc_clone", "clone", -1);
    log_output_event("CLONE", "");
    va_list ap;
    va_start(ap, arg);
    void* ptid = va_arg(ap, void*);
    void* tls = va_arg(ap, void*);
    void* ctid = va_arg(ap, void*);
    va_end(ap);
    return real_clone(fn, stack, flags, arg, ptid, tls, ctid);
}
void exit(int status) {
    static auto real_exit = (void (*)(int)) nullptr;
    if (!real_exit) real_exit = (void (*)(int))dlsym(RTLD_NEXT, "exit");
    log_output_event("EXIT", "");
    if (real_exit) {
        real_exit(status);
        __builtin_unreachable();
    }
    syscall(SYS_exit_group, status);
    __builtin_unreachable();
}
void _exit(int status) {
    static auto real__exit = (void (*)(int)) nullptr;
    if (!real__exit) real__exit = (void (*)(int))dlsym(RTLD_NEXT, "_exit");
    log_output_event("_EXIT", "");
    if (real__exit) {
        real__exit(status);
        __builtin_unreachable();
    }
    syscall(SYS_exit, status);
    __builtin_unreachable();
}
void _Exit(int status) {
    static auto real__Exit = (void (*)(int)) nullptr;
    if (!real__Exit) real__Exit = (void (*)(int))dlsym(RTLD_NEXT, "_Exit");
    log_output_event("_Exit", "");
    if (real__Exit) {
        real__Exit(status);
        __builtin_unreachable();
    }
    syscall(SYS_exit, status);
    __builtin_unreachable();
}*/
// --------------------- OPEN/CLOSE/DUP/PIPE HOOKS ------------------
/*
int open(const char* pathname, int flags, ...) {
    static auto real_open = (int (*)(const char*, int, ...)) nullptr;
    RESOLVE_REAL(real_open, "__libc_open", "open", -1);
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    int fd = real_open(pathname, flags, mode);
    SAVE_ERRNO;
    log_output_event("OPEN", pathname ? pathname : "");
    RESTORE_ERRNO;
    return fd;
}
int open64(const char* pathname, int flags, ...) {
    static auto real_open64 = (int (*)(const char*, int, ...)) nullptr;
    RESOLVE_REAL(real_open64, "__libc_open64", "open64", -1);
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    int fd = real_open64(pathname, flags, mode);
    SAVE_ERRNO;
    log_output_event("OPEN64", pathname ? pathname : "");
    RESTORE_ERRNO;
    return fd;
}
int creat(const char* pathname, mode_t mode) {
    static auto real_creat = (int (*)(const char*, mode_t)) nullptr;
    RESOLVE_REAL(real_creat, "__libc_creat", "creat", -1);
    int fd = real_creat(pathname, mode);
    SAVE_ERRNO;
    log_output_event("CREAT", pathname ? pathname : "");
    RESTORE_ERRNO;
    return fd;
}
int openat(int dirfd, const char* pathname, int flags, ...) {
    static auto real_openat = (int (*)(int, const char*, int, ...)) nullptr;
    RESOLVE_REAL(real_openat, "__libc_openat", "openat", -1);
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    int fd = real_openat(dirfd, pathname, flags, mode);
    SAVE_ERRNO;
    log_output_event("OPENAT", pathname ? pathname : "");
    RESTORE_ERRNO;
    return fd;
}
int openat2(int dirfd, const char* pathname, void* how, size_t size) {
    static auto real_openat2
        = (int (*)(int, const char*, void*, size_t)) nullptr;
    RESOLVE_REAL(real_openat2, "__libc_openat2", "openat2", -1);
    int fd = real_openat2(dirfd, pathname, how, size);
    SAVE_ERRNO;
    log_output_event("OPENAT2", pathname ? pathname : "");
    RESTORE_ERRNO;
    return fd;
}
int close(int fd) {
    static auto real_close = (int (*)(int)) nullptr;
    RESOLVE_REAL(real_close, "__libc_close", "close", -1);
    std::string in = fd_path(fd);
    int rc = real_close(fd);
    SAVE_ERRNO;
    log_unlink("CLOSE", in);
    RESTORE_ERRNO;
    return rc;
}
int close_range(unsigned int first, unsigned int last, int flags) {
    static auto real_close_range
        = (int (*)(unsigned int, unsigned int, int)) nullptr;
    RESOLVE_REAL(real_close_range, "__libc_close_range", "close_range", -1);
    int rc = real_close_range(first, last, flags);
    SAVE_ERRNO;
    log_output_event("CLOSE_RANGE", "");
    RESTORE_ERRNO;
    return rc;
}
int fclose(FILE* stream) {
    static auto real_fclose = (int (*)(FILE*)) nullptr;
    RESOLVE_REAL(real_fclose, "__libc_fclose", "fclose", -1);
    int fd = stream ? fileno(stream) : -1;
    std::string in = fd_path(fd);
    int rc = real_fclose(stream);
    SAVE_ERRNO;
    log_unlink("FCLOSE", in);
    RESTORE_ERRNO;
    return rc;
}
int pipe(int pipefd[2]) {
    static auto real_pipe = (int (*)(int[2])) nullptr;
    RESOLVE_REAL(real_pipe, "__libc_pipe", "pipe", -1);
    int rc = real_pipe(pipefd);
    SAVE_ERRNO;
    if (rc == 0) log_transfer_fd("PIPE", pipefd[0], pipefd[1]);
    RESTORE_ERRNO;
    return rc;
}
int pipe2(int pipefd[2], int flags) {
    static auto real_pipe2 = (int (*)(int[2], int)) nullptr;
    RESOLVE_REAL(real_pipe2, "__libc_pipe2", "pipe2", -1);
    int rc = real_pipe2(pipefd, flags);
    SAVE_ERRNO;
    if (rc == 0) log_transfer_fd("PIPE2", pipefd[0], pipefd[1]);
    RESTORE_ERRNO;
    return rc;
}
int dup(int oldfd) {
    static auto real_dup = (int (*)(int)) nullptr;
    RESOLVE_REAL(real_dup, "__libc_dup", "dup", -1);
    int newfd = real_dup(oldfd);
    SAVE_ERRNO;
    log_transfer_fd("DUP", oldfd, newfd);
    RESTORE_ERRNO;
    return newfd;
}
int dup2(int oldfd, int newfd) {
    static auto real_dup2 = (int (*)(int, int)) nullptr;
    RESOLVE_REAL(real_dup2, "__libc_dup2", "dup2", -1);
    int rc = real_dup2(oldfd, newfd);
    SAVE_ERRNO;
    log_transfer_fd("DUP2", oldfd, rc >= 0 ? rc : newfd);
    RESTORE_ERRNO;
    return rc;
}
int dup3(int oldfd, int newfd, int flags) {
    static auto real_dup3 = (int (*)(int, int, int)) nullptr;
    RESOLVE_REAL(real_dup3, "__libc_dup3", "dup3", -1);
    int rc = real_dup3(oldfd, newfd, flags);
    SAVE_ERRNO;
    log_transfer_fd("DUP3", oldfd, rc >= 0 ? rc : newfd);
    RESTORE_ERRNO;
    return rc;
}*/
// ------------------- MMAP/MUNMAP/MSYNC HOOKS ----------------
/*
void* mmap(void* addr, size_t length, int prot, int flags, int fd,
           off_t offset) {
    static auto real_mmap
        = (void* (*)(void*, size_t, int, int, int, off_t)) nullptr;
    RESOLVE_REAL(real_mmap, "__libc_mmap", "mmap", MAP_FAILED);
    void* ret = real_mmap(addr, length, prot, flags, fd, offset);
    SAVE_ERRNO;
    log_read_fd("MMAP", fd);
    RESTORE_ERRNO;
    return ret;
}
void* mmap64(void* addr, size_t length, int prot, int flags, int fd,
             off64_t offset) {
    static auto real_mmap64
        = (void* (*)(void*, size_t, int, int, int, off64_t)) nullptr;
    RESOLVE_REAL(real_mmap64, "__libc_mmap64", "mmap64", MAP_FAILED);
    void* ret = real_mmap64(addr, length, prot, flags, fd, offset);
    SAVE_ERRNO;
    log_read_fd("MMAP64", fd);
    RESTORE_ERRNO;
    return ret;
}
int munmap(void* addr, size_t length) {
    static auto real_munmap = (int (*)(void*, size_t)) nullptr;
    RESOLVE_REAL(real_munmap, "__libc_munmap", "munmap", -1);
    int rc = real_munmap(addr, length);
    SAVE_ERRNO;
    log_unlink("MUNMAP", "");
    RESTORE_ERRNO;
    return rc;
}
int msync(void* addr, size_t length, int flags) {
    static auto real_msync = (int (*)(void*, size_t, int)) nullptr;
    RESOLVE_REAL(real_msync, "__libc_msync", "msync", -1);
    int rc = real_msync(addr, length, flags);
    SAVE_ERRNO;
    log_unlink("MSYNC", "");
    RESTORE_ERRNO;
    return rc;
}
int mprotect(void* addr, size_t len, int prot) {
    static auto real_mprotect = (int (*)(void*, size_t, int)) nullptr;
    RESOLVE_REAL(real_mprotect, "__libc_mprotect", "mprotect", -1);
    int rc = real_mprotect(addr, len, prot);
    SAVE_ERRNO;
    log_output_event("MPROTECT", "");
    RESTORE_ERRNO;
    return rc;
}
int madvise(void* addr, size_t len, int advice) {
    static auto real_madvise = (int (*)(void*, size_t, int)) nullptr;
    RESOLVE_REAL(real_madvise, "__libc_madvise", "madvise", -1);
    int rc = real_madvise(addr, len, advice);
    SAVE_ERRNO;
    log_output_event("MADVISE", "");
    RESTORE_ERRNO;
    return rc;
}
int mincore(void* addr, size_t len, unsigned char* vec) {
    static auto real_mincore = (int (*)(void*, size_t, unsigned char*)) nullptr;
    RESOLVE_REAL(real_mincore, "__libc_mincore", "mincore", -1);
    int rc = real_mincore(addr, len, vec);
    SAVE_ERRNO;
    log_output_event("MINCORE", "");
    RESTORE_ERRNO;
    return rc;
}
*/
// ------------------- SIZE/SPACE METADATA HOOKS ----------------
/*
int ftruncate(int fd, off_t length) {
    static auto real_ftruncate = (int (*)(int, off_t)) nullptr;
    RESOLVE_REAL(real_ftruncate, "__libc_ftruncate", "ftruncate", -1);
    int rc = real_ftruncate(fd, length);
    SAVE_ERRNO;
    log_write_fd("FTRUNCATE", fd);
    RESTORE_ERRNO;
    return rc;
}
int truncate(const char* path, off_t length) {
    static auto real_truncate = (int (*)(const char*, off_t)) nullptr;
    RESOLVE_REAL(real_truncate, "__libc_truncate", "truncate", -1);
    int rc = real_truncate(path, length);
    SAVE_ERRNO;
    log_output_event("TRUNCATE", path ? path : "");
    RESTORE_ERRNO;
    return rc;
}
int posix_fadvise(int fd, off_t offset, off_t len, int advice) {
    static auto real_posix_fadvise = (int (*)(int, off_t, off_t, int)) nullptr;
    RESOLVE_REAL(real_posix_fadvise, "__libc_posix_fadvise", "posix_fadvise",
                 -1);
    int rc = real_posix_fadvise(fd, offset, len, advice);
    SAVE_ERRNO;
    log_write_fd("POSIX_FADVISE", fd);
    RESTORE_ERRNO;
    return rc;
}
int posix_fallocate(int fd, off_t offset, off_t len) {
    static auto real_posix_fallocate = (int (*)(int, off_t, off_t)) nullptr;
    RESOLVE_REAL(real_posix_fallocate, "__libc_posix_fallocate",
                 "posix_fallocate", -1);
    int rc = real_posix_fallocate(fd, offset, len);
    SAVE_ERRNO;
    log_write_fd("POSIX_FALLOCATE", fd);
    RESTORE_ERRNO;
    return rc;
}*/
//--------------- METADATA HOOKS -------------------------
/*int link(const char* oldpath, const char* newpath) {
    static auto real_link = (int (*)(const char*, const char*)) nullptr;
    RESOLVE_REAL(real_link, "__libc_link", "link", -1);
    int rc = real_link(oldpath, newpath);
    SAVE_ERRNO;
    log_rename("LINK", oldpath ? oldpath : "",
                           newpath ? newpath : "");
    RESTORE_ERRNO;
    return rc;
}
int linkat(int olddirfd, const char* oldpath, int newdirfd, const char* newpath,
           int flags) {
    static auto real_linkat
        = (int (*)(int, const char*, int, const char*, int)) nullptr;
    RESOLVE_REAL(real_linkat, "__libc_linkat", "linkat", -1);
    int rc = real_linkat(olddirfd, oldpath, newdirfd, newpath, flags);
    SAVE_ERRNO;
    log_rename("LINKAT", oldpath ? oldpath : "",
                           newpath ? newpath : "");
    RESTORE_ERRNO;
    return rc;
}
int symlink(const char* target, const char* linkpath) {
    static auto real_symlink = (int (*)(const char*, const char*)) nullptr;
    RESOLVE_REAL(real_symlink, "__libc_symlink", "symlink", -1);
    int rc = real_symlink(target, linkpath);
    SAVE_ERRNO;
    log_rename("SYMLINK", target ? target : "",
                           linkpath ? linkpath : "");
    RESTORE_ERRNO;
    return rc;
}
int symlinkat(const char* target, int newdirfd, const char* linkpath) {
    static auto real_symlinkat
        = (int (*)(const char*, int, const char*)) nullptr;
    RESOLVE_REAL(real_symlinkat, "__libc_symlinkat", "symlinkat", -1);
    int rc = real_symlinkat(target, newdirfd, linkpath);
    SAVE_ERRNO;
    log_rename("SYMLINKAT", target ? target : "",
                           linkpath ? linkpath : "");
    RESTORE_ERRNO;
    return rc;
}*/
int unlink(const char* pathname) {
    static auto real_unlink = (int (*)(const char*)) nullptr;
    RESOLVE_REAL(real_unlink, "__libc_unlink", "unlink", -1);
    int rc = real_unlink(pathname);
    SAVE_ERRNO;
    log_unlink(pathname ? pathname : "");
    RESTORE_ERRNO;
    return rc;
}
int unlinkat(int dirfd, const char* pathname, int flags) {
    static auto real_unlinkat = (int (*)(int, const char*, int)) nullptr;
    RESOLVE_REAL(real_unlinkat, "__libc_unlinkat", "unlinkat", -1);
    int rc = real_unlinkat(dirfd, pathname, flags);
    SAVE_ERRNO;
    log_unlink(pathname ? pathname : "");
    RESTORE_ERRNO;
    return rc;
}
int remove(const char* pathname) {
    static auto real_remove = (int (*)(const char*)) nullptr;
    RESOLVE_REAL(real_remove, "__libc_remove", "remove", -1);
    int rc = real_remove(pathname);
    SAVE_ERRNO;
    log_unlink(pathname ? pathname : "");
    RESTORE_ERRNO;
    return rc;
}
int rmdir(const char* pathname) {
    static auto real_rmdir = (int (*)(const char*)) nullptr;
    RESOLVE_REAL(real_rmdir, "__libc_rmdir", "rmdir", -1);
    int rc = real_rmdir(pathname);
    SAVE_ERRNO;
    log_unlink(pathname ? pathname : "");
    RESTORE_ERRNO;
    return rc;
}
int shm_unlink(const char* name) {
    static auto real_shm_unlink = (int (*)(const char*)) nullptr;
    RESOLVE_REAL(real_shm_unlink, "__libc_shm_unlink", "shm_unlink", -1);
    int rc = real_shm_unlink(name);
    SAVE_ERRNO;
    log_unlink(name ? name : "");
    RESTORE_ERRNO;
    return rc;
}
int mq_unlink(const char* name) {
    static auto real_mq_unlink = (int (*)(const char*)) nullptr;
    RESOLVE_REAL(real_mq_unlink, "__libc_mq_unlink", "mq_unlink", -1);
    int rc = real_mq_unlink(name);
    SAVE_ERRNO;
    log_unlink(name ? name : "");
    RESTORE_ERRNO;
    return rc;
}
int sem_unlink(const char* name) {
    static auto real_sem_unlink = (int (*)(const char*)) nullptr;
    RESOLVE_REAL(real_sem_unlink, "__libc_sem_unlink", "sem_unlink", -1);
    int rc = real_sem_unlink(name);
    SAVE_ERRNO;
    log_unlink(name ? name : "");
    RESTORE_ERRNO;
    return rc;
}
/*
int access(const char* path, int amode) {
    static auto real_access = (int (*)(const char*, int)) nullptr;
    RESOLVE_REAL(real_access, "__libc_access", "access", -1);
    int rc = real_access(path, amode);
    SAVE_ERRNO;
    log_unlink("ACCESS", path ? path : "");
    RESTORE_ERRNO;
    return rc;
}
int chmod(const char* path, mode_t mode) {
    static auto real_chmod = (int (*)(const char*, mode_t)) nullptr;
    RESOLVE_REAL(real_chmod, "__libc_chmod", "chmod", -1);
    int rc = real_chmod(path, mode);
    SAVE_ERRNO;
    log_output_event("CHMOD", path ? path : "");
    RESTORE_ERRNO;
    return rc;
}
int chown(const char* path, uid_t owner, gid_t group) {
    static auto real_chown = (int (*)(const char*, uid_t, gid_t)) nullptr;
    RESOLVE_REAL(real_chown, "__libc_chown", "chown", -1);
    int rc = real_chown(path, owner, group);
    SAVE_ERRNO;
    log_output_event("CHOWN", path ? path : "");
    RESTORE_ERRNO;
    return rc;
}
int utime(const char* path, const struct utimbuf* times) {
    static auto real_utime
        = (int (*)(const char*, const struct utimbuf*)) nullptr;
    RESOLVE_REAL(real_utime, "__libc_utime", "utime", -1);
    int rc = real_utime(path, times);
    SAVE_ERRNO;
    log_output_event("UTIME", path ? path : "");
    RESTORE_ERRNO;
    return rc;
}*/
}
