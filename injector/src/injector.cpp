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
#include <functional>
#include <mutex>
#include <queue>
#include <random>
#include <string>
#include <unordered_set>
#include <vector>

struct linux_dirent;
struct linux_dirent64;

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

static std::string get_full_cmd() {
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

static uint64_t random_id() {
    static thread_local std::mt19937_64 gen{std::random_device{}()};
    static thread_local std::uniform_int_distribution<uint64_t> dist;
    return dist(gen);
}

static long set_prov_pid() {
    const char* env = getenv("PROV_PID");
    char* endptr;
    return strtol(env, &endptr, 10);
}

static atomic_bool after_failed_execv = ATOMIC_VAR_INIT(false);
static std::string nodename = std::to_string(random_id());
static long prov_pid = set_prov_pid();

enum : uint32_t {
    EV_PROCESS_START = 1,
    EV_PROCESS_END = 2,
    EV_READ = 3,
    EV_WRITE = 4,
    EV_TRANSFER = 5,
    EV_RENAME = 6,
    EV_UNLINK = 7,
    EV_EXEC = 8,
    EV_EXEC_FAIL = 9
};

#pragma pack(push, 1)
struct RecHdr {
    uint32_t type;
    uint32_t size;
    uint64_t ts_ns;
    int32_t pid;
    int32_t tid;
};
#pragma pack(pop)

static_assert(sizeof(RecHdr) == 24);

static std::vector<uint8_t> event_buf;
static std::mutex buf_mutex;

static inline int32_t gettid32() {
    return (int32_t)syscall(SYS_gettid);
}

static inline uint64_t now_ns_u64() {
    using namespace std::chrono;
    return (uint64_t)duration_cast<nanoseconds>(
               system_clock::now().time_since_epoch())
        .count();
}

static inline void buf_append_locked(const void* p, size_t n) {
    size_t old = event_buf.size();
    event_buf.resize(old + n);
    memcpy(event_buf.data() + old, p, n);
}

static inline void buf_append_u32(uint32_t v) {
    buf_append_locked(&v, sizeof(v));
}

static inline void buf_append_str(const std::string& s) {
    uint32_t len = (uint32_t)s.size();
    buf_append_u32(len);
    if (len) buf_append_locked(s.data(), len);
}

static inline void add_record(uint32_t type, uint64_t ts_ns,
                              const std::function<void()>& payload_writer) {
    std::lock_guard<std::mutex> g(buf_mutex);
    RecHdr rec_hdr;
    rec_hdr.type = type;
    rec_hdr.ts_ns = ts_ns;
    rec_hdr.pid = (int32_t)getpid();
    rec_hdr.tid = gettid32();
    rec_hdr.size = 0;
    size_t start = event_buf.size();
    buf_append_locked(&rec_hdr, sizeof(rec_hdr));
    payload_writer();
    size_t end = event_buf.size();
    uint32_t total = (uint32_t)(end - start);
    memcpy(event_buf.data() + start + offsetof(RecHdr, size), &total,
           sizeof(total));
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

static void log_rename(const std::string original_path,
                       const std::string new_path) {
    uint64_t ts = now_ns_u64();
    add_record(EV_RENAME, ts, [&] {
        buf_append_str(original_path);
        buf_append_str(new_path);
    });
}

static void log_read_fd(int path_in_fd) {
    std::string path_in = fd_path(path_in_fd);
    uint64_t ts = now_ns_u64();
    add_record(EV_READ, ts, [&] {
        int32_t fd = (int32_t)path_in_fd;
        buf_append_locked(&fd, sizeof(fd));
        buf_append_str(path_in);
    });
}

static void log_write_fd(int path_out_fd) {
    std::string path_out = fd_path(path_out_fd);
    uint64_t ts = now_ns_u64();
    add_record(EV_WRITE, ts, [&] {
        int32_t fd = (int32_t)path_out_fd;
        buf_append_locked(&fd, sizeof(fd));
        buf_append_str(path_out);
    });
}

static void log_transfer_fd(int path_read_fd, int path_write_fd) {
    std::string path_read = fd_path(path_read_fd);
    std::string path_write = fd_path(path_write_fd);
    uint64_t ts = now_ns_u64();
    add_record(EV_TRANSFER, ts, [&] {
        int32_t rfd = (int32_t)path_read_fd;
        int32_t wfd = (int32_t)path_write_fd;
        buf_append_locked(&rfd, sizeof(rfd));
        buf_append_locked(&wfd, sizeof(wfd));
        buf_append_str(path_read);
        buf_append_str(path_write);
    });
}

static void log_exec() {
    setenv("AFTER_EXECV", "true", 1);
    uint64_t ts = now_ns_u64();
    add_record(EV_EXEC, ts, [&] {});
}

static void log_exec_fail() {
    unsetenv("AFTER_EXECV");
    uint64_t ts = now_ns_u64();
    add_record(EV_EXEC_FAIL, ts, [&] {});
}

static void log_unlink(std::string path) {
    uint64_t ts = now_ns_u64();
    add_record(EV_UNLINK, ts, [&] { buf_append_str(path); });
}

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
    uint64_t ts = now_ns_u64();
    pid_t pid = getpid();
    pid_t ppid = getppid();
    std::string launch_command = get_full_cmd();
    std::string env_variables_string = get_env_variables_string();
    add_record(EV_PROCESS_START, ts, [&] {
        int32_t pid32 = (int32_t)pid;
        int32_t ppid32 = (int32_t)ppid;
        buf_append_locked(&pid32, sizeof(pid32));
        buf_append_locked(&ppid32, sizeof(ppid32));
        buf_append_str(launch_command);
        buf_append_str(env_variables_string);
    });
}

static void log_process_end() {
    uint64_t ts = now_ns_u64();
    add_record(EV_PROCESS_END, ts, [&] {});
}

static bool get_after_failed_execv(void) {
    return atomic_load_explicit(&after_failed_execv, memory_order_relaxed);
}

static std::string make_output_path() {
    return get_env("PROV_PATH_WRITE") + "/" + nodename + "_"
           + std::to_string(getpid()) + ".bin";
}

static void flush_buffer_to_file() {
    std::string path = make_output_path();
    int fd = (int)syscall(SYS_open, path.c_str(), O_WRONLY | O_CREAT | O_APPEND,
                          0644);
    if (fd < 0) return;
    std::lock_guard<std::mutex> g(buf_mutex);
    if (!event_buf.empty()) {
        (void)syscall(SYS_write, fd, event_buf.data(), event_buf.size());
        event_buf.clear();
    }
    (void)syscall(SYS_close, fd);
}

static long prov_pid_from_env(void) {
    const char* s = getenv("PROV_PID");
    if (!s) return -1;
    char* end = 0;
    long v = strtol(s, &end, 10);
    return (end && *end == '\0') ? v : -1;
}

static int prov_sig_from_env(void) {
    const char* s = getenv("PROV_SIG");
    if (!s || !*s) return -1;
    char* end = nullptr;
    long v = strtol(s, &end, 10);
    if (!end || *end != '\0') return -1;
    if (v <= 0 || v >= NSIG) return -1;
    return (int)v;
}

static void notify_start() {
    int sig = prov_sig_from_env();
    long prov = prov_pid_from_env();
    if (sig < 0 || prov <= 1) return;
    union sigval v;
    v.sival_int = (int)getpid();
    (void)sigqueue((pid_t)prov, sig, v);
}

__attribute__((constructor)) static void preload_init(void) {
    if (std::getenv("AFTER_EXECV") == nullptr) {
        notify_start();
    } else {
        unsetenv("AFTER_EXECV");
    }
    log_process_start();
}

__attribute__((destructor)) static void preload_fini(void) {
    log_process_end();
    flush_buffer_to_file();
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

static char** build_argv_from_varargs(const char* first, va_list ap) {
    size_t n = 0;
    va_list ap2;
    va_copy(ap2, ap);
    for (const char* s = first; s; s = va_arg(ap2, const char*)) n++;
    va_end(ap2);

    char** argv = (char**)malloc((n + 1) * sizeof(char*));
    if (!argv) return NULL;

    size_t i = 0;
    for (const char* s = first; s; s = va_arg(ap, const char*))
        argv[i++] = (char*)s;
    argv[i] = NULL;
    return argv;
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
// --------------------- EXEC HOOKS -----------------------
int execve(const char* pathname, char* const argv[], char* const envp[]) {
    static auto real_execve
        = (int (*)(const char*, char* const[], char* const[])) nullptr;
    RESOLVE_REAL(real_execve, "__libc_execve", "execve", -1);
    log_exec();
    flush_buffer_to_file();
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
    flush_buffer_to_file();
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
    flush_buffer_to_file();
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
    flush_buffer_to_file();
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
    flush_buffer_to_file();
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
    flush_buffer_to_file();
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
    flush_buffer_to_file();
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
    flush_buffer_to_file();
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
    flush_buffer_to_file();
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
}
