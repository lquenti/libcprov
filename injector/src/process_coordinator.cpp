#define _GNU_SOURCE

#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <simdjson.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdlib>
#include <filesystem>
#include <string>
#include <unordered_map>

static int PROV_SIG = SIGRTMAX - 3;

void set_env_variables(const std::string& path_exec,
                       const std::string& path_access) {
    std::string pid_str = std::to_string(getpid());
    setenv("PROV_PID", pid_str.c_str(), 1);
    std::string prov_sig_string = std::to_string(PROV_SIG);
    setenv("PROV_SIG", prov_sig_string.c_str(), 1);
    setenv("PROV_PATH_WRITE", path_access.c_str(), 1);
}

void start_preload_process(const std::string& so_path, const std::string& cmd,
                           const std::string& path_access) {
    std::filesystem::create_directory(path_access);
    pid_t pid = fork();
    if (pid == 0) {
        if (!so_path.empty()) setenv("LD_PRELOAD", so_path.c_str(), 1);
        execl("/bin/sh", "sh", "-c", cmd.c_str(), (char*)nullptr);
        _exit(127);
    } else if (pid > 0) {
        (void)waitpid(pid, nullptr, 0);
    }
}

void send_json(const std::string& url, const std::string& header,
               const std::string& json) {
    CURL* curl = curl_easy_init();
    if (!curl) return;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    std::string payload = header + json;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, payload.size());
    curl_easy_setopt(
        curl, CURLOPT_WRITEFUNCTION,
        +[](void*, size_t s, size_t n, void*) { return s * n; });
    curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}

static int pidfd_open_sys(pid_t pid, unsigned int flags) {
    return (int)syscall(SYS_pidfd_open, pid, flags);
}

static int sigpipe_fds[2] = {-1, -1};
static int epfd = -1;
static std::unordered_map<int, pid_t> live;
static bool seen_any = false;
static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void epoll_add_fd(int fd, uint32_t events) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.fd = fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) != 0) close(fd);
}

static void sig_handler(int sig, siginfo_t* info, void* uctx) {
    (void)sig;
    (void)uctx;
    pid_t pid = (pid_t)info->si_value.sival_int;
    (void)write(sigpipe_fds[1], &pid, sizeof(pid));
}

static void install_sig_pipe(void) {
    if (pipe(sigpipe_fds) != 0) _exit(1);
    set_nonblock(sigpipe_fds[0]);
    set_nonblock(sigpipe_fds[1]);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sig_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    if (sigaction(PROV_SIG, &sa, nullptr) != 0) _exit(1);
}

static void handle_new_pids_from_pipe(void) {
    for (;;) {
        pid_t pid;
        ssize_t r = read(sigpipe_fds[0], &pid, sizeof(pid));
        if (r == (ssize_t)sizeof(pid)) {
            seen_any = true;
            int pfd = pidfd_open_sys(pid, 0);
            if (pfd >= 0) {
                if (live.find(pfd) != live.end()) {
                    close(pfd);
                    continue;
                }
                live.emplace(pfd, pid);
                epoll_add_fd(pfd, EPOLLIN);
            }
        } else {
            break;
        }
    }
}

static void wait_until_all_tracked_exit(void) {
    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) _exit(1);
    epoll_add_fd(sigpipe_fds[0], EPOLLIN);
    struct epoll_event evs[64];
    bool first_phase = true;
    for (;;) {
        int timeout_ms = first_phase ? 10000 : -1;
        int n = epoll_wait(epfd, evs, 64, timeout_ms);
        if (n < 0) {
            if (errno == EINTR) continue;
            _exit(1);
        }
        if (n == 0 && first_phase) break;
        first_phase = false;
        for (int i = 0; i < n; i++) {
            int fd = evs[i].data.fd;
            if (fd == sigpipe_fds[0]) {
                handle_new_pids_from_pipe();
                continue;
            }
            auto it = live.find(fd);
            if (it != live.end()) {
                epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
                close(fd);
                live.erase(it);
            }
        }
        if (live.empty()) break;
    }
    close(epfd);
    epfd = -1;
}

void start_and_await_process(const std::string& injector_path,
                             const std::string& exec_command,
                             const std::string& injector_data_path) {
    install_sig_pipe();
    start_preload_process(injector_path, exec_command, injector_data_path);
    wait_until_all_tracked_exit();
}
