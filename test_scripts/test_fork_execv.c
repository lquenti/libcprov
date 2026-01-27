#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char* msg) {
    perror(msg);
    exit(1);
}
static void ensure_dir(const char* path) {
    if (mkdir(path, 0777) != 0 && errno != EEXIST) die("mkdir");
}
static void append_line(const char* path, const char* line) {
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) die("open");
    if (write(fd, line, strlen(line)) < 0) die("write");
    close(fd);
}
static void write_mark(const char* dir, const char* tag) {
    char path[512];
    char line[512];
    snprintf(path, sizeof(path), "%s/%s.txt", dir, tag);
    snprintf(line, sizeof(line), "%s pid=%d ppid=%d errno=%d\n", tag, getpid(),
             getppid(), errno);
    append_line(path, line);
}
static void exec_self(const char* self, const char* role, const char* dir) {
    char* const argv[] = {(char*)self, (char*)role, (char*)dir, NULL};
    execv(self, argv);
    _exit(127);
}
int main(int argc, char** argv) {
    const char* dir = "/dev/shm/execv_fail_test";
    ensure_dir("/dev/shm");
    ensure_dir(dir);
    const char* role = (argc > 1) ? argv[1] : "A";
    if (strcmp(role, "A") == 0) {
        write_mark(dir, "A");
        pid_t pid = fork();
        if (pid < 0) die("fork");
        if (pid == 0) exec_self(argv[0], "B", dir);
        waitpid(pid, NULL, 0);
        return 0;
    }
    if (strcmp(role, "B") == 0) {
        write_mark(dir, "B");
        exec_self(argv[0], "C", dir);
    }
    if (strcmp(role, "C") == 0) {
        write_mark(dir, "C");
        exec_self(argv[0], "D", dir);
    }
    if (strcmp(role, "D") == 0) {
        write_mark(dir, "D_before_exec");
        char* const bad_argv[]
            = {(char*)"/definitely/not/a/real/binary", (char*)"E", NULL};
        execv(bad_argv[0], bad_argv);
        write_mark(dir, "D_after_failed_exec");
        return 0;
    }
    write_mark(dir, "UNKNOWN");
    return 0;
}
