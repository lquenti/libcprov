#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char* msg) {
    perror(msg);
    _exit(1);
}

static void ensure_dir(const char* path) {
    if (mkdir(path, 0777) != 0 && errno != EEXIST) die("mkdir");
}

static void write_all(int fd, const void* buf, size_t n) {
    const unsigned char* p = (const unsigned char*)buf;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) die("write");
        p += (size_t)w;
        n -= (size_t)w;
    }
}

static void pread_some(int fd, off_t off, size_t n) {
    unsigned char* buf = (unsigned char*)malloc(n);
    if (!buf) die("malloc");
    ssize_t r = pread(fd, buf, n, off);
    if (r < 0) die("pread");
    free(buf);
}

static void pwrite_some(int fd, off_t off, const char* s) {
    ssize_t w = pwrite(fd, s, strlen(s), off);
    if (w < 0) die("pwrite");
}

typedef struct {
    int tid;
    char dir[512];
} thread_arg_t;

static void* worker_thread(void* vp) {
    thread_arg_t* a = (thread_arg_t*)vp;
    char path[512];
    snprintf(path, sizeof(path), "%s/t_shared_%d.txt", a->dir, a->tid % 2);
    int fd = open(path, O_CREAT | O_RDWR, 0644);
    if (fd < 0) die("open(thread)");
    char line[128];
    snprintf(line, sizeof(line), "thread=%d pid=%d hello\n", a->tid, getpid());
    write_all(fd, line, strlen(line));
    struct iovec iov[2];
    iov[0].iov_base = (void*)"iovA:";
    iov[0].iov_len = 5;
    iov[1].iov_base = (void*)"iovB\n";
    iov[1].iov_len = 5;
    if (writev(fd, iov, 2) < 0) die("writev(thread)");
    char pw[128];
    snprintf(pw, sizeof(pw), "PWRITE tid=%d pid=%d\n", a->tid, getpid());
    pwrite_some(fd, 0, pw);
    lseek(fd, 0, SEEK_SET);
    unsigned char rbuf[32];
    if (read(fd, rbuf, sizeof(rbuf)) < 0) die("read(thread)");
    pread_some(fd, 10, 24);
    unsigned char b1[8], b2[8];
    struct iovec riov[2] = {
        {.iov_base = b1, .iov_len = sizeof(b1)},
        {.iov_base = b2, .iov_len = sizeof(b2)},
    };
    if (readv(fd, riov, 2) < 0) die("readv(thread)");
    close(fd);
    return NULL;
}

static void threaded_phase(const char* dir, int nthreads) {
    pthread_t* th = (pthread_t*)calloc((size_t)nthreads, sizeof(pthread_t));
    thread_arg_t* args
        = (thread_arg_t*)calloc((size_t)nthreads, sizeof(thread_arg_t));
    if (!th || !args) die("calloc");
    for (int i = 0; i < nthreads; i++) {
        args[i].tid = i;
        snprintf(args[i].dir, sizeof(args[i].dir), "%s", dir);
        if (pthread_create(&th[i], NULL, worker_thread, &args[i]) != 0)
            die("pthread_create");
    }
    for (int i = 0; i < nthreads; i++) {
        if (pthread_join(th[i], NULL) != 0) die("pthread_join");
    }
    free(th);
    free(args);
}

static void simple_file_ops(const char* dir, const char* tag) {
    char p[512];
    snprintf(p, sizeof(p), "%s/%s_seq.txt", dir, tag);
    int fd = open(p, O_CREAT | O_TRUNC | O_RDWR, 0644);
    if (fd < 0) die("open(seq)");
    dprintf(fd, "tag=%s pid=%d start\n", tag, getpid());
    write_all(fd, "plain_write\n", 12);
    pwrite_some(fd, 5, "PWR\n");
    lseek(fd, 0, SEEK_SET);
    char buf[64];
    (void)read(fd, buf, sizeof(buf));
    close(fd);
}

static void child_process(const char* dir, int child_idx) {
    char tag[32];
    snprintf(tag, sizeof(tag), "child%d", child_idx);
    simple_file_ops(dir, tag);
    threaded_phase(dir, 4);
    char p1[512], p2[512];
    snprintf(p1, sizeof(p1), "%s/%s_rename_me.txt", dir, tag);
    snprintf(p2, sizeof(p2), "%s/%s_renamed.txt", dir, tag);
    int fd = open(p1, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0) die("open(rename_me)");
    write_all(fd, "rename_test\n", 12);
    close(fd);
    if (rename(p1, p2) != 0) die("rename");
    if (unlink(p2) != 0) die("unlink");
    _exit(0);
}

int main(int argc, char** argv) {
    const char* dir = (argc > 1) ? argv[1] : "/dev/shm/prov_test_mt_mp";
    int nchildren = (argc > 2) ? atoi(argv[2]) : 3;
    sleep(1);
    ensure_dir("/dev/shm");
    ensure_dir(dir);
    simple_file_ops(dir, "parent");
    threaded_phase(dir, 6);
    for (int i = 0; i < nchildren; i++) {
        pid_t p = fork();
        if (p < 0) die("fork");
        if (p == 0) child_process(dir, i);
    }
    for (int i = 0; i < nchildren; i++) {
        int st = 0;
        if (wait(&st) < 0) die("wait");
    }
    for (int k = 0; k < 2; k++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/t_shared_%d.txt", dir, k);
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            char buf[128];
            (void)read(fd, buf, sizeof(buf));
            close(fd);
        }
    }
    return 0;
}
