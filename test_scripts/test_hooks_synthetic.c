#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char* msg) {
    perror(msg);
    exit(1);
}

static void ensure_dir(const char* path) {
    if (mkdir(path, 0777) != 0 && errno != EEXIST) die("mkdir");
}

static void write_file(const char* path, const char* data) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) die("open write_file");
    ssize_t n = write(fd, data, strlen(data));
    if (n < 0) die("write");
    if (close(fd) != 0) die("close");
}

static int open_ro(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) die("open_ro");
    return fd;
}

static int open_rw(const char* path) {
    int fd = open(path, O_RDWR);
    if (fd < 0) die("open_rw");
    return fd;
}

static void test_write_family(const char* dir) {
    char p1[512], p2[512], p3[512];
    snprintf(p1, sizeof(p1), "%s/write.txt", dir);
    snprintf(p2, sizeof(p2), "%s/fprintf.txt", dir);
    snprintf(p3, sizeof(p3), "%s/pwrite.txt", dir);
    int fd1 = open(p1, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd1 < 0) die("open write.txt");
    if (write(fd1, "hello\n", 6) < 0) die("write");
    struct iovec iov[2];
    iov[0].iov_base = (void*)"vec";
    iov[0].iov_len = 3;
    iov[1].iov_base = (void*)"tor\n";
    iov[1].iov_len = 4;
    if (writev(fd1, iov, 2) < 0) die("writev");
    if (pwrite(fd1, "PWRITE\n", 7, 0) < 0) die("pwrite");
    if (close(fd1) != 0) die("close fd1");
    FILE* f = fopen(p2, "w");
    if (!f) die("fopen fprintf.txt");
    if (fputs("fputs\n", f) < 0) die("fputs");
    if (fputc('X', f) == EOF) die("fputc");
    if (fputc('\n', f) == EOF) die("fputc");
    if (fprintf(f, "fprintf %d\n", 123) < 0) die("fprintf");
    if (fwrite("fwrite\n", 1, 6, f) != 6) die("fwrite");
    if (fflush(f) != 0) die("fflush");
    if (fclose(f) != 0) die("fclose");
    int fd3 = open(p3, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd3 < 0) die("open pwrite.txt");
    if (pwrite64(fd3, "PWRITE64\n", 9, 0) < 0) die("pwrite64");
    if (close(fd3) != 0) die("close fd3");
    int fdout = open(p1, O_WRONLY | O_APPEND);
    if (fdout < 0) die("open append");
    if (dprintf(fdout, "dprintf %s\n", "ok") < 0) die("dprintf");
    if (close(fdout) != 0) die("close fdout");
}

static void test_read_family(const char* dir) {
    char src[512], dst[512];
    snprintf(src, sizeof(src), "%s/read_src.txt", dir);
    snprintf(dst, sizeof(dst), "%s/read_dst.txt", dir);
    write_file(src, "0123456789abcdef\n");
    int fdr = open_ro(src);
    char buf[8];
    if (read(fdr, buf, sizeof(buf)) < 0) die("read");
    if (pread(fdr, buf, sizeof(buf), 2) < 0) die("pread");
    if (pread64(fdr, buf, sizeof(buf), 3) < 0) die("pread64");
    struct iovec iov[2];
    char b1[4], b2[4];
    iov[0].iov_base = b1;
    iov[0].iov_len = sizeof(b1);
    iov[1].iov_base = b2;
    iov[1].iov_len = sizeof(b2);
    if (readv(fdr, iov, 2) < 0) die("readv");
    if (close(fdr) != 0) die("close fdr");
    FILE* f = fopen(src, "r");
    if (!f) die("fopen read_src.txt");
    char line[64];
    if (!fgets(line, sizeof(line), f)) die("fgets");
    if (fgetc(f) == EOF) {
    }
    if (getc(f) == EOF) {
    }
    if (fseek(f, 0, SEEK_SET) != 0) die("fseek");
    char rbuf[16];
    fread(rbuf, 1, sizeof(rbuf), f);
    fclose(f);
    int fdw = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fdw < 0) die("open read_dst.txt");
    if (write(fdw, "ok\n", 3) < 0) die("write dst");
    close(fdw);
}

static void test_transfer_family(const char* dir) {
    char src[512], dst1[512], dst2[512];
    snprintf(src, sizeof(src), "%s/transfer_src.bin", dir);
    snprintf(dst1, sizeof(dst1), "%s/transfer_dst_sendfile.bin", dir);
    snprintf(dst2, sizeof(dst2), "%s/transfer_dst_copy.bin", dir);
    write_file(src, "abcdefghijklmnopqrstuvwxyz0123456789\n");
    int in = open_ro(src);
    int out = open(dst1, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) die("open dst1");
    struct stat st;
    if (fstat(in, &st) != 0) die("fstat");
    off_t off = 0;
    if (sendfile(out, in, &off, (size_t)st.st_size) < 0) die("sendfile");
    close(out);
    close(in);
    int in2 = open_ro(src);
    int out2 = open(dst2, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out2 < 0) die("open dst2");
    off64_t off_in = 0, off_out = 0;
    close(out2);
    close(in2);
}

static void test_rename_unlink(const char* dir) {
    char p1[512], p2[512], p3[512];
    snprintf(p1, sizeof(p1), "%s/rename_me.txt", dir);
    snprintf(p2, sizeof(p2), "%s/renamed.txt", dir);
    snprintf(p3, sizeof(p3), "%s/unlink_me.txt", dir);
    write_file(p1, "rename\n");
    if (rename(p1, p2) != 0) die("rename");
    write_file(p3, "unlink\n");
    if (unlink(p3) != 0) die("unlink");
    if (unlink(p2) != 0) die("unlink renamed");
}

static void test_exec_hooks(const char* dir, const char* self_path) {
    char child_path[512];
    snprintf(child_path, sizeof(child_path), "%s/child_exec_test", dir);
    int fd = open(child_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) die("open child");
    const char* script
        = "#!/bin/sh\n"
          "echo child_exec_ok\n";
    if (write(fd, script, strlen(script)) < 0) die("write child");
    if (close(fd) != 0) die("close child");
    pid_t p = fork();
    if (p < 0) die("fork");
    if (p == 0) {
        char* const argv[] = {(char*)child_path, NULL};
        execve(child_path, argv, environ);
        _exit(127);
    }
    int st = 0;
    waitpid(p, &st, 0);
    pid_t p2 = fork();
    if (p2 < 0) die("fork2");
    if (p2 == 0) {
        execl(child_path, child_path, (char*)NULL);
        _exit(127);
    }
    waitpid(p2, &st, 0);
    pid_t p3 = fork();
    if (p3 < 0) die("fork3");
    if (p3 == 0) {
        char* const argv[] = {(char*)child_path, NULL};
        execv(child_path, argv);
        _exit(127);
    }
    waitpid(p3, &st, 0);
    pid_t p4 = fork();
    if (p4 < 0) die("fork4");
    if (p4 == 0) {
        execlp("sh", "sh", "-c", "echo execvp_ok", (char*)NULL);
        _exit(127);
    }
    waitpid(p4, &st, 0);
    pid_t p5 = fork();
    if (p5 < 0) die("fork5");
    if (p5 == 0) {
        char* const argv[]
            = {(char*)"sh", (char*)"-c", (char*)"echo execvpe_ok", NULL};
        execvpe("sh", argv, environ);
        _exit(127);
    }
    waitpid(p5, &st, 0);
    (void)self_path;
}

int main(int argc, char** argv) {
    const char* dir = "/dev/shm/prov_test";
    ensure_dir("/dev/shm");
    ensure_dir(dir);
    test_write_family(dir);
    test_read_family(dir);
    test_transfer_family(dir);
    test_rename_unlink(dir);
    const char* self_path = (argc > 0) ? argv[0] : "./prov_hook_test";
    test_exec_hooks(dir, self_path);
    return 0;
}
