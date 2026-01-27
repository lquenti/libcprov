#!/usr/bin/env python3
import os
import time
import shutil
import subprocess

DIR = "/dev/shm/prov_test"

def ensure_dir(p):
    os.makedirs(p, exist_ok=True)

def write_file(path, data: bytes):
    with open(path, "wb") as f:
        f.write(data)

def test_write_family(dirp):
    p1 = os.path.join(dirp, "write.txt")
    p2 = os.path.join(dirp, "fprintf.txt")
    p3 = os.path.join(dirp, "pwrite.txt")
    fd = os.open(p1, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    os.write(fd, b"hello\n")
    os.write(fd, b"vec")
    os.write(fd, b"tor\n")
    if hasattr(os, "pwrite"):
        os.pwrite(fd, b"PWRITE\n", 0)
    os.close(fd)
    with open(p2, "w", buffering=1) as f:
        f.write("fputs\n")
        f.write("X\n")
        f.write(f"fprintf {123}\n")
        f.write("fwrite\n")
        f.flush()
    fd3 = os.open(p3, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    if hasattr(os, "pwrite"):
        os.pwrite(fd3, b"PWRITE64\n", 0)
    else:
        os.write(fd3, b"PWRITE64\n")
    os.close(fd3)
    fdout = os.open(p1, os.O_WRONLY | os.O_APPEND)
    os.write(fdout, f"dprintf {'ok'}\n".encode("utf-8"))
    os.close(fdout)

def test_read_family(dirp):
    src = os.path.join(dirp, "read_src.txt")
    dst = os.path.join(dirp, "read_dst.txt")
    write_file(src, b"0123456789abcdef\n")
    fd = os.open(src, os.O_RDONLY)
    os.read(fd, 8)
    if hasattr(os, "pread"):
        os.pread(fd, 8, 2)
        os.pread(fd, 8, 3)
    os.read(fd, 8)
    os.close(fd)
    with open(src, "r") as f:
        _ = f.readline()
        _ = f.read(1)
        f.seek(0)
        _ = f.read(16)
    with open(dst, "wb") as f:
        f.write(b"ok\n")

def test_transfer_family(dirp):
    src = os.path.join(dirp, "transfer_src.bin")
    dst1 = os.path.join(dirp, "transfer_dst_sendfile.bin")
    dst2 = os.path.join(dirp, "transfer_dst_copy.bin")
    write_file(src, b"abcdefghijklmnopqrstuvwxyz0123456789\n")
    if hasattr(os, "sendfile"):
        in_fd = os.open(src, os.O_RDONLY)
        out_fd = os.open(dst1, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        st = os.fstat(in_fd)
        offset = 0
        remaining = st.st_size
        while remaining > 0:
            sent = os.sendfile(out_fd, in_fd, offset, remaining)
            if sent == 0:
                break
            offset += sent
            remaining -= sent
        os.close(out_fd)
        os.close(in_fd)
    else:
        shutil.copyfile(src, dst1)
    shutil.copyfile(src, dst2)

def test_rename_unlink(dirp):
    p1 = os.path.join(dirp, "rename_me.txt")
    p2 = os.path.join(dirp, "renamed.txt")
    p3 = os.path.join(dirp, "unlink_me.txt")
    write_file(p1, b"rename\n")
    os.rename(p1, p2)
    write_file(p3, b"unlink\n")
    os.unlink(p3)
    os.unlink(p2)

def test_exec_hooks(dirp):
    child = os.path.join(dirp, "child_exec_test")
    script = "#!/bin/sh\necho child_exec_ok\n"
    with open(child, "w") as f:
        f.write(script)
    os.chmod(child, 0o755)
    subprocess.run([child], check=False)
    subprocess.run([child], check=False)
    subprocess.run(["sh", "-c", "echo execvp_ok"], check=False)
    env = dict(os.environ)
    subprocess.run(["sh", "-c", "echo execvpe_ok"], env=env, check=False)

def main():
    time.sleep(3)
    ensure_dir("/dev/shm")
    ensure_dir(DIR)
    test_write_family(DIR)
    test_read_family(DIR)
    test_transfer_family(DIR)
    test_rename_unlink(DIR)
    test_exec_hooks(DIR)

if __name__ == "__main__":
    main()
