package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

const dirp = "/dev/shm/prov_test"

func ensureDir(p string) {
	_ = os.MkdirAll(p, 0o777)
}

func writeFile(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		panic(err)
	}
}

func testWriteFamily(dir string) {
	p1 := filepath.Join(dir, "write.txt")
	p2 := filepath.Join(dir, "fprintf.txt")
	p3 := filepath.Join(dir, "pwrite.txt")
	f1, err := os.OpenFile(p1, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		panic(err)
	}
	_, _ = f1.Write([]byte("hello\n"))
	_, _ = f1.Write([]byte("vector\n"))
	_, _ = f1.WriteAt([]byte("PWRITE\n"), 0)
	_ = f1.Close()
	f2, err := os.OpenFile(p2, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		panic(err)
	}
	_, _ = f2.Write([]byte("fputs\n"))
	_, _ = f2.Write([]byte("X\n"))
	_, _ = fmt.Fprintf(f2, "fprintf %d\n", 123)
	_, _ = f2.Write([]byte("fwrite\n"))
	_ = f2.Sync()
	_ = f2.Close()
	f3, err := os.OpenFile(p3, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		panic(err)
	}
	_, _ = f3.WriteAt([]byte("PWRITE64\n"), 0)
	_ = f3.Close()
	fa, err := os.OpenFile(p1, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		panic(err)
	}
	_, _ = fmt.Fprintf(fa, "dprintf %s\n", "ok")
	_ = fa.Close()
}

func testReadFamily(dir string) {
	src := filepath.Join(dir, "read_src.txt")
	dst := filepath.Join(dir, "read_dst.txt")
	writeFile(src, []byte("0123456789abcdef\n"))
	f, err := os.Open(src)
	if err != nil {
		panic(err)
	}
	buf := make([]byte, 8)
	_, _ = f.Read(buf)
	_, _ = f.ReadAt(buf, 2)
	_, _ = f.ReadAt(buf, 3)
	_, _ = f.Read(buf)
	_ = f.Close()
	if err := os.WriteFile(dst, []byte("ok\n"), 0o644); err != nil {
		panic(err)
	}
}

func testTransferFamily(dir string) {
	src := filepath.Join(dir, "transfer_src.bin")
	dst1 := filepath.Join(dir, "transfer_dst_sendfile.bin")
	dst2 := filepath.Join(dir, "transfer_dst_copy.bin")
	writeFile(src, []byte("abcdefghijklmnopqrstuvwxyz0123456789\n"))
	copyFile := func(a, b string) {
		in, err := os.Open(a)
		if err != nil {
			panic(err)
		}
		defer in.Close()
		out, err := os.OpenFile(b, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			panic(err)
		}
		defer out.Close()
		_, _ = io.Copy(out, in)
	}
	copyFile(src, dst1)
	copyFile(src, dst2)
}

func testRenameUnlink(dir string) {
	p1 := filepath.Join(dir, "rename_me.txt")
	p2 := filepath.Join(dir, "renamed.txt")
	p3 := filepath.Join(dir, "unlink_me.txt")
	writeFile(p1, []byte("rename\n"))
	_ = os.Rename(p1, p2)
	writeFile(p3, []byte("unlink\n"))
	_ = os.Remove(p3)
	_ = os.Remove(p2)
}

func testExecHooks(dir string) {
	child := filepath.Join(dir, "child_exec_test")
	script := "#!/bin/sh\necho child_exec_ok\n"
	if err := os.WriteFile(child, []byte(script), 0o755); err != nil {
		panic(err)
	}
	_ = exec.Command(child).Run()
	_ = exec.Command("sh", "-c", "echo execvp_ok").Run()
	cmd := exec.Command("sh", "-c", "echo execvpe_ok")
	cmd.Env = os.Environ()
	_ = cmd.Run()
}

func main() {
	ensureDir("/dev/shm")
	ensureDir(dirp)
	testWriteFamily(dirp)
	testReadFamily(dirp)
	testTransferFamily(dirp)
	testRenameUnlink(dirp)
	testExecHooks(dirp)
}
