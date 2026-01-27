#!/usr/bin/env Rscript

dirp <- "/dev/shm/prov_test"

ensure_dir <- function(p) {
  if (!dir.exists(p)) dir.create(p, recursive = TRUE, mode = "0777")
}

write_file <- function(path, data) {
  con <- file(path, open = "wb")
  on.exit(close(con), add = TRUE)
  writeBin(charToRaw(data), con)
}

test_write_family <- function(dirp) {
  p1 <- file.path(dirp, "write.txt")
  p2 <- file.path(dirp, "fprintf.txt")
  p3 <- file.path(dirp, "pwrite.txt")
  con1 <- file(p1, open = "wb")
  on.exit(close(con1), add = TRUE)
  writeBin(charToRaw("hello\n"), con1)
  writeBin(charToRaw("vector\n"), con1)
  close(con1)
  con2 <- file(p2, open = "wt")
  writeLines("fputs", con2)
  writeChar("X\n", con2, eos = NULL)
  writeLines(sprintf("fprintf %d", 123), con2)
  writeLines("fwrite", con2)
  flush(con2)
  close(con2)
  con3 <- file(p3, open = "wb")
  writeBin(charToRaw("PWRITE64\n"), con3)
  close(con3)
  cona <- file(p1, open = "at")
  writeLines(sprintf("dprintf %s", "ok"), cona)
  close(cona)
}

test_read_family <- function(dirp) {
  src <- file.path(dirp, "read_src.txt")
  dst <- file.path(dirp, "read_dst.txt")
  write_file(src, "0123456789abcdef\n")
  con <- file(src, open = "rb")
  on.exit(close(con), add = TRUE)
  readBin(con, "raw", n = 8)
  seek(con, 2, origin = "start")
  readBin(con, "raw", n = 8)
  seek(con, 3, origin = "start")
  readBin(con, "raw", n = 8)
  close(con)
  con2 <- file(src, open = "rt")
  readLines(con2, n = 1)
  readChar(con2, nchars = 1)
  seek(con2, 0, origin = "start")
  readChar(con2, nchars = 16, useBytes = TRUE)
  close(con2)
  conw <- file(dst, open = "wb")
  writeBin(charToRaw("ok\n"), conw)
  close(conw)
}

test_transfer_family <- function(dirp) {
  src <- file.path(dirp, "transfer_src.bin")
  dst1 <- file.path(dirp, "transfer_dst_sendfile.bin")
  dst2 <- file.path(dirp, "transfer_dst_copy.bin")
  write_file(src, "abcdefghijklmnopqrstuvwxyz0123456789\n")
  file.copy(src, dst1, overwrite = TRUE)
  file.copy(src, dst2, overwrite = TRUE)
}

test_rename_unlink <- function(dirp) {
  p1 <- file.path(dirp, "rename_me.txt")
  p2 <- file.path(dirp, "renamed.txt")
  p3 <- file.path(dirp, "unlink_me.txt")
  write_file(p1, "rename\n")
  file.rename(p1, p2)
  write_file(p3, "unlink\n")
  unlink(p3)
  unlink(p2)
}

test_exec_hooks <- function(dirp) {
  child <- file.path(dirp, "child_exec_test")
  script <- "#!/bin/sh\necho child_exec_ok\n"
  writeLines(script, child)
  Sys.chmod(child, mode = "0755")
  system(child, ignore.stdout = FALSE, ignore.stderr = FALSE)
  system2("sh", c("-c", "echo execvp_ok"))
  system2("sh", c("-c", "echo execvpe_ok"), env = Sys.getenv())
}

Sys.sleep(3)
ensure_dir("/dev/shm")
ensure_dir(dirp)
test_write_family(dirp)
test_read_family(dirp)
test_transfer_family(dirp)
test_rename_unlink(dirp)
test_exec_hooks(dirp)
