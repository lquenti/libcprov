#!/usr/bin/env Rscript

die <- function(msg) {
  stop(msg, call. = FALSE)
}

ensure_dir <- function(path) {
  if (!dir.exists(path)) {
    ok <- dir.create(path, recursive = TRUE, mode = "0777")
    if (!ok) die(paste("dir.create failed:", path))
  }
}

write_file <- function(path, data) {
  ok <- writeLines(text = data, con = path, sep = "")
  invisible(ok)
}

test_write_family <- function(dir) {
  p1 <- file.path(dir, "write.txt")
  p2 <- file.path(dir, "fprintf.txt")
  p3 <- file.path(dir, "pwrite.txt")
  con1 <- file(p1, open = "wb")
  on.exit(try(close(con1), silent = TRUE), add = TRUE)
  writeBin(charToRaw("hello\n"), con1)
  writeBin(charToRaw("vec"), con1)
  writeBin(charToRaw("tor\n"), con1)
  seek(con1, where = 0, origin = "start")
  writeBin(charToRaw("PWRITE\n"), con1)
  close(con1)
  con1a <- file(p1, open = "ab")
  on.exit(try(close(con1a), silent = TRUE), add = TRUE)
  writeBin(charToRaw(sprintf("dprintf %s\n", "ok")), con1a)
  close(con1a)
  con2 <- file(p2, open = "wt")
  on.exit(try(close(con2), silent = TRUE), add = TRUE)
  writeLines("fputs", con2)
  writeChar("X\n", con2, eos = NULL)
  writeLines(sprintf("fprintf %d", 123), con2)
  writeChar("fwrite\n", con2, eos = NULL)
  flush(con2)
  close(con2)
  con3 <- file(p3, open = "wb")
  on.exit(try(close(con3), silent = TRUE), add = TRUE)
  seek(con3, 0, origin = "start")
  writeBin(charToRaw("PWRITE64\n"), con3)
  close(con3)
}

test_read_family <- function(dir) {
  src <- file.path(dir, "read_src.txt")
  dst <- file.path(dir, "read_dst.txt")
  write_file(src, "0123456789abcdef\n")
  con <- file(src, open = "rb")
  on.exit(try(close(con), silent = TRUE), add = TRUE)
  buf1 <- readBin(con, what = "raw", n = 8)
  seek(con, 2, origin = "start"); buf2 <- readBin(con, "raw", n = 8)
  seek(con, 3, origin = "start"); buf3 <- readBin(con, "raw", n = 8)
  seek(con, 0, origin = "start")
  b1 <- readBin(con, "raw", n = 4)
  b2 <- readBin(con, "raw", n = 4)
  close(con)
  con2 <- file(src, open = "rb")
  on.exit(try(close(con2), silent = TRUE), add = TRUE)
  seek(con2, 0, origin = "start")
  line_raw <- raw()
  while (TRUE) {
    ch <- readBin(con2, "raw", n = 1)
    if (length(ch) == 0) break
    line_raw <- c(line_raw, ch)
    if (as.integer(ch) == as.integer(charToRaw("\n"))) break
  }
  line <- rawToChar(line_raw)
  ch1 <- readBin(con2, "raw", n = 1)
  ch2 <- readBin(con2, "raw", n = 1)
  seek(con2, 0, origin = "start")
  rbuf <- readBin(con2, "raw", n = 16)
  close(con2)
  writeLines("ok", dst)
}

test_transfer_family <- function(dir) {
  src  <- file.path(dir, "transfer_src.bin")
  dst1 <- file.path(dir, "transfer_dst_sendfile.bin")
  dst2 <- file.path(dir, "transfer_dst_copy.bin")
  write_file(src, "abcdefghijklmnopqrstuvwxyz0123456789\n")
  ok1 <- file.copy(src, dst1, overwrite = TRUE)
  if (!ok1) die("file.copy (sendfile analog) failed")
  in_con  <- file(src, open = "rb")
  on.exit(try(close(in_con), silent = TRUE), add = TRUE)
  out_con <- file(dst2, open = "wb")
  on.exit(try(close(out_con), silent = TRUE), add = TRUE)
  repeat {
    chunk <- readBin(in_con, what = "raw", n = 8192)
    if (length(chunk) == 0) break
    writeBin(chunk, out_con)
  }
  close(in_con); close(out_con)
}

test_rename_unlink <- function(dir) {
  p1 <- file.path(dir, "rename_me.txt")
  p2 <- file.path(dir, "renamed.txt")
  p3 <- file.path(dir, "unlink_me.txt")
  write_file(p1, "rename\n")
  ok <- file.rename(p1, p2)
  if (!ok) die("file.rename failed")
  write_file(p3, "unlink\n")
  if (file.exists(p3)) file.remove(p3)
  if (file.exists(p2)) file.remove(p2)
}

test_exec_hooks <- function(dir) {
  child_path <- file.path(dir, "child_exec_test.sh")
  script <- c("#!/bin/sh", "echo child_exec_ok")
  writeLines(script, child_path)
  Sys.chmod(child_path, mode = "0755")
  out1 <- system2(child_path, stdout = TRUE, stderr = TRUE)
  out2 <- system2("sh", c("-c", shQuote(child_path)), stdout = TRUE, stderr = TRUE)
  out3 <- system2("sh", c("-c", "echo execvp_ok"), stdout = TRUE, stderr = TRUE)
  out4 <- system2("sh", c("-c", "echo execvpe_ok"), stdout = TRUE, stderr = TRUE)
  invisible(list(out1 = out1, out2 = out2, out3 = out3, out4 = out4))
}

main <- function() {
  dir <- "/dev/shm/prov_test"
  ensure_dir("/dev/shm")
  ensure_dir(dir)
  test_write_family(dir)
  test_read_family(dir)
  test_transfer_family(dir)
  test_rename_unlink(dir)
  test_exec_hooks(dir)
  invisible(0)
}

main()
