#!/usr/bin/env julia

using Printf

const DIRP = "/dev/shm/prov_test"

function ensure_dir(p::AbstractString)
    isdir(p) || mkpath(p)
end

function write_file(path::AbstractString, data::AbstractString)
    open(path, "w") do io
        write(io, data)
    end
end

function test_write_family(dirp)
    p1 = joinpath(dirp, "write.txt")
    p2 = joinpath(dirp, "fprintf.txt")
    p3 = joinpath(dirp, "pwrite.txt")
    open(p1, "w") do io
        write(io, "hello\n")
        write(io, "vector\n")
        seek(io, 0)
        write(io, "PWRITE\n")
    end
    open(p2, "w") do io
        write(io, "fputs\n")
        write(io, "X\n")
        @printf(io, "fprintf %d\n", 123)
        write(io, "fwrite\n")
        flush(io)
    end
    open(p3, "w") do io
        seek(io, 0)
        write(io, "PWRITE64\n")
    end
    open(p1, "a") do io
        write(io, "dprintf ok\n")
    end
end

function test_read_family(dirp)
    src = joinpath(dirp, "read_src.txt")
    dst = joinpath(dirp, "read_dst.txt")
    write_file(src, "0123456789abcdef\n")
    open(src, "r") do io
        read(io, 8)
        seek(io, 2); read(io, 8)
        seek(io, 3); read(io, 8)
        read(io, 8)
    end
    open(src, "r") do io
        _line = readline(io)
        _c = eof(io) ? '\0' : read(io, Char)
        seekstart(io)
        _buf = read(io, 16)
    end
    open(dst, "w") do io
        write(io, "ok\n")
    end
end

function test_transfer_family(dirp)
    src  = joinpath(dirp, "transfer_src.bin")
    dst1 = joinpath(dirp, "transfer_dst_sendfile.bin")
    dst2 = joinpath(dirp, "transfer_dst_copy.bin")
    write_file(src, "abcdefghijklmnopqrstuvwxyz0123456789\n")
    cp(src, dst1; force=true)
    cp(src, dst2; force=true)
end

function test_rename_unlink(dirp)
    p1 = joinpath(dirp, "rename_me.txt")
    p2 = joinpath(dirp, "renamed.txt")
    p3 = joinpath(dirp, "unlink_me.txt")
    write_file(p1, "rename\n")
    mv(p1, p2; force=true)
    write_file(p3, "unlink\n")
    rm(p3; force=true)
    rm(p2; force=true)
end

function test_exec_hooks(dirp)
    child = joinpath(dirp, "child_exec_test")
    open(child, "w") do io
        write(io, "#!/bin/sh\necho child_exec_ok\n")
    end
    chmod(child, 0o755)
    run(`$child`)
    run(`sh -c "echo execvp_ok"`)
    run(setenv(`sh -c "echo execvpe_ok"`, ENV))
end

ensure_dir("/dev/shm")
ensure_dir(DIRP)
test_write_family(DIRP)
test_read_family(DIRP)
test_transfer_family(DIRP)
test_rename_unlink(DIRP)
test_exec_hooks(DIRP)
