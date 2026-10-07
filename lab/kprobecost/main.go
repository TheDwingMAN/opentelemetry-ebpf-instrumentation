// kprobecost times system calls that OBI's file sync kprobes and block tracepoints fire on, so
// that runs with and without OBI give the cost of the probes, mechanism included.
//
//	kprobecost <op> <path> <n>
//
// op: getppid (baseline), fsync, fdatasync, syncfs (on a file), writefsync (a 4 KiB write then
// fsync of a file), read (4 KiB O_DIRECT reads of a block device).
package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

const blockSize = 4096

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: kprobecost <op> <path> <n>")
		os.Exit(2)
	}
	op, path := os.Args[1], os.Args[2]
	n, err := strconv.Atoi(os.Args[3])
	if err != nil {
		fail(err)
	}

	flags := unix.O_RDWR | unix.O_CREAT
	if op == "read" {
		flags = unix.O_RDONLY | unix.O_DIRECT
	}
	fd, err := unix.Open(path, flags, 0o600)
	if err != nil {
		fail(err)
	}
	defer unix.Close(fd)

	// O_DIRECT needs an aligned buffer: anonymous mappings are page aligned
	buf, err := unix.Mmap(-1, 0, blockSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		fail(err)
	}

	start := time.Now()
	for i := 0; i < n; i++ {
		switch op {
		case "getppid":
			unix.Getppid()
		case "fsync":
			err = unix.Fsync(fd)
		case "fdatasync":
			err = unix.Fdatasync(fd)
		case "syncfs":
			err = unix.Syncfs(fd)
		case "writefsync":
			if _, err = unix.Pwrite(fd, buf, 0); err == nil {
				err = unix.Fsync(fd)
			}
		case "read":
			_, err = unix.Pread(fd, buf, int64(i%256)*blockSize)
		default:
			fail(fmt.Errorf("unknown op %q", op))
		}
		if err != nil {
			fail(err)
		}
	}
	elapsed := time.Since(start)
	fmt.Printf("%s: %.0f ns per call (%d calls)\n", op, float64(elapsed.Nanoseconds())/float64(n), n)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
