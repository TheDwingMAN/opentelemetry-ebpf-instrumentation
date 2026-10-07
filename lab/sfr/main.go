// sfr <file> <hints> <waits>: writes one byte to <file>, then calls sync_file_range(2) <hints>
// times with SYNC_FILE_RANGE_WRITE alone and <waits> times with WAIT_BEFORE|WRITE|WAIT_AFTER,
// from the same call site, so a probe that reads the wrong register sees the same flags for both.
// The final payload runs it (build-payload.sh builds it): OBI must count only the <waits> calls.
package main

import (
	"os"
	"strconv"
	"syscall"
)

const (
	waitBefore = 1
	write      = 2
	waitAfter  = 4
)

func main() {
	f, err := os.Create(os.Args[1])
	if err != nil {
		panic(err)
	}
	if _, err := f.Write([]byte{1}); err != nil {
		panic(err)
	}
	hints, _ := strconv.Atoi(os.Args[2])
	waits, _ := strconv.Atoi(os.Args[3])
	for i := 0; i < hints+waits; i++ {
		flags := uintptr(write)
		if i >= hints {
			flags = waitBefore | write | waitAfter
		}
		if _, _, errno := syscall.Syscall6(syscall.SYS_SYNC_FILE_RANGE, f.Fd(), 0, 0, flags, 0, 0); errno != 0 {
			panic(errno)
		}
	}
}
