// bpfmaps prints "name entries max_entries" for every loaded eBPF map whose name starts with
// one of the given prefixes. Counting walks the keys, so it suits maps of tens of thousands
// of entries.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
)

func main() {
	prefixes := os.Args[1:]
	var id ebpf.MapID
	for {
		next, err := ebpf.MapGetNextID(id)
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		id = next
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			continue
		}
		info, err := m.Info()
		if err != nil || !matches(info.Name, prefixes) {
			m.Close()
			continue
		}
		fmt.Printf("%s %d %d\n", info.Name, count(m), info.MaxEntries)
		m.Close()
	}
}

func matches(name string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return len(prefixes) == 0
}

func count(m *ebpf.Map) int {
	if m.Type() == ebpf.Array || m.Type() == ebpf.PerCPUArray || m.Type() == ebpf.RingBuf {
		return -1
	}
	n := 0
	var key []byte
	next := make([]byte, m.KeySize())
	for {
		var err error
		if key == nil {
			err = m.NextKey(nil, next)
		} else {
			err = m.NextKey(key, next)
		}
		if err != nil {
			return n
		}
		n++
		key = append(key[:0:0], next...)
	}
}
