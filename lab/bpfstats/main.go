// bpfstats prints the average run time of the loaded eBPF programs whose name contains a
// substring. Needs `sysctl kernel.bpf_stats_enabled=1` while the workload runs.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
)

func main() {
	filter := ""
	if len(os.Args) > 1 {
		filter = os.Args[1]
	}
	var id ebpf.ProgramID
	for {
		next, err := ebpf.ProgramGetNextID(id)
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		id = next
		prog, err := ebpf.NewProgramFromID(id)
		if err != nil {
			continue
		}
		info, err := prog.Info()
		if err != nil || !strings.Contains(info.Name, filter) {
			prog.Close()
			continue
		}
		stats, err := prog.Stats()
		prog.Close()
		if err != nil {
			continue
		}
		avg := 0.0
		if stats.RunCount > 0 {
			avg = float64(stats.Runtime.Nanoseconds()) / float64(stats.RunCount)
		}
		fmt.Printf("%-16s runs=%-10d total=%-12v avg=%.0fns\n", info.Name, stats.RunCount, stats.Runtime, avg)
	}
}
