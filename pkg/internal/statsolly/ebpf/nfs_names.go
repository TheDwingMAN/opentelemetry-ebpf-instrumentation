// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"io/fs"
	"log/slog"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf/btf"
)

// nfsv2Procedures names the NFSv2 procedures by number (RFC 1094; ROOT and
// WRITECACHE are never called).
var nfsv2Procedures = [...]string{
	"NULL", "GETATTR", "SETATTR", "ROOT", "LOOKUP", "READLINK", "READ", "WRITECACHE", "WRITE",
	"CREATE", "REMOVE", "RENAME", "LINK", "SYMLINK", "MKDIR", "RMDIR", "READDIR", "STATFS",
}

// nfsv3Procedures names the NFSv3 procedures by number (RFC 1813): the
// kernel's p_name, which /proc/self/mountstats shows.
var nfsv3Procedures = [...]string{
	"NULL", "GETATTR", "SETATTR", "LOOKUP", "ACCESS", "READLINK", "READ", "WRITE", "CREATE",
	"MKDIR", "SYMLINK", "MKNOD", "REMOVE", "RMDIR", "RENAME", "LINK", "READDIR",
	"READDIRPLUS", "FSSTAT", "FSINFO", "PATHCONF", "COMMIT",
}

// nfsProcedureName returns onc_rpc.procedure.name for an NFSv2 or NFSv3 RPC,
// or "" for NFSv4, whose wire procedure is always COMPOUND: its operation is
// nfs.operation.name instead. A number outside the table keeps its decimal
// value.
func nfsProcedureName(version uint8, statIdx uint16) string {
	var names []string
	switch version {
	case 2:
		names = nfsv2Procedures[:]
	case 3:
		names = nfsv3Procedures[:]
	default:
		return ""
	}
	if int(statIdx) < len(names) {
		return names[statIdx]
	}
	return strconv.Itoa(int(statIdx))
}

// nfs4OperationName returns nfs.operation.name for an NFSv4 RPC, or "" for
// the other versions.
func nfs4OperationName(version uint8, statIdx uint16) string {
	if version != 4 {
		return ""
	}
	return nfs4Names.name(statIdx)
}

// nfs4OpPrefix prefixes the members of the kernel's NFSv4 client operation
// enum, whose order changes between kernels and which has no type name
// (include/linux/nfs4.h: enum { NFSPROC4_CLNT_NULL = 0, ... }).
const nfs4OpPrefix = "NFSPROC4_CLNT_"

// nfs4OpNames reads the names of the NFSv4 client operations from the
// kernel, once: an NFSv4 RPC can only happen with the nfsv4 module loaded,
// and a module cannot change while it has an NFSv4 mount. A kernel without
// the names (no module BTF) gets decimal indexes.
type nfs4OpNames struct {
	once  sync.Once
	load  func() ([]string, error)
	names []string
}

var nfs4Names = &nfs4OpNames{load: loadKernelNFS4OpNames}

func (n *nfs4OpNames) name(statIdx uint16) string {
	n.once.Do(func() {
		names, err := n.load()
		if err != nil {
			slog.With("component", "ebpf.NFS").Warn("can't read the NFSv4 operation names from the kernel BTF;"+
				" nfs.operation.name holds the operation index instead", "error", err)
			return
		}
		n.names = names
	})
	if int(statIdx) < len(n.names) && n.names[statIdx] != "" {
		return n.names[statIdx]
	}
	return strconv.Itoa(int(statIdx))
}

// nfs4OpNamesFrom finds the NFSv4 client operation enum in spec, by its
// NFSPROC4_CLNT_NULL member, and returns its names by index without the
// prefix. Its last member, NFSPROC4_CLNT_MAX or similar, names no operation
// but is harmless: no RPC carries its index.
func nfs4OpNamesFrom(spec *btf.Spec) ([]string, error) {
	for typ, err := range spec.All() {
		if err != nil {
			return nil, err
		}
		enum, ok := typ.(*btf.Enum)
		if !ok || enum.Name != "" || !hasEnumValue(enum, nfs4OpPrefix+"NULL") {
			continue
		}
		var names []string
		for _, v := range enum.Values {
			if v.Value > 1<<16 || !strings.HasPrefix(v.Name, nfs4OpPrefix) {
				continue
			}
			for uint64(len(names)) <= v.Value {
				names = append(names, "")
			}
			names[v.Value] = strings.TrimPrefix(v.Name, nfs4OpPrefix)
		}
		return names, nil
	}
	return nil, errNoNFS4Ops
}

// loadKernelNFS4OpNames reads the operation names from the BTF of the nfsv4
// module, or of the kernel when NFSv4 is built in. Only the module's own
// types are scanned, not the kernel's it is split from.
func loadKernelNFS4OpNames() ([]string, error) {
	spec, err := btf.LoadKernelModuleSpec("nfsv4")
	if errors.Is(err, fs.ErrNotExist) {
		spec, err = btf.LoadKernelSpec()
	}
	if err != nil {
		return nil, err
	}
	return nfs4OpNamesFrom(spec)
}

var errNoNFS4Ops = errors.New("no enum with " + nfs4OpPrefix + "NULL in the BTF")

func hasEnumValue(enum *btf.Enum, name string) bool {
	for _, v := range enum.Values {
		if v.Name == name {
			return true
		}
	}
	return false
}
