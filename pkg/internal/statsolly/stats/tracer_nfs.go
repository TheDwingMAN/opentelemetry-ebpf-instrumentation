// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"syscall"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

func newNFSProcedureReader(
	accum accumSource[ebpf.StatsNfsProcedureKeyT, ebpf.StatsNfsProcedureAccumT],
	latencyBounds []float64,
	containers *cgroupContainers,
) *accumReader[ebpf.StatsNfsProcedureKeyT, ebpf.StatsNfsProcedureAccumT] {
	n := nfsProcedureStats{latencyBounds: latencyBounds, containers: containers}
	return newAccumReader("nfs_procedure_accum", accum, n.stat)
}

type nfsProcedureStats struct {
	latencyBounds []float64
	containers    *cgroupContainers
}

// stat returns the NFS RPCs that completed since the previous read of the key, or nil
func (n *nfsProcedureStats) stat(key ebpf.StatsNfsProcedureKeyT, current, previous ebpf.StatsNfsProcedureAccumT) *ebpf.Stat {
	if anyDecreased(current.LatencyCount[:], previous.LatencyCount[:]) ||
		anyDecreased(current.LatencySumNs[:], previous.LatencySumNs[:]) {
		previous = ebpf.StatsNfsProcedureAccumT{}
	}
	delta := latencyDelta(n.latencyBounds, current.LatencyCount[:], current.LatencySumNs[:],
		previous.LatencyCount[:], previous.LatencySumNs[:])
	if delta.operations == 0 {
		return nil
	}
	errorType := nfsErrorType(key.Status)
	if errorType == errorTypeOther {
		dtlog().Debug("NFS RPCs completed with a status without a name", "status", key.Status, "calls", delta.operations)
	}
	return &ebpf.Stat{
		Type: ebpf.StatTypeNFSProcedure,
		NFSProcedure: &ebpf.NFSProcedure{
			Server:      unix.ByteSliceToString(key.Server[:]),
			Procedure:   unix.ByteSliceToString(key.Procedure[:]),
			Version:     key.Version,
			ErrorType:   errorType,
			ContainerID: n.containers.containerID(key.CgroupId),
			Calls:       delta.operations,
			Time:        delta.seconds(),
			Latency:     delta.latency,
		},
	}
}

func newNFSIOReader(
	accum accumSource[ebpf.StatsNfsIoKeyT, uint64],
	containers *cgroupContainers,
) *accumReader[ebpf.StatsNfsIoKeyT, uint64] {
	stat := func(key ebpf.StatsNfsIoKeyT, current, previous uint64) *ebpf.Stat {
		// kernel counters only grow; a decrease means the entry was deleted and re-created
		if current < previous {
			previous = 0
		}
		if current == previous {
			return nil
		}
		return &ebpf.Stat{
			Type: ebpf.StatTypeNFSIO,
			NFSIO: &ebpf.NFSIO{
				Server:      unix.ByteSliceToString(key.Server[:]),
				Direction:   uint8(key.Direction),
				ContainerID: containers.containerID(key.CgroupId),
				Bytes:       current - previous,
			},
		}
	}
	return newAccumReader("nfs_io_accum", accum, stat)
}

// nfsStatusNames names the RPC statuses that the uapi errno table doesn't have: the kernel-internal
// errnos of include/linux/errno.h (e.g. EJUKEBOX from an NFSv3 server, ERESTARTSYS on a signal),
// and the NFSv4 statuses (enum nfsstat4), which the NFS client passes up as they are when
// nfs4_stat_to_errno doesn't translate them into errnos (e.g. NFS4ERR_DELAY).
var nfsStatusNames = map[uint16]string{
	512: "ERESTARTSYS",
	513: "ERESTARTNOINTR",
	514: "ERESTARTNOHAND",
	515: "ENOIOCTLCMD",
	516: "ERESTART_RESTARTBLOCK",
	517: "EPROBE_DEFER",
	518: "EOPENSTALE",
	519: "ENOPARAM",
	521: "EBADHANDLE",
	522: "ENOTSYNC",
	523: "EBADCOOKIE",
	524: "ENOTSUPP",
	525: "ETOOSMALL",
	526: "ESERVERFAULT",
	527: "EBADTYPE",
	528: "EJUKEBOX",
	529: "EIOCBQUEUED",
	530: "ERECALLCONFLICT",
	531: "ENOGRACE",

	10001: "NFS4ERR_BADHANDLE",
	10003: "NFS4ERR_BAD_COOKIE",
	10004: "NFS4ERR_NOTSUPP",
	10005: "NFS4ERR_TOOSMALL",
	10006: "NFS4ERR_SERVERFAULT",
	10007: "NFS4ERR_BADTYPE",
	10008: "NFS4ERR_DELAY",
	10009: "NFS4ERR_SAME",
	10010: "NFS4ERR_DENIED",
	10011: "NFS4ERR_EXPIRED",
	10012: "NFS4ERR_LOCKED",
	10013: "NFS4ERR_GRACE",
	10014: "NFS4ERR_FHEXPIRED",
	10015: "NFS4ERR_SHARE_DENIED",
	10016: "NFS4ERR_WRONGSEC",
	10017: "NFS4ERR_CLID_INUSE",
	10018: "NFS4ERR_RESOURCE",
	10019: "NFS4ERR_MOVED",
	10020: "NFS4ERR_NOFILEHANDLE",
	10021: "NFS4ERR_MINOR_VERS_MISMATCH",
	10022: "NFS4ERR_STALE_CLIENTID",
	10023: "NFS4ERR_STALE_STATEID",
	10024: "NFS4ERR_OLD_STATEID",
	10025: "NFS4ERR_BAD_STATEID",
	10026: "NFS4ERR_BAD_SEQID",
	10027: "NFS4ERR_NOT_SAME",
	10028: "NFS4ERR_LOCK_RANGE",
	10029: "NFS4ERR_SYMLINK",
	10030: "NFS4ERR_RESTOREFH",
	10031: "NFS4ERR_LEASE_MOVED",
	10032: "NFS4ERR_ATTRNOTSUPP",
	10033: "NFS4ERR_NO_GRACE",
	10034: "NFS4ERR_RECLAIM_BAD",
	10035: "NFS4ERR_RECLAIM_CONFLICT",
	10036: "NFS4ERR_BADXDR",
	10037: "NFS4ERR_LOCKS_HELD",
	10038: "NFS4ERR_OPENMODE",
	10039: "NFS4ERR_BADOWNER",
	10040: "NFS4ERR_BADCHAR",
	10041: "NFS4ERR_BADNAME",
	10042: "NFS4ERR_BAD_RANGE",
	10043: "NFS4ERR_LOCK_NOTSUPP",
	10044: "NFS4ERR_OP_ILLEGAL",
	10045: "NFS4ERR_DEADLOCK",
	10046: "NFS4ERR_FILE_OPEN",
	10047: "NFS4ERR_ADMIN_REVOKED",
	10048: "NFS4ERR_CB_PATH_DOWN",
	10049: "NFS4ERR_BADIOMODE",
	10050: "NFS4ERR_BADLAYOUT",
	10051: "NFS4ERR_BAD_SESSION_DIGEST",
	10052: "NFS4ERR_BADSESSION",
	10053: "NFS4ERR_BADSLOT",
	10054: "NFS4ERR_COMPLETE_ALREADY",
	10055: "NFS4ERR_CONN_NOT_BOUND_TO_SESSION",
	10056: "NFS4ERR_DELEG_ALREADY_WANTED",
	10057: "NFS4ERR_BACK_CHAN_BUSY",
	10058: "NFS4ERR_LAYOUTTRYLATER",
	10059: "NFS4ERR_LAYOUTUNAVAILABLE",
	10060: "NFS4ERR_NOMATCHING_LAYOUT",
	10061: "NFS4ERR_RECALLCONFLICT",
	10062: "NFS4ERR_UNKNOWN_LAYOUTTYPE",
	10063: "NFS4ERR_SEQ_MISORDERED",
	10064: "NFS4ERR_SEQUENCE_POS",
	10065: "NFS4ERR_REQ_TOO_BIG",
	10066: "NFS4ERR_REP_TOO_BIG",
	10067: "NFS4ERR_REP_TOO_BIG_TO_CACHE",
	10068: "NFS4ERR_RETRY_UNCACHED_REP",
	10069: "NFS4ERR_UNSAFE_COMPOUND",
	10070: "NFS4ERR_TOO_MANY_OPS",
	10071: "NFS4ERR_OP_NOT_IN_SESSION",
	10072: "NFS4ERR_HASH_ALG_UNSUPP",
	10074: "NFS4ERR_CLIENTID_BUSY",
	10075: "NFS4ERR_PNFS_IO_HOLE",
	10076: "NFS4ERR_SEQ_FALSE_RETRY",
	10077: "NFS4ERR_BAD_HIGH_SLOT",
	10078: "NFS4ERR_DEADSESSION",
	10079: "NFS4ERR_ENCR_ALG_UNSUPP",
	10080: "NFS4ERR_PNFS_NO_LAYOUT",
	10081: "NFS4ERR_NOT_ONLY_OP",
	10082: "NFS4ERR_WRONG_CRED",
	10083: "NFS4ERR_WRONG_TYPE",
	10084: "NFS4ERR_DIRDELEG_UNAVAIL",
	10085: "NFS4ERR_REJECT_DELEG",
	10086: "NFS4ERR_RETURNCONFLICT",
	10087: "NFS4ERR_DELEG_REVOKED",
	10088: "NFS4ERR_PARTNER_NOTSUPP",
	10089: "NFS4ERR_PARTNER_NO_AUTH",
	10090: "NFS4ERR_UNION_NOTSUPP",
	10091: "NFS4ERR_OFFLOAD_DENIED",
	10092: "NFS4ERR_WRONG_LFS",
	10093: "NFS4ERR_BADLABEL",
	10094: "NFS4ERR_OFFLOAD_NO_REQS",
	10095: "NFS4ERR_NOXATTR",
	10096: "NFS4ERR_XATTR2BIG",
}

// nfsErrorType names the status of an NFS RPC after its errno, or after its name in
// nfsStatusNames. A status without a name is _OTHER, as its numbers would be an open set of
// values. Empty on success.
func nfsErrorType(status uint16) string {
	if status == 0 {
		return ""
	}
	if name := unix.ErrnoName(syscall.Errno(status)); name != "" {
		return name
	}
	if name, ok := nfsStatusNames[status]; ok {
		return name
	}
	return errorTypeOther
}
