// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import "strconv"

// kernelErrnoNames are the kernel-internal errnos of include/linux/errno.h,
// from 512 (ERESTARTSYS) on. They are not in the uapi errno table, but reach
// storage probes anyway: the NFS client passes EJUKEBOX (528) and ENOTSUPP
// (524) up from the server's replies, for example. 520 is unassigned.
var kernelErrnoNames = [...]string{
	"ERESTARTSYS", "ERESTARTNOINTR", "ERESTARTNOHAND", "ENOIOCTLCMD",
	"ERESTART_RESTARTBLOCK", "EPROBE_DEFER", "EOPENSTALE", "ENOPARAM",
	"",
	"EBADHANDLE", "ENOTSYNC", "EBADCOOKIE", "ENOTSUPP", "ETOOSMALL",
	"ESERVERFAULT", "EBADTYPE", "EJUKEBOX", "EIOCBQUEUED", "ERECALLCONFLICT",
	"ENOGRACE",
}

const firstKernelErrno = 512

// nfs4StatusNames are the NFSv4 statuses from 10001 on (enum nfsstat4 in
// include/linux/nfs4.h, RFC 7530, 8881, 7862 and 8276). The NFSv4 client
// returns the ones nfs4_stat_to_errno does not map as the negated status, so
// a delayed OPEN fails with -10008, NFS4ERR_DELAY. 10002 and 10073 are
// unassigned.
var nfs4StatusNames = [...]string{
	"NFS4ERR_BADHANDLE", "", "NFS4ERR_BAD_COOKIE", "NFS4ERR_NOTSUPP",
	"NFS4ERR_TOOSMALL", "NFS4ERR_SERVERFAULT", "NFS4ERR_BADTYPE", "NFS4ERR_DELAY",
	"NFS4ERR_SAME", "NFS4ERR_DENIED", "NFS4ERR_EXPIRED", "NFS4ERR_LOCKED",
	"NFS4ERR_GRACE", "NFS4ERR_FHEXPIRED", "NFS4ERR_SHARE_DENIED", "NFS4ERR_WRONGSEC",
	"NFS4ERR_CLID_INUSE", "NFS4ERR_RESOURCE", "NFS4ERR_MOVED", "NFS4ERR_NOFILEHANDLE",
	"NFS4ERR_MINOR_VERS_MISMATCH", "NFS4ERR_STALE_CLIENTID", "NFS4ERR_STALE_STATEID", "NFS4ERR_OLD_STATEID",
	"NFS4ERR_BAD_STATEID", "NFS4ERR_BAD_SEQID", "NFS4ERR_NOT_SAME", "NFS4ERR_LOCK_RANGE",
	"NFS4ERR_SYMLINK", "NFS4ERR_RESTOREFH", "NFS4ERR_LEASE_MOVED", "NFS4ERR_ATTRNOTSUPP",
	"NFS4ERR_NO_GRACE", "NFS4ERR_RECLAIM_BAD", "NFS4ERR_RECLAIM_CONFLICT", "NFS4ERR_BADXDR",
	"NFS4ERR_LOCKS_HELD", "NFS4ERR_OPENMODE", "NFS4ERR_BADOWNER", "NFS4ERR_BADCHAR",
	"NFS4ERR_BADNAME", "NFS4ERR_BAD_RANGE", "NFS4ERR_LOCK_NOTSUPP", "NFS4ERR_OP_ILLEGAL",
	"NFS4ERR_DEADLOCK", "NFS4ERR_FILE_OPEN", "NFS4ERR_ADMIN_REVOKED", "NFS4ERR_CB_PATH_DOWN",
	"NFS4ERR_BADIOMODE", "NFS4ERR_BADLAYOUT", "NFS4ERR_BAD_SESSION_DIGEST", "NFS4ERR_BADSESSION",
	"NFS4ERR_BADSLOT", "NFS4ERR_COMPLETE_ALREADY", "NFS4ERR_CONN_NOT_BOUND_TO_SESSION", "NFS4ERR_DELEG_ALREADY_WANTED",
	"NFS4ERR_BACK_CHAN_BUSY", "NFS4ERR_LAYOUTTRYLATER", "NFS4ERR_LAYOUTUNAVAILABLE", "NFS4ERR_NOMATCHING_LAYOUT",
	"NFS4ERR_RECALLCONFLICT", "NFS4ERR_UNKNOWN_LAYOUTTYPE", "NFS4ERR_SEQ_MISORDERED", "NFS4ERR_SEQUENCE_POS",
	"NFS4ERR_REQ_TOO_BIG", "NFS4ERR_REP_TOO_BIG", "NFS4ERR_REP_TOO_BIG_TO_CACHE", "NFS4ERR_RETRY_UNCACHED_REP",
	"NFS4ERR_UNSAFE_COMPOUND", "NFS4ERR_TOO_MANY_OPS", "NFS4ERR_OP_NOT_IN_SESSION", "NFS4ERR_HASH_ALG_UNSUPP",
	"", "NFS4ERR_CLIENTID_BUSY", "NFS4ERR_PNFS_IO_HOLE", "NFS4ERR_SEQ_FALSE_RETRY",
	"NFS4ERR_BAD_HIGH_SLOT", "NFS4ERR_DEADSESSION", "NFS4ERR_ENCR_ALG_UNSUPP", "NFS4ERR_PNFS_NO_LAYOUT",
	"NFS4ERR_NOT_ONLY_OP", "NFS4ERR_WRONG_CRED", "NFS4ERR_WRONG_TYPE", "NFS4ERR_DIRDELEG_UNAVAIL",
	"NFS4ERR_REJECT_DELEG", "NFS4ERR_RETURNCONFLICT", "NFS4ERR_DELEG_REVOKED", "NFS4ERR_PARTNER_NOTSUPP",
	"NFS4ERR_PARTNER_NO_AUTH", "NFS4ERR_UNION_NOTSUPP", "NFS4ERR_OFFLOAD_DENIED", "NFS4ERR_WRONG_LFS",
	"NFS4ERR_BADLABEL", "NFS4ERR_OFFLOAD_NO_REQS", "NFS4ERR_NOXATTR", "NFS4ERR_XATTR2BIG",
}

const firstNFS4Status = 10001

// errnoName returns the name error.type carries for an error a storage probe
// reported: the platform's errno name, else a kernel-internal errno, else an
// NFSv4 status, else the decimal value. The sign is ignored, since probes
// report -errno.
func errnoName(errno int32) string {
	n := int64(errno)
	if n < 0 {
		n = -n
	}
	if name := platformErrnoName(n); name != "" {
		return name
	}
	if name := tableName(kernelErrnoNames[:], firstKernelErrno, n); name != "" {
		return name
	}
	if name := tableName(nfs4StatusNames[:], firstNFS4Status, n); name != "" {
		return name
	}
	return strconv.FormatInt(n, 10)
}

func tableName(names []string, first, n int64) string {
	if n < first || n-first >= int64(len(names)) {
		return ""
	}
	return names[n-first]
}
