// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sunrpcparser // import "go.opentelemetry.io/obi/pkg/internal/sunrpcparser"

// Well-known ONC RPC program numbers used for onc_rpc.program.name.
//
// Sources: [RFC 5531] (RPC model), program numbers assigned in the RPC
// literature and Linux/NFS deployments (portmapper 100000, NFS 100003, mount
// 100005, etc.). See also IANA "RPC Program Numbers" and /etc/rpc on typical
// Unix systems.
//
// [RFC 5531]: https://datatracker.ietf.org/doc/html/rfc5531
const (
	ProgramPortmapper = 100000
	ProgramRstat      = 100001
	ProgramRusers     = 100002
	ProgramNFS        = 100003
	ProgramYpbind     = 100007
	ProgramMount      = 100005
	ProgramNFSACL     = 100227
	ProgramNlockmgr   = 100021
)

func ProgramName(prog uint32) string {
	switch prog {
	case ProgramPortmapper:
		return "portmapper"
	case ProgramRstat:
		return "rstat"
	case ProgramRusers:
		return "rusers"
	case ProgramNFS:
		return "nfs"
	case ProgramYpbind:
		return "ypbind"
	case ProgramMount:
		return "mount"
	case ProgramNFSACL:
		return "nfsacl"
	case ProgramNlockmgr:
		return "nlockmgr"
	default:
		return ""
	}
}

// Procedure names indexed by procedure number, without the per-program
// prefix of the RFC constants (NFSPROC3_READ is reported as READ), matching
// the onc_rpc.procedure.name examples in the semantic conventions. The
// program version disambiguates the numbering and is exported separately as
// onc_rpc.version.

// [RFC 1833] section 3 (PMAP, version 2).
//
// [RFC 1833]: https://datatracker.ietf.org/doc/html/rfc1833
var portmapV2Procedures = []string{"NULL", "SET", "UNSET", "GETPORT", "DUMP", "CALLIT"}

// [RFC 1833] section 2 (RPCBIND, versions 3 and 4; version 4 adds 9-12).
var rpcbindV4Procedures = []string{
	"NULL", "SET", "UNSET", "GETADDR", "DUMP", "BCAST", "GETTIME",
	"UADDR2TADDR", "TADDR2UADDR", "GETVERSADDR", "INDIRECT", "GETADDRLIST", "GETSTAT",
}

const rpcbindV3ProcedureCount = 9

// [RFC 1094] appendix A (MOUNT versions 1 and 2; PATHCONF is version 2 only).
//
// [RFC 1094]: https://datatracker.ietf.org/doc/html/rfc1094
var mountV2Procedures = []string{"NULL", "MNT", "DUMP", "UMNT", "UMNTALL", "EXPORT", "EXPORTALL", "PATHCONF"}

const mountV1ProcedureCount = 7

// [RFC 1813] appendix I (MOUNT version 3).
//
// [RFC 1813]: https://datatracker.ietf.org/doc/html/rfc1813
var mountV3Procedures = []string{"NULL", "MNT", "DUMP", "UMNT", "UMNTALL", "EXPORT"}

// [RFC 1094] section 2.2 (NFS version 2).
var nfsV2Procedures = []string{
	"NULL", "GETATTR", "SETATTR", "ROOT", "LOOKUP", "READLINK", "READ", "WRITECACHE", "WRITE",
	"CREATE", "REMOVE", "RENAME", "LINK", "SYMLINK", "MKDIR", "RMDIR", "READDIR", "STATFS",
}

// [RFC 1813] section 3 (NFS version 3).
var nfsV3Procedures = []string{
	"NULL", "GETATTR", "SETATTR", "LOOKUP", "ACCESS", "READLINK", "READ", "WRITE", "CREATE",
	"MKDIR", "SYMLINK", "MKNOD", "REMOVE", "RMDIR", "RENAME", "LINK", "READDIR", "READDIRPLUS",
	"FSSTAT", "FSINFO", "PATHCONF", "COMMIT",
}

// [RFC 7530] section 16 (NFS version 4; the operations travel inside COMPOUND).
//
// [RFC 7530]: https://datatracker.ietf.org/doc/html/rfc7530
var nfsV4Procedures = []string{"NULL", "COMPOUND"}

// NLM procedures from the X/Open XNFS specification. Numbers 0-15 are shared by
// versions 1-4; SHARE through FREE_ALL (20-23) exist from version 3.
var nlmProcedures = []string{
	"NULL", "TEST", "LOCK", "CANCEL", "UNLOCK", "GRANTED",
	"TEST_MSG", "LOCK_MSG", "CANCEL_MSG", "UNLOCK_MSG", "GRANTED_MSG",
	"TEST_RES", "LOCK_RES", "CANCEL_RES", "UNLOCK_RES", "GRANTED_RES",
	"", "", "", "",
	"SHARE", "UNSHARE", "NM_LOCK", "FREE_ALL",
}

const nlmV2ProcedureCount = 16

func procedureName(prog, vers, proc uint32) string {
	names := procedureNames(prog, vers)
	if uint64(proc) >= uint64(len(names)) {
		return ""
	}
	return names[proc]
}

func procedureNames(prog, vers uint32) []string {
	switch prog {
	case ProgramPortmapper:
		switch vers {
		case 2:
			return portmapV2Procedures
		case 3:
			return rpcbindV4Procedures[:rpcbindV3ProcedureCount]
		case 4:
			return rpcbindV4Procedures
		}
	case ProgramMount:
		switch vers {
		case 1:
			return mountV2Procedures[:mountV1ProcedureCount]
		case 2:
			return mountV2Procedures
		case 3:
			return mountV3Procedures
		}
	case ProgramNFS:
		switch vers {
		case 2:
			return nfsV2Procedures
		case 3:
			return nfsV3Procedures
		case 4:
			return nfsV4Procedures
		}
	case ProgramNlockmgr:
		switch vers {
		case 1, 2:
			return nlmProcedures[:nlmV2ProcedureCount]
		case 3, 4:
			return nlmProcedures
		}
	}
	return nil
}

// AuthFlavorName returns a stable label for an RPC authentication flavor.
func AuthFlavorName(flavor uint32) string {
	switch flavor {
	case authNull:
		return "auth_null"
	case authUnix:
		return "auth_unix"
	case authShort:
		return "auth_short"
	case authDES:
		return "auth_des"
	case authKerb:
		return "auth_kerb"
	case authRSA:
		return "auth_rsa"
	case authRPCSECgss:
		return "rpcsec_gss"
	default:
		return ""
	}
}
