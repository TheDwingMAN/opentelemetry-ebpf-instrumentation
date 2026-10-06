// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"structs"

	"go.opentelemetry.io/obi/pkg/internal/pipe"
)

type StatType uint8

// These alias the bpf2go-generated constants derived from enum stat_type in
// bpf/statsolly/types.h, so kernel and userspace values cannot drift.
const (
	StatTypeTCPRtt                  = StatType(StatsStatTypeK_statTypeTcpRtt)
	StatTypeTCPFailedConnection     = StatType(StatsStatTypeK_statTypeTcpFailedConnection)
	StatTypeTCPRetransmit           = StatType(StatsStatTypeK_statTypeTcpRetransmit)
	StatTypeTCPIo                   = StatType(StatsStatTypeK_statTypeTcpIo)
	StatTypeTCPSuccessfulConnection = StatType(StatsStatTypeK_statTypeTcpSuccessfulConnection)
	StatTypeBlockIo                 = StatType(StatsStatTypeK_statTypeBlockIo)
	StatTypeFsIo                    = StatType(StatsStatTypeK_statTypeFsIo)
	StatTypeNFSRPC                  = StatType(StatsStatTypeK_statTypeNfsRpc)
)

type TCPFailReasonType string

const (
	Unknown           TCPFailReasonType = "unknown"
	ConnectionRefused TCPFailReasonType = "refused"
	ConnectionReset   TCPFailReasonType = "reset"
	TimedOut          TCPFailReasonType = "timed-out"
	HostUnreachable   TCPFailReasonType = "host-unreachable"
	NetUnreachable    TCPFailReasonType = "net-unreachable"
	Other             TCPFailReasonType = "other"
)

// TCPFailReasonTypeCode aliases the bpf2go-generated constants derived from
// enum tcp_fail_reason in bpf/statsolly/types.h.
type TCPFailReasonTypeCode uint8

const (
	CodeUnknown           = TCPFailReasonTypeCode(StatsTcpFailReasonReasonUnknown)
	CodeConnectionRefused = TCPFailReasonTypeCode(StatsTcpFailReasonReasonConnectionRefused)
	CodeConnectionReset   = TCPFailReasonTypeCode(StatsTcpFailReasonReasonConnectionReset)
	CodeTimedOut          = TCPFailReasonTypeCode(StatsTcpFailReasonReasonTimedOut)
	CodeHostUnreachable   = TCPFailReasonTypeCode(StatsTcpFailReasonReasonHostUnreachable)
	CodeNetUnreachable    = TCPFailReasonTypeCode(StatsTcpFailReasonReasonNetUnreachable)
	CodeOther             = TCPFailReasonTypeCode(StatsTcpFailReasonReasonOther)
)

type NetworkTCPHandshakeRoleType string

const (
	RoleUnknown NetworkTCPHandshakeRoleType = "unknown"
	RoleClient  NetworkTCPHandshakeRoleType = "client"
	RoleServer  NetworkTCPHandshakeRoleType = "server"
)

// NetworkTCPHandshakeRoleCode aliases the bpf2go-generated constants derived
// from enum tcp_handshake_role in bpf/statsolly/types.h.
type NetworkTCPHandshakeRoleCode uint8

const (
	CodeRoleUnknown = NetworkTCPHandshakeRoleCode(StatsTcpHandshakeRoleRoleUnknown)
	CodeRoleClient  = NetworkTCPHandshakeRoleCode(StatsTcpHandshakeRoleRoleClient)
	CodeRoleServer  = NetworkTCPHandshakeRoleCode(StatsTcpHandshakeRoleRoleServer)
)

type NetworkIoDirectionType string

const (
	DirectionReceive  NetworkIoDirectionType = "receive"
	DirectionTransmit NetworkIoDirectionType = "transmit"
)

// NetworkIoDirectionCode aliases the bpf2go-generated constants derived from
// enum network_io_direction in bpf/statsolly/types.h.
type NetworkIoDirectionCode uint8

const (
	CodeDirectionReceive  = NetworkIoDirectionCode(StatsNetworkIoDirectionDirectionReceive)
	CodeDirectionTransmit = NetworkIoDirectionCode(StatsNetworkIoDirectionDirectionTransmit)
)

type DiskIoDirectionType string

const (
	DirectionRead  DiskIoDirectionType = "read"
	DirectionWrite DiskIoDirectionType = "write"
)

// DiskIoDirectionCode aliases the read and write members of the
// bpf2go-generated enum blk_io_op in bpf/statsolly/types.h: the kinds of block
// request that have a direction.
type DiskIoDirectionCode uint8

const (
	CodeDirectionRead  = DiskIoDirectionCode(StatsBlkIoOpBlkOpRead)
	CodeDirectionWrite = DiskIoDirectionCode(StatsBlkIoOpBlkOpWrite)
)

// BlockOpCode aliases the bpf2go-generated enum blk_io_op in
// bpf/statsolly/types.h: what a block request was.
type BlockOpCode uint8

const (
	CodeBlockRead    = BlockOpCode(StatsBlkIoOpBlkOpRead)
	CodeBlockWrite   = BlockOpCode(StatsBlkIoOpBlkOpWrite)
	CodeBlockFlush   = BlockOpCode(StatsBlkIoOpBlkOpFlush)
	CodeBlockDiscard = BlockOpCode(StatsBlkIoOpBlkOpDiscard)
)

type FsTypeName string

const (
	FsNFS   FsTypeName = "nfs"
	FsCeph  FsTypeName = "ceph"
	FsCIFS  FsTypeName = "cifs"
	FsFUSE  FsTypeName = "fuse"
	FsExt4  FsTypeName = "ext4"
	FsXFS   FsTypeName = "xfs"
	FsBtrfs FsTypeName = "btrfs"
)

// FsTypeCode mirrors enum fs_type in bpf/statsolly/types.h.
type FsTypeCode uint8

const (
	CodeFsUnknown FsTypeCode = 0
	CodeFsNFS     FsTypeCode = 1
	CodeFsCeph    FsTypeCode = 2
	CodeFsCIFS    FsTypeCode = 3
	CodeFsFUSE    FsTypeCode = 4
	CodeFsExt4    FsTypeCode = 5
	CodeFsXFS     FsTypeCode = 6
	CodeFsBtrfs   FsTypeCode = 7
)

type FsOpType string

const (
	FsOpRead      FsOpType = "read"
	FsOpWrite     FsOpType = "write"
	FsOpFsync     FsOpType = "fsync"
	FsOpFdatasync FsOpType = "fdatasync"
)

// FsOpCode mirrors enum fs_op in bpf/statsolly/types.h.
type FsOpCode uint8

const (
	CodeFsOpRead      FsOpCode = 0
	CodeFsOpWrite     FsOpCode = 1
	CodeFsOpFsync     FsOpCode = 2
	CodeFsOpFdatasync FsOpCode = 3
)

// Stat contains accumulated metrics from a stat, with extra metadata
// that is added from the user space
// REMINDER: any attribute here must be also added to the functions StatGetters
// in pkg/internal/statsolly/ebpf/stat_getters.go and getDefinitions in
// pkg/export/attributes/attr_defs.go
type Stat struct {
	Type                    StatType                 `json:"type"`
	TCPRtt                  *TCPRtt                  `json:"-"`
	TCPFailedConnection     *TCPFailedConnection     `json:"-"`
	TCPSuccessfulConnection *TCPSuccessfulConnection `json:"-"`
	TCPRetransmit           bool                     `json:"-"`
	TCPIo                   *TCPIo                   `json:"-"`
	BlockIo                 *BlockIo                 `json:"-"`
	FsIo                    *FsIo                    `json:"-"`
	NFSRPC                  *NFSRPC                  `json:"-"`

	// Attrs of the flow record: source/destination, OBI IP, etc...
	CommonAttrs pipe.CommonAttrs
}

type TCPRtt struct {
	SrttUs uint32 `json:"srtt_us"`
	Role   uint8  `json:"role"`
}

type TCPFailedConnection struct {
	Reason uint8 `json:"reason"`
	Role   uint8 `json:"role"`
}

type TCPSuccessfulConnection struct {
	Role uint8 `json:"role"`
}

type TCPIo struct {
	Direction uint8  `json:"direction"`
	Bytes     uint32 `json:"bytes"`
}

type BlockIo struct {
	Dev uint32 `json:"dev"`
	// Op is a BlockOpCode.
	Op        uint8  `json:"op"`
	LatencyNs uint64 `json:"latency_ns"`
	QueueNs   uint64 `json:"queue_ns"`
	Bytes     uint64 `json:"bytes"`
	Error     int32  `json:"error"`
	Inflight  uint32 `json:"inflight"`
}

// IsReadWrite reports whether b is a read or a write request: the only ones
// that feed the metrics with a disk.io.direction. It is false for a nil b.
func (b *BlockIo) IsReadWrite() bool {
	return b != nil && (BlockOpCode(b.Op) == CodeBlockRead || BlockOpCode(b.Op) == CodeBlockWrite)
}

// IsFlush reports whether b is a cache flush request. It is false for a nil b.
func (b *BlockIo) IsFlush() bool {
	return b != nil && BlockOpCode(b.Op) == CodeBlockFlush
}

// IsDiscard reports whether b is a discard (or secure erase) request. It is
// false for a nil b.
func (b *BlockIo) IsDiscard() bool {
	return b != nil && BlockOpCode(b.Op) == CodeBlockDiscard
}

type FsIo struct {
	Fs        uint8  `json:"fs"`
	Op        uint8  `json:"op"`
	SDev      uint32 `json:"s_dev"`
	HostPID   uint32 `json:"host_pid"`
	PidNs     uint32 `json:"pid_ns"`
	LatencyNs uint64 `json:"latency_ns"`
	Bytes     uint64 `json:"bytes"`
	Error     int32  `json:"error"`
	// RootIno is the inode of the root of the mount the file was reached
	// through, which tells apart volumes that share SDev.
	RootIno uint64 `json:"root_ino"`
	// Mount holds the attributes of the mount the file was reached through,
	// or nil when it is no Kubernetes volume. The PID decorator sets it.
	Mount *MountAttrs `json:"-"`
}

// MountAttrs are the attributes of a filesystem stat that depend only on the
// mount the I/O went through. They are resolved once per mount and shared by
// every stat of that mount, so the value is never modified once set: a new
// resolution makes a new MountAttrs.
type MountAttrs struct {
	PVName       string
	PVCName      string
	StorageClass string
	// PVCNamespace names the pod namespace of I/O whose process is in no
	// known pod.
	PVCNamespace string
	// SystemDevice, PhysicalDevice and ServerAddress are the fs join labels
	// of step 10 (system.device, obi.disk.physical_device, server.address):
	// resolved once per mount, alongside the PV/PVC lookup, so a getter
	// never takes the block-stack or mount-table locks per event.
	SystemDevice string
	// PhysicalDevice is "" when SystemDevice could not be resolved to a
	// block device (a network filesystem, or an anonymous superblock this
	// mount's source did not resolve either), and otherwise a
	// comma-separated, sorted, deduplicated list of the physical disks
	// behind it, capped at 8 members.
	PhysicalDevice string
	// ServerAddress is "" for ceph (several monitors, ambiguous) and local
	// filesystems.
	ServerAddress string
}

// NFSRPC is an NFS client RPC attempt, or the kernel aggregation key of
// attempts to one server with one procedure and outcome (struct nfs_rpc_key
// in bpf/statsolly/nfs_rpc.h).
type NFSRPC struct {
	// Owner attributes the RPC to a submitter (step 19): the cgroup v2 id
	// of the thread that called rpc_execute, or on a cgroup v1 host the
	// tgid of that thread (task->tk_owner); 0 when no pod attribute is
	// selected, or when the owner could not be read. It is not itself an
	// attribute: the decoration pipeline resolves it to the pod trio and
	// k8s.owner.name in CommonAttrs.Metadata.
	Owner uint64 `json:"owner"`
	// OwnerPending is set by the decoration when Owner could not be settled
	// yet (a cgroup the index has not scanned, a container the Kubernetes
	// store has not learned): the aggregated family decorates the key again
	// the next time it counts. Not part of the key or an attribute.
	OwnerPending bool `json:"-"`
	// Version is the NFS version: 2, 3 or 4 (whatever its minor version).
	Version uint8 `json:"version"`
	// StatIdx is the procedure number of an NFSv2 or NFSv3 RPC, the
	// NFSPROC4_CLNT_* operation index of an NFSv4 one.
	StatIdx uint16 `json:"stat_idx"`
	// Status is 0, or the RPC task's negative status: -errno, -528
	// (EJUKEBOX) or -NFS4ERR_*.
	Status int32 `json:"status"`
	// Family is the server address family, AF_INET or AF_INET6, or 0 when
	// the address is unknown. Addr holds 4 (AF_INET) or 16 bytes, in network
	// byte order, and ScopeID the IPv6 scope of a link-local server.
	Family  uint8    `json:"family"`
	Addr    [16]byte `json:"-"`
	ScopeID uint32   `json:"scope_id"`

	// ExecuteNs, Retransmits, TxBytes and RxBytes describe a single
	// attempt: kernel aggregation keeps their sums in the key's values
	// instead. TxBytes and RxBytes are the attempt's rq_xmit_bytes_sent and
	// rq_reply_bytes_recvd: the wire bytes of the call and its reply,
	// headers included, the same fields /proc/self/mountstats sums.
	ExecuteNs   uint64 `json:"execute_ns"`
	Retransmits uint64 `json:"retransmits"`
	TxBytes     uint64 `json:"tx_bytes"`
	RxBytes     uint64 `json:"rx_bytes"`

	// Direction is not part of the kernel key: it is set by the exporters
	// that split StatNFSClientIO's one kernel-counted value into its two
	// NetworkIoDirectionCode series, transmit and receive, right before
	// reading this stat's attributes.
	Direction uint8 `json:"-"`
}

// Conn mirrors connection_info_t from bpf/common/connection_info.h.
type Conn struct {
	_      structs.HostLayout
	S_addr [16]uint8 //nolint:revive,staticcheck
	D_addr [16]uint8 //nolint:revive,staticcheck
	S_port uint16    //nolint:revive,staticcheck
	D_port uint16    //nolint:revive,staticcheck
}

type StatsTCPRtt struct {
	_      structs.HostLayout
	Flags  uint8
	Role   uint8
	Pad    [2]uint8
	SrttUs uint32
	Conn
}

type StatsTCPFailedConnection struct {
	_      structs.HostLayout
	Flags  uint8
	Reason uint8
	Role   uint8
	Pad    [1]uint8
	Conn
}

type StatsTCPSuccessfulConnection struct {
	_     structs.HostLayout
	Flags uint8
	Role  uint8
	Pad   [2]uint8
	Conn
}

type StatsTCPRetransmit struct {
	_     structs.HostLayout
	Flags uint8
	Pad   [3]uint8
	Conn
}

type StatsTCPIo struct {
	_         structs.HostLayout
	Flags     uint8
	Direction uint8
	Count     uint8
	Pad       [1]uint8
	Bytes     [TCPIoBatchSize]uint32
	Conn
}

// StatsBlockIo mirrors block_io_t in bpf/statsolly/types.h.
type StatsBlockIo struct {
	_         structs.HostLayout
	Flags     uint8
	Op        uint8
	Pad       [2]uint8
	Dev       uint32
	LatencyNs uint64
	QueueNs   uint64
	Bytes     uint64
	Error     int32
	Inflight  uint32
	PartDev   uint32
	Pad2      [4]uint8
}

// StatsFsIo mirrors fs_io_t in bpf/statsolly/types.h.
type StatsFsIo struct {
	_         structs.HostLayout
	Flags     uint8
	Fs        uint8
	Op        uint8
	Pad       [1]uint8
	SDev      uint32
	HostPID   uint32
	PidNs     uint32
	LatencyNs uint64
	Bytes     uint64
	Error     int32
	Pad2      [4]uint8
	RootIno   uint64
}

// TCPIoBatchSize mirrors k_tcp_io_batch_size in bpf/statsolly/types.h.
const TCPIoBatchSize = 10
