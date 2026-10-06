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
	FsUnknown FsTypeName = "unknown"
	FsNFS     FsTypeName = "nfs"
	FsCeph    FsTypeName = "ceph"
	FsCIFS    FsTypeName = "cifs"
	FsFUSE    FsTypeName = "fuse"
	FsExt4    FsTypeName = "ext4"
	FsXFS     FsTypeName = "xfs"
	FsBtrfs   FsTypeName = "btrfs"
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
