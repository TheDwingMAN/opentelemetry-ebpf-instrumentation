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
	StatTypeDiskIO                  = StatType(StatsStatTypeK_statTypeDiskIo)
	StatTypeFsSync                  = StatType(StatsStatTypeK_statTypeFsSync)
	StatTypeDiskPending             = StatType(StatsStatTypeK_statTypeDiskPending)
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

type DiskIODirectionType string

const (
	DiskDirectionRead  DiskIODirectionType = "read"
	DiskDirectionWrite DiskIODirectionType = "write"
)

// DiskOpCode aliases the bpf2go-generated constants derived from enum disk_op in
// bpf/statsolly/types.h.
type DiskOpCode uint8

const (
	CodeDiskOpRead    = DiskOpCode(StatsDiskOpDiskOpRead)
	CodeDiskOpWrite   = DiskOpCode(StatsDiskOpDiskOpWrite)
	CodeDiskOpFlush   = DiskOpCode(StatsDiskOpDiskOpFlush)
	CodeDiskOpDiscard = DiskOpCode(StatsDiskOpDiskOpDiscard)
)

// IsTransfer tells whether the operation reads or writes data, the operations that the disk I/O
// metrics report per direction
func (o DiskOpCode) IsTransfer() bool {
	return o == CodeDiskOpRead || o == CodeDiskOpWrite
}

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
	DiskIO                  *DiskIO                  `json:"-"`
	DiskPending             *DiskPending             `json:"-"`
	FsSync                  *FsSync                  `json:"-"`

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

// DiskIO is the block I/O completed on a device, with an operation and an outcome, and charged
// to a cgroup, since the previous read of the kernel accumulation map.
type DiskIO struct {
	Device string
	// Partition of Device that the I/O targets. Empty for I/O on the whole device.
	Partition string
	// Stacked devices are built on other block devices, which report the same I/O too
	Stacked bool
	Op      DiskOpCode
	// ErrorType is empty for successful requests
	ErrorType string
	// ContainerID of the cgroup the I/O is charged to. Empty for I/O charged to no container.
	ContainerID string

	Operations uint64
	// Time is the sum of the latencies of the operations, in seconds
	Time float64
	// Bytes transferred by the operations that succeeded
	Bytes uint64
	// Latency of the completed requests, as one representative value per kernel histogram bucket
	Latency []LatencySample
	// Queue is the time that the requests waited before their issue to the device, for the
	// requests whose wait the kernel knows
	Queue []LatencySample
}

// DiskPending is the number of block requests of an operation that a device is serving
type DiskPending struct {
	Device   string
	Stacked  bool
	Op       DiskOpCode
	Requests int64
}

// ContainerID returns the container that a block I/O or file sync stat is charged to, or an empty
// string for any other stat
func (s *Stat) ContainerID() string {
	switch {
	case s.DiskIO != nil:
		return s.DiskIO.ContainerID
	case s.FsSync != nil:
		return s.FsSync.ContainerID
	}
	return ""
}

// FsSync is the file syncs that completed with an outcome and charged to a cgroup, since the
// previous read of the kernel accumulation map.
type FsSync struct {
	// ErrorType is empty for successful syncs
	ErrorType string
	// ContainerID of the cgroup of the thread that synced. Empty outside containers.
	ContainerID string
	// Latency of the syncs, as one representative value per kernel histogram bucket
	Latency []LatencySample
}

// LatencySample stands for Count requests whose latency fell in the same kernel histogram
// bucket. Seconds is their mean latency, which always falls in that bucket.
type LatencySample struct {
	Seconds float64
	Count   uint64
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

// TCPIoBatchSize mirrors k_tcp_io_batch_size in bpf/statsolly/types.h.
const TCPIoBatchSize = 10
