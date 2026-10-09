// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// StatGetters returns the attributes.Getter function that returns the string value of a given
// attribute name.
//
//nolint:cyclop
func StatGetters(name attr.Name) (attributes.Getter[*Stat, attribute.KeyValue], bool) {
	var getter attributes.Getter[*Stat, attribute.KeyValue]
	switch name {
	case attr.OBIIP:
		getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(attr.OBIIP), s.CommonAttrs.OBIIP) }
	case attr.SrcAddress:
		getter = func(s *Stat) attribute.KeyValue {
			return attribute.String(string(attr.SrcAddress), s.CommonAttrs.SrcAddr.IP().String())
		}
	case attr.DstAddress:
		getter = func(s *Stat) attribute.KeyValue {
			return attribute.String(string(attr.DstAddress), s.CommonAttrs.DstAddr.IP().String())
		}
	case attr.SrcPort:
		getter = func(s *Stat) attribute.KeyValue {
			return attribute.Int(string(attr.SrcPort), int(s.CommonAttrs.SrcPort))
		}
	case attr.DstPort:
		getter = func(s *Stat) attribute.KeyValue {
			return attribute.Int(string(attr.DstPort), int(s.CommonAttrs.DstPort))
		}
	case attr.SrcName:
		getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(attr.SrcName), s.CommonAttrs.SrcName) }
	case attr.DstName:
		getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(attr.DstName), s.CommonAttrs.DstName) }
	case attr.SrcZone:
		getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(attr.SrcZone), s.CommonAttrs.SrcZone) }
	case attr.DstZone:
		getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(attr.DstZone), s.CommonAttrs.DstZone) }
	case attr.TCPFailedConnectionReason:
		getter = func(s *Stat) attribute.KeyValue {
			if s.TCPFailedConnection == nil {
				return attribute.String(string(attr.TCPFailedConnectionReason), string(Unknown))
			}
			return attribute.String(string(attr.TCPFailedConnectionReason), tcpFailReasonStr(s.TCPFailedConnection.Reason))
		}
	case attr.NetworkTCPHandshakeRole:
		getter = func(s *Stat) attribute.KeyValue {
			var role uint8
			switch s.Type {
			case StatTypeTCPFailedConnection:
				role = s.TCPFailedConnection.Role
			case StatTypeTCPRtt:
				role = s.TCPRtt.Role
			case StatTypeTCPSuccessfulConnection:
				role = s.TCPSuccessfulConnection.Role
			}
			return attribute.String(string(attr.NetworkTCPHandshakeRole), networkTCPHandshakeRoleStr(role))
		}
	case attr.NetworkIoDirection:
		getter = func(s *Stat) attribute.KeyValue {
			var direction uint8
			if s.TCPIo != nil {
				direction = s.TCPIo.Direction
			}
			return attribute.String(string(attr.NetworkIoDirection), networkIoDirectionStr(NetworkIoDirectionCode(direction)))
		}
	case attr.SystemDevice:
		getter = func(s *Stat) attribute.KeyValue {
			if s.DiskIO != nil && s.DiskIO.Device != "" {
				return attribute.String(string(attr.SystemDevice), s.DiskIO.Device)
			}
			return attribute.KeyValue{}
		}
	case attr.DiskStacked:
		getter = func(s *Stat) attribute.KeyValue {
			if s.DiskIO != nil {
				return attribute.Bool(string(attr.DiskStacked), s.DiskIO.Stacked)
			}
			return attribute.KeyValue{}
		}
	case attr.DiskVolumeName:
		getter = func(s *Stat) attribute.KeyValue {
			if s.DiskIO != nil && s.DiskIO.VolumeName != "" {
				return attribute.String(string(attr.DiskVolumeName), s.DiskIO.VolumeName)
			}
			return attribute.KeyValue{}
		}
	case attr.DiskIODirection:
		getter = func(s *Stat) attribute.KeyValue {
			if s.DiskIO == nil {
				return attribute.KeyValue{}
			}
			if direction := diskIODirectionStr(s.DiskIO.Op); direction != "" {
				return attribute.String(string(attr.DiskIODirection), direction)
			}
			return attribute.KeyValue{}
		}
	case attr.FsSyncType:
		getter = func(s *Stat) attribute.KeyValue {
			if s.FsSync == nil {
				return attribute.KeyValue{}
			}
			return attribute.String(string(attr.FsSyncType), fsSyncTypeStr(s.FsSync.Type))
		}
	case attr.ErrorType:
		getter = func(s *Stat) attribute.KeyValue {
			// error.type only applies to failed operations: return an invalid
			// KeyValue so the attribute is omitted instead of emitted empty.
			if errorType := storageErrorType(s); errorType != "" {
				return attribute.String(string(attr.ErrorType), errorType)
			}
			return attribute.KeyValue{}
		}
	case attr.ContainerID:
		getter = func(s *Stat) attribute.KeyValue {
			if containerID := s.ContainerID(); containerID != "" {
				return attribute.String(string(attr.ContainerID), containerID)
			}
			return attribute.KeyValue{}
		}

	default:
		getter = func(s *Stat) attribute.KeyValue {
			value := s.CommonAttrs.Metadata[name]
			// the Kubernetes metadata that is unknown for a storage stat (no pod, or no cluster
			// name) is omitted instead of exported empty
			if value == "" && isStorageStat(s) {
				return attribute.KeyValue{}
			}
			return attribute.String(string(name), value)
		}
	}
	return getter, getter != nil
}

// isStorageStat tells whether a stat is a block I/O or file sync stat, not a TCP one
func isStorageStat(s *Stat) bool {
	return s.Type == StatTypeDiskIO || s.Type == StatTypeFsSync
}

// storageErrorType is the error of a block I/O or file sync stat, empty on success and for any
// other stat
func storageErrorType(s *Stat) string {
	switch {
	case s.DiskIO != nil:
		return s.DiskIO.ErrorType
	case s.FsSync != nil:
		return s.FsSync.ErrorType
	}
	return ""
}

func StatStringGetters(name attr.Name) (attributes.Getter[*Stat, string], bool) {
	if g, ok := StatGetters(name); ok {
		return func(s *Stat) string { return g(s).Value.Emit() }, true
	}
	return nil, false
}

func tcpFailReasonStr(reason uint8) string {
	switch TCPFailReasonTypeCode(reason) {
	case CodeConnectionRefused:
		return string(ConnectionRefused)
	case CodeConnectionReset:
		return string(ConnectionReset)
	case CodeTimedOut:
		return string(TimedOut)
	case CodeHostUnreachable:
		return string(HostUnreachable)
	case CodeNetUnreachable:
		return string(NetUnreachable)
	case CodeOther:
		return string(Other)
	default:
		return string(Unknown)
	}
}

func networkTCPHandshakeRoleStr(role uint8) string {
	switch NetworkTCPHandshakeRoleCode(role) {
	case CodeRoleClient:
		return string(RoleClient)
	case CodeRoleServer:
		return string(RoleServer)
	default:
		return string(RoleUnknown)
	}
}

func networkIoDirectionStr(d NetworkIoDirectionCode) string {
	switch d {
	case CodeDirectionTransmit:
		return string(DirectionTransmit)
	case CodeDirectionReceive:
		return string(DirectionReceive)
	}
	return ""
}

// diskIODirectionStr is the disk.io.direction of reads and writes, empty for other operations
func diskIODirectionStr(op DiskOpCode) string {
	switch op {
	case CodeDiskOpRead:
		return string(DiskDirectionRead)
	case CodeDiskOpWrite:
		return string(DiskDirectionWrite)
	}
	return ""
}

// fsSyncTypeStr is the obi.fs.sync.type of a file sync
func fsSyncTypeStr(t FsSyncTypeCode) string {
	switch t {
	case CodeFsSyncFsync:
		return "fsync"
	case CodeFsSyncFdatasync:
		return "fdatasync"
	case CodeFsSyncSync:
		return "sync"
	case CodeFsSyncSyncfs:
		return "syncfs"
	case CodeFsSyncSyncFileRange:
		return "sync_file_range"
	}
	return "unknown"
}
