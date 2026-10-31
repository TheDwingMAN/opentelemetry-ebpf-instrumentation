// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

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
			var device string
			if s.DiskIO != nil {
				device = s.DiskIO.Device
			}
			return attribute.String(string(attr.SystemDevice), device)
		}
	case attr.DiskStacked:
		getter = func(s *Stat) attribute.KeyValue {
			var stacked bool
			if s.DiskIO != nil {
				stacked = s.DiskIO.Stacked
			}
			return attribute.Bool(string(attr.DiskStacked), stacked)
		}
	case attr.DiskVolumeName:
		getter = func(s *Stat) attribute.KeyValue {
			// the devices that aren't device mapper volumes have none: an invalid KeyValue isn't exported
			if s.DiskIO == nil || s.DiskIO.VolumeName == "" {
				return attribute.KeyValue{}
			}
			return attribute.String(string(attr.DiskVolumeName), s.DiskIO.VolumeName)
		}
	case attr.DiskIODirection:
		getter = func(s *Stat) attribute.KeyValue {
			var op DiskOpCode
			if s.DiskIO != nil {
				op = s.DiskIO.Op
			}
			return attribute.String(string(attr.DiskIODirection), diskIODirectionStr(op))
		}
	case attr.ServerAddr:
		getter = func(s *Stat) attribute.KeyValue {
			if s.NFSProcedure == nil {
				return attribute.KeyValue{}
			}
			return attribute.String(string(attr.ServerAddr), s.NFSProcedure.Server)
		}
	case attr.OncRPCProcedureName:
		getter = func(s *Stat) attribute.KeyValue {
			if s.NFSProcedure == nil || isNFSv4(s.NFSProcedure.Version) {
				return attribute.KeyValue{}
			}
			return attribute.String(string(attr.OncRPCProcedureName), s.NFSProcedure.Procedure)
		}
	case attr.NfsOperationName:
		getter = func(s *Stat) attribute.KeyValue {
			if s.NFSProcedure == nil || !isNFSv4(s.NFSProcedure.Version) {
				return attribute.KeyValue{}
			}
			return attribute.String(string(attr.NfsOperationName), s.NFSProcedure.Procedure)
		}
	case attr.OncRPCVersion:
		getter = func(s *Stat) attribute.KeyValue {
			if s.NFSProcedure == nil {
				return attribute.KeyValue{}
			}
			return attribute.Int(string(attr.OncRPCVersion), int(s.NFSProcedure.Version))
		}
	case attr.FsSyncType:
		getter = func(s *Stat) attribute.KeyValue {
			var syncType FsSyncTypeCode
			if s.FsSync != nil {
				syncType = s.FsSync.Type
			}
			return attribute.String(string(attr.FsSyncType), fsSyncTypeStr(syncType))
		}
	case attr.ErrorType:
		getter = func(s *Stat) attribute.KeyValue {
			var errorType string
			switch {
			case s.DiskIO != nil:
				errorType = s.DiskIO.ErrorType
			case s.FsSync != nil:
				errorType = s.FsSync.ErrorType
			case s.NFSProcedure != nil:
				errorType = s.NFSProcedure.ErrorType
			}
			// the successful operations have none: an invalid KeyValue isn't exported
			if errorType == "" {
				return attribute.KeyValue{}
			}
			return attribute.String(string(attr.ErrorType), errorType)
		}
	case attr.ContainerID:
		getter = func(s *Stat) attribute.KeyValue {
			var containerID string
			switch {
			case s.DiskIO != nil:
				containerID = s.DiskIO.ContainerID
			case s.FsSync != nil:
				containerID = s.FsSync.ContainerID
			}
			if containerID == "" {
				return attribute.KeyValue{}
			}
			return attribute.String(string(attr.ContainerID), containerID)
		}

	default:
		getter = func(s *Stat) attribute.KeyValue {
			value := s.CommonAttrs.Metadata[name]
			// the storage stats leave out the metadata that they don't have, like the Kubernetes
			// attributes of the I/O charged to no pod: an invalid KeyValue isn't exported
			if value == "" && (s.Type == StatTypeDiskIO || s.Type == StatTypeFsSync || s.Type == StatTypeNFSProcedure) {
				return attribute.KeyValue{}
			}
			return attribute.String(string(name), value)
		}
	}
	return getter, getter != nil
}

// nfsV4 is the first version of the NFS protocol whose procedures are COMPOUND requests of operations
const nfsV4 = 4

// isNFSv4 tells whether an NFS version names its RPCs after NFSv4 operations, which the semantic
// conventions call nfs.operation.name, rather than after ONC RPC procedures, as NFSv2 and NFSv3 do
func isNFSv4(version uint32) bool {
	return version >= nfsV4
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

func diskIODirectionStr(op DiskOpCode) string {
	switch op {
	case CodeDiskOpRead:
		return semconv.DiskIODirectionRead.Value.AsString()
	case CodeDiskOpWrite:
		return semconv.DiskIODirectionWrite.Value.AsString()
	}
	return ""
}

func fsSyncTypeStr(syncType FsSyncTypeCode) string {
	switch syncType {
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
	return ""
}
