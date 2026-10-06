// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"sync/atomic"

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
	case attr.DiskDevice:
		getter = func(s *Stat) attribute.KeyValue {
			var dev uint32
			if s.BlockIo != nil {
				dev = s.BlockIo.Dev
			}
			return attribute.String(string(attr.DiskDevice), deviceName(dev))
		}
	case attr.DiskIODirection:
		getter = func(s *Stat) attribute.KeyValue {
			var op uint8
			if s.BlockIo != nil {
				op = s.BlockIo.Op
			}
			return attribute.String(string(attr.DiskIODirection), diskIoDirectionStr(DiskIoDirectionCode(op)))
		}
	case attr.FsType:
		getter = func(s *Stat) attribute.KeyValue {
			if s.FsIo == nil {
				return attribute.String(string(attr.FsType), "")
			}
			return attribute.String(string(attr.FsType), fsTypeStr(FsTypeCode(s.FsIo.Fs)))
		}
	case attr.FsOperation:
		getter = func(s *Stat) attribute.KeyValue {
			if s.FsIo == nil {
				return attribute.String(string(attr.FsOperation), "")
			}
			return attribute.String(string(attr.FsOperation), fsOpStr(FsOpCode(s.FsIo.Op)))
		}
	case attr.ErrorType:
		// Omitted when the operation succeeded, as semconv asks: the metrics
		// that record successes too (the flush and discard durations) carry
		// no error.type then.
		getter = func(s *Stat) attribute.KeyValue {
			errType := errorTypeStr(s)
			if errType == "" {
				return attribute.KeyValue{}
			}
			return attribute.String(string(attr.ErrorType), errType)
		}
	case attr.K8sPersistentVolumeName:
		getter = mountAttrGetter(name, func(m *MountAttrs) string { return m.PVName })
	case attr.K8sPersistentVolumeClaimName:
		getter = mountAttrGetter(name, func(m *MountAttrs) string { return m.PVCName })
	case attr.K8sStorageClassName:
		getter = mountAttrGetter(name, func(m *MountAttrs) string { return m.StorageClass })
	case attr.K8sNodeName:
		// The agent sees only the processes of its own node, so the value is
		// the same for every stat and is built once, with the getter.
		kv := attribute.String(string(attr.K8sNodeName), NodeName())
		getter = func(*Stat) attribute.KeyValue { return kv }
	default:
		getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(name), s.CommonAttrs.Metadata[name]) }
	}
	return getter, getter != nil
}

// mountAttrGetter reads an attribute of the mount a filesystem stat went
// through, resolved once per mount by the PID decorator; "" when there is none.
func mountAttrGetter(name attr.Name, field func(*MountAttrs) string) attributes.Getter[*Stat, attribute.KeyValue] {
	return func(s *Stat) attribute.KeyValue {
		if s.FsIo == nil || s.FsIo.Mount == nil {
			return attribute.String(string(name), "")
		}
		return attribute.String(string(name), field(s.FsIo.Mount))
	}
}

// nodeName is the Kubernetes node the agent runs on, "" when unknown.
var nodeName atomic.Pointer[string]

// SetNodeName records the Kubernetes node the agent runs on. The stats
// pipeline calls it before its exporters build their getters.
func SetNodeName(name string) { nodeName.Store(&name) }

// NodeName returns the name SetNodeName recorded, or "".
func NodeName() string {
	if n := nodeName.Load(); n != nil {
		return *n
	}
	return ""
}

func StatStringGetters(name attr.Name) (attributes.Getter[*Stat, string], bool) {
	if g, ok := StatGetters(name); ok {
		return func(s *Stat) string {
			// An invalid (zero) KeyValue means "omit this attribute".
			// Prometheus label sets are fixed, so omission is the empty
			// value rather than Value.Emit()'s "unknown" placeholder.
			if kv := g(s); kv.Valid() {
				return kv.Value.Emit()
			}
			return ""
		}, true
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

func diskIoDirectionStr(d DiskIoDirectionCode) string {
	switch d {
	case CodeDirectionRead:
		return string(DirectionRead)
	case CodeDirectionWrite:
		return string(DirectionWrite)
	}
	return ""
}

// fsTypeStr returns "" for a code with no name, fs_type_unknown included, so
// the attribute is omitted rather than set to a made-up type.
func fsTypeStr(f FsTypeCode) string {
	switch f {
	case CodeFsNFS:
		return string(FsNFS)
	case CodeFsCeph:
		return string(FsCeph)
	case CodeFsCIFS:
		return string(FsCIFS)
	case CodeFsFUSE:
		return string(FsFUSE)
	case CodeFsExt4:
		return string(FsExt4)
	case CodeFsXFS:
		return string(FsXFS)
	case CodeFsBtrfs:
		return string(FsBtrfs)
	}
	return ""
}

// fsOpStr returns "" for a code with no name, so an operation the probes
// report and this table does not know is never counted as a read.
func fsOpStr(o FsOpCode) string {
	switch o {
	case CodeFsOpRead:
		return string(FsOpRead)
	case CodeFsOpWrite:
		return string(FsOpWrite)
	case CodeFsOpFsync:
		return string(FsOpFsync)
	case CodeFsOpFdatasync:
		return string(FsOpFdatasync)
	}
	return ""
}

// errorTypeStr returns the errno name for a failed BlockIo or FsIo event
// (Error holds 0 or -errno), or "" when there was no error or the stat
// carries neither event type.
func errorTypeStr(s *Stat) string {
	switch {
	case s.BlockIo != nil:
		return errnoNameForError(s.BlockIo.Error)
	case s.FsIo != nil:
		return errnoNameForError(s.FsIo.Error)
	default:
		return ""
	}
}

// errnoNameForError returns the errno name for a non-zero error (0 or
// -errno), or "" when there was no error.
func errnoNameForError(err int32) string {
	if err == 0 {
		return ""
	}
	return errnoName(err)
}
