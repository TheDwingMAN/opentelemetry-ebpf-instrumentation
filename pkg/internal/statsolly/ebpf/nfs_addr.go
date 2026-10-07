// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"encoding/binary"
	"net/netip"
	"strconv"
)

// Address families of an NFS RPC's server address, as the kernel stores them
// in rpc_xprt.addr (k_nfs_af_inet and k_nfs_af_inet6 in
// bpf/statsolly/nfs_rpc.h).
const (
	nfsAFInet  = 2
	nfsAFInet6 = 10
)

// nfsServerAddress returns the server address of an NFS RPC the way the
// kernel prints the mount option addr= of its mount (rpc_ntop in
// net/sunrpc/addr.c, the RPC_DISPLAY_ADDR string of the transport), so that
// server.address joins the RPC metrics with the filesystem metrics, which
// read addr=. addr holds 4 (AF_INET) or 16 bytes in network byte order.
// Unknown families give "", which leaves the attribute out.
//
// For IPv6 that is the kernel's own compression (%pI6c), which netip's
// matches except for ISATAP addresses, which the kernel prints with an
// embedded IPv4 address; a v4-mapped address stays mapped (::ffff:a.b.c.d),
// as the kernel prints it; and a link-local address with a scope id gets
// %<scope id>, a number, never an interface name.
func nfsServerAddress(family uint8, addr *[16]byte, scopeID uint32) string {
	switch family {
	case nfsAFInet:
		return netip.AddrFrom4([4]byte(addr[:4])).String()
	case nfsAFInet6:
		s := kernelIPv6String(addr)
		if scopeID != 0 && addr[0] == 0xfe && addr[1]&0xc0 == 0x80 {
			s += "%" + strconv.FormatUint(uint64(scopeID), 10)
		}
		return s
	}
	return ""
}

// kernelIPv6String is lib/vsprintf.c ip6_compressed_string: the first longest
// run of at least two zero words is compressed, words are lowercase hex
// without leading zeros, and v4-mapped and ISATAP addresses end with their
// IPv4 address.
func kernelIPv6String(addr *[16]byte) string {
	var words [8]uint16
	for i := range words {
		words[i] = binary.BigEndian.Uint16(addr[2*i:])
	}
	v4mapped := words[0]|words[1]|words[2]|words[3]|words[4] == 0 && words[5] == 0xffff
	// ipv6_addr_is_isatap: (s6_addr32[2] | htonl(0x02000000)) == htonl(0x02005EFE).
	isatap := (binary.BigEndian.Uint32(addr[8:]) | 0x02000000) == 0x02005efe
	useIPv4 := v4mapped || isatap
	n := 8
	if useIPv4 {
		n = 6
	}

	longest, colonPos := 1, -1
	for i := 0; i < n; i++ {
		run := 0
		for j := i; j < n && words[j] == 0; j++ {
			run++
		}
		if run > longest {
			longest, colonPos = run, i
		}
	}

	buf := make([]byte, 0, 46)
	needColon := false
	for i := 0; i < n; i++ {
		if i == colonPos {
			if needColon || i == 0 {
				buf = append(buf, ':')
			}
			buf = append(buf, ':')
			needColon = false
			i += longest - 1
			continue
		}
		if needColon {
			buf = append(buf, ':')
		}
		buf = strconv.AppendUint(buf, uint64(words[i]), 16)
		needColon = true
	}
	if useIPv4 {
		if needColon {
			buf = append(buf, ':')
		}
		buf = netip.AddrFrom4([4]byte(addr[12:16])).AppendTo(buf)
	}
	return string(buf)
}
