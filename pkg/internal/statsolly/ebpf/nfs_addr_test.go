// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"math/rand/v2"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

// server.address of an NFS RPC must equal, byte for byte, the addr= mount
// option the kernel prints for the same transport (rpc_ntop), which the
// filesystem metrics read: the fs <-> NFS join depends on it. The expected
// strings follow net/sunrpc/addr.c and lib/vsprintf.c ip6_compressed_string.
func TestNFSServerAddressIsTheKernelsAddr(t *testing.T) {
	v6 := func(s string) [16]byte { return netip.MustParseAddr(s).As16() }
	for _, tc := range []struct {
		name   string
		family uint8
		addr   [16]byte
		scope  uint32
		want   string
	}{
		{"IPv4", nfsAFInet, [16]byte{192, 168, 122, 34}, 0, "192.168.122.34"},
		{"IPv6", nfsAFInet6, v6("2001:db8::1"), 0, "2001:db8::1"},
		{"IPv6 leading zeros", nfsAFInet6, v6("2001:0db8:000a:0:0:0:0:00ff"), 0, "2001:db8:a::ff"},
		{"a single zero word is not compressed", nfsAFInet6, v6("2001:db8:0:1:1:1:1:1"), 0, "2001:db8:0:1:1:1:1:1"},
		{"first of two longest zero runs", nfsAFInet6, v6("2001:0:0:1:0:0:1:1"), 0, "2001::1:0:0:1:1"},
		{"trailing zero run", nfsAFInet6, v6("2001:db8:1::"), 0, "2001:db8:1::"},
		{"unspecified", nfsAFInet6, v6("::"), 0, "::"},
		{"loopback", nfsAFInet6, v6("::1"), 0, "::1"},
		// The kernel keeps a v4-mapped address mapped in addr=.
		{"v4-mapped", nfsAFInet6, v6("::ffff:10.0.0.1"), 0, "::ffff:10.0.0.1"},
		{"link-local with its scope id", nfsAFInet6, v6("fe80::2"), 2, "fe80::2%2"},
		{"link-local without a scope id", nfsAFInet6, v6("fe80::2"), 0, "fe80::2"},
		{"a scope id outside link-local is not printed", nfsAFInet6, v6("2001:db8::1"), 5, "2001:db8::1"},
		// %pI6c prints ISATAP interface ids with an embedded IPv4 address,
		// which netip does not.
		{"ISATAP", nfsAFInet6, v6("fe80::5efe:c0a8:101"), 3, "fe80::5efe:192.168.1.1%3"},
		{"ISATAP, universal", nfsAFInet6, v6("2001:db8::200:5efe:a00:1"), 0, "2001:db8::200:5efe:10.0.0.1"},
		{"unknown family", 1, [16]byte{1}, 0, ""},
	} {
		assert.Equal(t, tc.want, nfsServerAddress(tc.family, &tc.addr, tc.scope), tc.name)
	}
}

// Outside ISATAP interface ids, the kernel's IPv6 form is RFC 5952's, which
// netip prints: compare them over addresses with random zero runs.
func TestKernelIPv6StringMatchesNetip(t *testing.T) {
	rnd := rand.New(rand.NewPCG(1, 2))
	for range 20000 {
		var addr [16]byte
		for w := 0; w < 16; w += 2 {
			if rnd.IntN(2) == 0 {
				continue
			}
			addr[w], addr[w+1] = byte(rnd.IntN(3)), byte(rnd.IntN(256))
		}
		if isatap := (uint32(addr[8])<<24|uint32(addr[9])<<16|uint32(addr[10])<<8|uint32(addr[11]))|0x02000000 == 0x02005efe; isatap {
			continue
		}
		assert.Equal(t, netip.AddrFrom16(addr).String(), kernelIPv6String(&addr), "%x", addr)
	}
}

func BenchmarkNFSServerAddress(b *testing.B) {
	v4 := [16]byte{192, 168, 122, 34}
	v6 := netip.MustParseAddr("2001:db8:0:0:1::1").As16()
	b.Run("IPv4", func(b *testing.B) {
		for b.Loop() {
			_ = nfsServerAddress(nfsAFInet, &v4, 0)
		}
	})
	b.Run("IPv6", func(b *testing.B) {
		for b.Loop() {
			_ = nfsServerAddress(nfsAFInet6, &v6, 0)
		}
	})
}
