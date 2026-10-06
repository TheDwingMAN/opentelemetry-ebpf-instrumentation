// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Storage probes see errors the uapi errno table has no name for: the
// kernel-internal errnos from 512 on, and the NFSv4 statuses the NFS client
// passes up unmapped. The negative values are what the NFS spike (S0-c)
// observed on the wire.
func TestErrnoNameBeyondUapi(t *testing.T) {
	for _, tc := range []struct {
		err  int32
		want string
	}{
		{-528, "EJUKEBOX"},            // v3 WRITE answered NFS3ERR_JUKEBOX
		{-10008, "NFS4ERR_DELAY"},     // v4.2 OPEN answered NFS4ERR_DELAY
		{-10013, "NFS4ERR_GRACE"},     // expected on the same path; not observed yet
		{-512, "ERESTARTSYS"},         // first kernel-internal errno
		{-524, "ENOTSUPP"},            // not EOPNOTSUPP (95)
		{-531, "ENOGRACE"},            // last kernel-internal errno
		{-10001, "NFS4ERR_BADHANDLE"}, // first NFSv4 status
		{-10096, "NFS4ERR_XATTR2BIG"}, // last NFSv4 status
		{528, "EJUKEBOX"},             // the sign does not matter
	} {
		assert.Equal(t, tc.want, errnoName(tc.err), "%d", tc.err)
	}
}

// Anything without a name keeps its decimal value, as released: unassigned
// codes inside the tables, and values past them.
func TestErrnoNameDecimalFallback(t *testing.T) {
	for _, tc := range []struct {
		err  int32
		want string
	}{
		{-520, "520"},
		{-532, "532"},
		{-10002, "10002"},
		{-10073, "10073"},
		{-10097, "10097"},
		{-5000, "5000"},
		{math.MinInt32, "2147483648"},
	} {
		assert.Equal(t, tc.want, errnoName(tc.err), "%d", tc.err)
	}
}

func TestErrnoNameForErrorOmitsSuccess(t *testing.T) {
	assert.Empty(t, errnoNameForError(0))
	assert.Equal(t, "EJUKEBOX", errnoNameForError(-528))
}

// The NFS RPC errors S0-c observed, as error.type names them: tk_status is
// -errno, or -528 for a v3 JUKEBOX, or -NFS4ERR_* for a v4 status the client
// does not map.
func TestNFSRPCErrorType(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version uint8
		statIdx uint16
		status  int32
		want    string
	}{
		{"v3 READ", 3, 6, -13, "EACCES"},
		{"v3 WRITE", 3, 7, -528, "EJUKEBOX"},
		{"v3 LOOKUP", 3, 3, -2, "ENOENT"},
		{"v4 READ", 4, 1, -13, "EACCES"},
		{"v4 OPEN_NOATTR", 4, 25, -13, "EACCES"},
		{"v4 OPEN", 4, 2, -10008, "NFS4ERR_DELAY"},
		// UNVERIFIED: GRACE is expected on the same path as DELAY; S0-c
		// could not reproduce it without restarting the lab's nfsd.
		{"v4 OPEN in grace", 4, 2, -10013, "NFS4ERR_GRACE"},
		{"success", 3, 6, 0, ""},
	} {
		s := &Stat{Type: StatTypeNFSRPC, NFSRPC: &NFSRPC{Version: tc.version, StatIdx: tc.statIdx, Status: tc.status}}
		assert.Equal(t, tc.want, errorTypeStr(s), tc.name)
	}
}
