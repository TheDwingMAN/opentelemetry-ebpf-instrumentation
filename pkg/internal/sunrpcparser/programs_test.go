// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sunrpcparser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProcedureLabel(t *testing.T) {
	tests := []struct {
		name string
		prog uint32
		vers uint32
		proc uint32
		want string
	}{
		{"portmap v2 GETPORT", ProgramPortmapper, 2, 3, "GETPORT"},
		{"portmap v2 NULL", ProgramPortmapper, 2, 0, "NULL"},
		{"rpcbind v3 GETADDR", ProgramPortmapper, 3, 3, "GETADDR"},
		{"rpcbind v3 has no GETVERSADDR", ProgramPortmapper, 3, 9, "9"},
		{"rpcbind v4 GETVERSADDR", ProgramPortmapper, 4, 9, "GETVERSADDR"},
		{"mount v1 EXPORT", ProgramMount, 1, 5, "EXPORT"},
		{"mount v1 has no PATHCONF", ProgramMount, 1, 7, "7"},
		{"mount v2 PATHCONF", ProgramMount, 2, 7, "PATHCONF"},
		{"mount v3 MNT", ProgramMount, 3, 1, "MNT"},
		{"mount v3 has no EXPORTALL", ProgramMount, 3, 6, "6"},
		{"nfs v2 WRITE", ProgramNFS, 2, 8, "WRITE"},
		{"nfs v3 READ", ProgramNFS, 3, 6, "READ"},
		{"nfs v3 WRITE", ProgramNFS, 3, 7, "WRITE"},
		{"nfs v3 COMMIT", ProgramNFS, 3, 21, "COMMIT"},
		{"nfs v3 out of range", ProgramNFS, 3, 22, "22"},
		{"nfs v4 COMPOUND", ProgramNFS, 4, 1, "COMPOUND"},
		{"nfs unknown version", ProgramNFS, 5, 1, "1"},
		{"nlm v4 LOCK", ProgramNlockmgr, 4, 2, "LOCK"},
		{"nlm v4 FREE_ALL", ProgramNlockmgr, 4, 23, "FREE_ALL"},
		{"nlm v4 unassigned number", ProgramNlockmgr, 4, 17, "17"},
		{"nlm v2 has no SHARE", ProgramNlockmgr, 2, 20, "20"},
		{"unknown program", 200000, 1, 1, "1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ProcedureLabel(tt.prog, tt.vers, tt.proc))
		})
	}
}

func TestProcedureNames_noGapsExceptNLM(t *testing.T) {
	for _, names := range [][]string{
		portmapV2Procedures, rpcbindV4Procedures, mountV2Procedures, mountV3Procedures,
		nfsV2Procedures, nfsV3Procedures, nfsV4Procedures,
	} {
		for proc, name := range names {
			assert.NotEmpty(t, name, "procedure %d", proc)
		}
	}
}
