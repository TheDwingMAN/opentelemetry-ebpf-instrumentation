// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

const (
	statTypesHeader = "../../../../bpf/statsolly/types.h"
	statsRegistry   = "../../../../schemas/obi/groups/stats/registry.yaml"
)

// cEnumCodes returns the member values of a C enum in statTypesHeader.
func cEnumCodes(t *testing.T, enum string) map[string]uint8 {
	t.Helper()

	src, err := os.ReadFile(statTypesHeader)
	require.NoError(t, err)
	body := regexp.MustCompile(`(?s)enum ` + enum + `\b[^{]*\{(.*?)\};`).FindSubmatch(src)
	require.NotNil(t, body, "enum %s not found in %s", enum, statTypesHeader)

	codes := map[string]uint8{}
	for _, m := range regexp.MustCompile(`(\w+)\s*=\s*(\d+)`).FindAllSubmatch(body[1], -1) {
		v, err := strconv.ParseUint(string(m[2]), 10, 8)
		require.NoError(t, err)
		codes[string(m[1])] = uint8(v)
	}
	require.NotEmpty(t, codes, "enum %s has no explicit values", enum)
	return codes
}

// registryMembers returns the values of an enum attribute in statsRegistry.
func registryMembers(t *testing.T, attrID string) map[string]bool {
	t.Helper()

	src, err := os.ReadFile(statsRegistry)
	require.NoError(t, err)
	var reg struct {
		Groups []struct {
			Attributes []struct {
				ID   string `yaml:"id"`
				Type struct {
					Members []struct {
						Value string `yaml:"value"`
					} `yaml:"members"`
				} `yaml:"type"`
			} `yaml:"attributes"`
		} `yaml:"groups"`
	}
	require.NoError(t, yaml.Unmarshal(src, &reg))

	for _, g := range reg.Groups {
		for _, a := range g.Attributes {
			if a.ID != attrID {
				continue
			}
			members := map[string]bool{}
			for _, m := range a.Type.Members {
				members[m.Value] = true
			}
			return members
		}
	}
	require.Failf(t, "attribute not in the registry", "%s in %s", attrID, statsRegistry)
	return nil
}

// Every operation code the kernel can send has a name, and that name is a
// member of the registry's closed fs.operation enum.
func TestFsOpCodesMatchRegistry(t *testing.T) {
	members := registryMembers(t, "fs.operation")
	for member, code := range cEnumCodes(t, "fs_op") {
		name := fsOpStr(FsOpCode(code))
		assert.NotEmpty(t, name, "%s (%d) has no name", member, code)
		assert.True(t, members[name], "%s (%d) maps to %q, not a registry member", member, code, name)
	}
}

// Every filesystem code but fs_type_unknown has a name; unknown has none, so
// the attribute is omitted. system.filesystem.type is an open semconv enum.
func TestFsTypeCodesHaveNames(t *testing.T) {
	for member, code := range cEnumCodes(t, "fs_type") {
		if FsTypeCode(code) == CodeFsUnknown {
			assert.Empty(t, fsTypeStr(FsTypeCode(code)), member)
			continue
		}
		assert.NotEmpty(t, fsTypeStr(FsTypeCode(code)), "%s (%d) has no name", member, code)
	}
}

// Only reads and writes have a disk.io.direction, one of the two values of
// the semconv enum; flushes and discards omit it.
func TestBlockOpCodesDirection(t *testing.T) {
	for member, code := range cEnumCodes(t, "blk_io_op") {
		dir := diskIoDirectionStr(DiskIoDirectionCode(code))
		switch BlockOpCode(code) {
		case CodeBlockRead:
			assert.Equal(t, "read", dir, member)
		case CodeBlockWrite:
			assert.Equal(t, "write", dir, member)
		default:
			assert.Empty(t, dir, member)
		}
	}
}
