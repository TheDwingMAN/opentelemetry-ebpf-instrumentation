# Claude Code Instructions

@AGENTS.md
@AI-POLICY.md

## Path-scoped instructions

The files below carry an `applyTo:` glob in their frontmatter. Apply each one
whenever you create, modify, or review a file matching its glob.

- `**/*.go` → @.github/instructions/go.instructions.md
- `bpf/**/*.c`, `bpf/**/*.h` → @.github/instructions/ebpf.instructions.md
