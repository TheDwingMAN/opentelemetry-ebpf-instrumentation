#!/usr/bin/env python3
"""Extract the cpio payload of an RPM into a directory (no rpm tools needed).

Usage: rpm-extract.py <file.rpm> <dest-dir>
"""
import struct
import subprocess
import sys


def header_end(data, off):
    # header: magic(3) version(1) reserved(4) nindex(4) hsize(4), then 16*nindex + hsize
    if data[off:off + 3] != b"\x8e\xad\xe8":
        raise SystemExit(f"bad header magic at {off}")
    nindex, hsize = struct.unpack(">II", data[off + 8:off + 16])
    return off + 16 + 16 * nindex + hsize


def main():
    rpm, dest = sys.argv[1], sys.argv[2]
    data = open(rpm, "rb").read()
    if data[:4] != b"\xed\xab\xee\xdb":
        raise SystemExit("not an rpm")
    off = header_end(data, 96)       # signature header, padded to 8 bytes
    off = (off + 7) & ~7
    off = header_end(data, off)      # main header
    payload = data[off:]
    if payload[:6] == b"\xfd7zXZ\x00":
        decomp = ["xz", "-d", "-c"]
    elif payload[:4] == b"\x28\xb5\x2f\xfd":
        decomp = ["zstd", "-q", "-d", "-c"]
    elif payload[:2] == b"\x1f\x8b":
        decomp = ["gzip", "-d", "-c"]
    else:
        raise SystemExit(f"unknown payload compression {payload[:6]!r}")
    raw = subprocess.run(decomp, input=payload, stdout=subprocess.PIPE, check=True).stdout
    subprocess.run(["cpio", "-idm", "--quiet", "--no-absolute-filenames", "-D", dest],
                   input=raw, check=True)


if __name__ == "__main__":
    main()
