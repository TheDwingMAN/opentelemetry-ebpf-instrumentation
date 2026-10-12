// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// go-disk-io writes a file and reads it back with O_DIRECT, over and over, so that every write
// and read reaches the block device instead of the page cache.
package main

import (
	"log"
	"os"
	"syscall"
	"time"
)

const (
	blockSize = 64 << 10
	blocks    = 64
	pause     = time.Second
)

func main() {
	path := os.Getenv("DATA_FILE")
	if path == "" {
		path = "/data/disk-io.dat"
	}
	// O_DIRECT needs a buffer aligned to the device's logical block size: a page is enough
	buf, err := syscall.Mmap(-1, 0, blockSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		log.Fatalf("allocating aligned buffer: %v", err)
	}
	for {
		if err := writeAndReadBack(path, buf); err != nil {
			log.Fatal(err)
		}
		time.Sleep(pause)
	}
}

func writeAndReadBack(path string, buf []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_DIRECT, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	for i := range blocks {
		if _, err := f.WriteAt(buf, int64(i*blockSize)); err != nil {
			return err
		}
	}
	for i := range blocks {
		if _, err := f.ReadAt(buf, int64(i*blockSize)); err != nil {
			return err
		}
	}
	return nil
}
