//go:build linux
// +build linux

// Copyright 2019-2021 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tracer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/filetop/types"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// #include <linux/types.h>
// #include "./bpf/filetop.h"
import "C"

//go:generate sh -c "GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang filetop ./bpf/filetop.bpf.c -- -I./bpf/ -I../../.. -target bpf -D__TARGET_ARCH_x86"

type Config struct {
	TargetPid  int
	AllFiles   bool
	OutputRows int
	Interval   time.Duration
	SortBy     types.SortBy
	// TODO: Make it a *ebpf.Map once
	// https://github.com/cilium/ebpf/issues/515 and
	// https://github.com/cilium/ebpf/issues/517 are fixed
	MountnsMap string
}

type Tracer struct {
	c             *Config
	objs          filetopObjects
	readLink      link.Link
	writeLink     link.Link
	resolver      containercollection.ContainerResolver
	statsCallback func([]types.Stats)
	errorCallback func(error)
	done          chan bool
}

func NewTracer(c *Config, resolver containercollection.ContainerResolver,
	statsCallback func([]types.Stats), errorCallback func(error)) (*Tracer, error) {
	t := &Tracer{
		c:             c,
		resolver:      resolver,
		statsCallback: statsCallback,
		errorCallback: errorCallback,
		done:          make(chan bool),
	}

	if err := t.start(); err != nil {
		t.Stop()
		return nil, err
	}

	return t, nil
}

func (t *Tracer) Stop() {
	close(t.done)

	t.readLink.Close()
	t.writeLink.Close()
	t.objs.Close()
}

func (t *Tracer) start() error {
	spec, err := loadFiletop()
	if err != nil {
		return fmt.Errorf("Failed to load ebpf program: %w", err)
	}

	filter_by_mnt_ns := false

	if t.c.MountnsMap != "" {
		filter_by_mnt_ns = true
		m := spec.Maps["mount_ns_set"]
		m.Pinning = ebpf.PinByName
		m.Name = filepath.Base(t.c.MountnsMap)
	}

	consts := map[string]interface{}{
		"target_pid":        uint32(t.c.TargetPid),
		"regular_file_only": !t.c.AllFiles,
		"filter_by_mnt_ns":  filter_by_mnt_ns,
	}

	if err := spec.RewriteConstants(consts); err != nil {
		return fmt.Errorf("error RewriteConstants: %w", err)
	}

	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: filepath.Dir(t.c.MountnsMap),
		},
	}

	if err := spec.LoadAndAssign(&t.objs, &opts); err != nil {
		return fmt.Errorf("Failed to load ebpf program: %w", err)
	}

	kpread, err := link.Kprobe("vfs_read", t.objs.VfsReadEntry)
	if err != nil {
		return fmt.Errorf("Error opening kprobe: %w", err)
	}
	t.readLink = kpread

	kpwrite, err := link.Kprobe("vfs_write", t.objs.VfsWriteEntry)
	if err != nil {
		return fmt.Errorf("Error opening kprobe: %w", err)
	}
	t.writeLink = kpwrite

	t.run()

	return nil
}

func (t *Tracer) next_stats() ([]types.Stats, error) {
	stats := []types.Stats{}

	var prev *C.struct_file_id = nil
	key := C.struct_file_id{}
	entries := t.objs.Entries

	// gather elements
	err := entries.NextKey(nil, unsafe.Pointer(&key))
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return stats, nil
		}
		return nil, fmt.Errorf("Error getting next key: %w", err)
	}

	for {
		file_stat := C.struct_file_stat{}
		if err := entries.Lookup(key, unsafe.Pointer(&file_stat)); err != nil {
			return nil, err
		}

		stat := types.Stats{
			Reads:      uint64(file_stat.reads),
			Writes:     uint64(file_stat.writes),
			ReadBytes:  uint64(file_stat.read_bytes),
			WriteBytes: uint64(file_stat.write_bytes),
			Pid:        uint32(file_stat.pid),
			Tid:        uint32(file_stat.tid),
			Filename:   C.GoString(&file_stat.filename[0]),
			Comm:       C.GoString(&file_stat.comm[0]),
			FileType:   byte(file_stat.type_),
			MountNsId:  uint64(file_stat.mntns_id),
		}

		container := t.resolver.LookupContainerByMntns(stat.MountNsId)
		if container != nil {
			stat.Container = container.Name
			stat.Pod = container.Podname
			stat.Namespace = container.Namespace
			stat.Node = os.Getenv("NODE_NAME")
		}

		stats = append(stats, stat)

		prev = &key
		if err := entries.NextKey(unsafe.Pointer(prev), unsafe.Pointer(&key)); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}
			return nil, fmt.Errorf("error getting next key: %w\n", err)
		}
	}

	types.SortStats(stats, t.c.SortBy)

	// delete elements
	err = entries.NextKey(nil, unsafe.Pointer(&key))
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("error getting next key: %w", err)
	}

	for {
		if err := entries.Delete(key); err != nil {
			return nil, fmt.Errorf("error deleting element: %w", err)
		}

		prev = &key
		if err := entries.NextKey(unsafe.Pointer(prev), unsafe.Pointer(&key)); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}
			return nil, fmt.Errorf("error getting next key: %w\n", err)
		}
	}

	return stats, nil
}

func (t *Tracer) run() {
	ticker := time.NewTicker(t.c.Interval)

	go func() {
		for {
			select {
			case <-t.done:
				break
			case <-ticker.C:
				stats, err := t.next_stats()
				if err != nil {
					t.errorCallback(err)
					return
				}

				n := len(stats)
				if n > t.c.OutputRows {
					n = t.c.OutputRows
				}
				t.statsCallback(stats[:n])
			}
		}
	}()
}
