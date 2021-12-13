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

// #include <linux/types.h>
// #include "./bpf/execsnoop.h"
import "C"
import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/execsnoop/types"
)

//go:generate sh -c "GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang execsnoop ./bpf/execsnoop.bpf.c -- -I./bpf/ -I../../.. -target bpf -D__TARGET_ARCH_x86"

type Config struct {
	// TODO: Make it a *ebpf.Map once
	// https://github.com/cilium/ebpf/issues/515 and
	// https://github.com/cilium/ebpf/issues/517 are fixed
	MountnsMap string
}

type Tracer struct {
	c             *Config
	objs          execsnoopObjects
	enterLink     link.Link
	exitLink      link.Link
	resolver      containercollection.ContainerResolver
	eventCallback func(types.Event)
	errorCallback func(error)
	done          chan bool
}

func NewTracer(c *Config, resolver containercollection.ContainerResolver,
	eventCallback func(types.Event), errorCallback func(error)) (*Tracer, error) {
	t := &Tracer{c: c}

	t.resolver = resolver
	t.eventCallback = eventCallback
	t.errorCallback = errorCallback
	t.done = make(chan bool)

	if err := t.start(); err != nil {
		t.Stop()
		return nil, err
	}

	return t, nil
}

func (t *Tracer) Stop() {
	t.stop()
}

func (t *Tracer) stop() {
	close(t.done)

	t.enterLink.Close()
	t.exitLink.Close()
	t.objs.Close()
}

func (t *Tracer) start() error {
	spec, err := loadExecsnoop()
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
		//TODO: other options
		"filter_by_mnt_ns": filter_by_mnt_ns,
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

	enter, err := link.Tracepoint("syscalls", "sys_enter_execve", t.objs.TracepointSyscallsSysEnterExecve)
	if err != nil {
		return fmt.Errorf("Error opening tracepoint: %w", err)
	}
	t.enterLink = enter

	exit, err := link.Tracepoint("syscalls", "sys_exit_execve", t.objs.TracepointSyscallsSysExitExecve)
	if err != nil {
		return fmt.Errorf("Error opening tracepoint: %w", err)
	}
	t.exitLink = exit

	go t.run()

	return nil
}

func (t *Tracer) run() {
	// TODO: what's the right value for 4096?
	pb, err := perf.NewReader(t.objs.execsnoopMaps.Events, 4096)
	if err != nil {
		t.errorCallback(fmt.Errorf("Error creating perf ring buffer: %w", err))
		return
	}
	defer pb.Close()

	for {
		record, err := pb.Read()
		if err != nil {
			t.errorCallback(fmt.Errorf("Error reading perf ring buffer: %w", err))
			return
		}

		eventC := (*C.struct_event)(unsafe.Pointer(&record.RawSample[0]))

		event := types.Event{
			Pid:       uint32(eventC.pid),
			Ppid:      uint32(eventC.ppid),
			Uid:       uint32(eventC.uid),
			MountNsId: uint64(eventC.mntns_id),
			Retval:    int(eventC.retval),
			Comm:      C.GoString(&eventC.comm[0]),
		}

		args_count := 0
		buf := []byte{}

		for i := 0; i < int(eventC.args_size) && args_count < int(eventC.args_count); i++ {
			c := eventC.args[i]
			if c == 0 {
				event.Args = append(event.Args, string(buf))
				args_count = 0
				buf = []byte{}
			} else {
				buf = append(buf, byte(c))
			}
		}

		container := t.resolver.LookupContainerByMntns(event.MountNsId)
		if container != nil {
			event.Container = container.Name
			event.Pod = container.Podname
			event.Namespace = container.Namespace
			event.Node = os.Getenv("NODE_NAME")
		}

		t.eventCallback(event)
	}
}
