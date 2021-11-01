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
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// #include "bpf/snisnoop.h"
import "C"

const (
	BPF_PROG_NAME = "bpf_prog1"
	BPF_MAP_NAME  = "events"
	SO_ATTACH_BPF = 50
)

type link struct {
	collection *ebpf.Collection
	perfRd     *perf.Reader

	sockFd int

	// users count how many users called Attach(). This can happen for two reasons:
	// 1. several containers in a pod (sharing the netns)
	// 2. pods with networkHost=true
	users int
}

type Tracer struct {
	mu sync.Mutex

	spec *ebpf.CollectionSpec

	// key: namespace/podname
	// value: Tracelet
	attachments map[string]*link
}

// Both openRawSock and htons are from github.com/cilium/ebpf:
// MIT License
// https://github.com/cilium/ebpf/blob/eaa1fe7482d837490c22d9d96a788f669b9e3843/example_sock_elf_test.go#L146-L166
func openRawSock(pid uint32) (int, error) {
	if pid != 0 {
		// Lock the OS Thread so we don't accidentally switch namespaces
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		// Save the current network namespace
		origns, _ := netns.Get()
		defer origns.Close()

		netnsHandle, err := netns.GetFromPid(int(pid))
		if err != nil {
			return -1, err
		}
		defer netnsHandle.Close()
		err = netns.Set(netnsHandle)
		if err != nil {
			return -1, err
		}

		// Switch back to the original namespace
		defer netns.Set(origns)
	}

	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return -1, err
	}
	sll := syscall.SockaddrLinklayer{
		Ifindex:  0, // 0 matches any interface
		Protocol: htons(syscall.ETH_P_ALL),
	}
	if err := syscall.Bind(sock, &sll); err != nil {
		return -1, err
	}
	return sock, nil
}

// htons converts an unsigned short integer from host byte order to network byte order.
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func NewTracer() (*Tracer, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ebpfProg))
	if err != nil {
		return nil, fmt.Errorf("failed to load asset: %w", err)
	}

	t := &Tracer{
		spec:        spec,
		attachments: make(map[string]*link),
	}

	return t, nil
}

func (t *Tracer) Attach(key string, pid uint32, f func(name string)) error {
	if l, ok := t.attachments[key]; ok {
		l.users++
		return nil
	}

	coll, err := ebpf.NewCollectionWithOptions(t.spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSize: ebpf.DefaultVerifierLogSize * 100}})
	if err != nil {
		return fmt.Errorf("failed to create BPF collection: %w", err)
	}

	rd, err := perf.NewReader(coll.Maps[BPF_MAP_NAME], os.Getpagesize())
	if err != nil {
		return fmt.Errorf("failed to get a perf reader: %w", err)
	}

	prog, ok := coll.Programs[BPF_PROG_NAME]
	if !ok {
		return fmt.Errorf("Failed to find BPF program %q", BPF_PROG_NAME)
	}

	sockFd, err := openRawSock(pid)
	if err != nil {
		return fmt.Errorf("Failed to open raw socket: %w", err)
	}

	if err := syscall.SetsockoptInt(sockFd, syscall.SOL_SOCKET, SO_ATTACH_BPF, prog.FD()); err != nil {
		return fmt.Errorf("Failed to attach BPF program: %w", err)
	}

	l := &link{
		collection: coll,
		sockFd:     sockFd,
		perfRd:     rd,
		users:      1,
	}
	t.attachments[key] = l

	go t.listen(key, rd, f)

	return nil
}

func parseSNIEvent(rawSample []byte) (ret string) {
	// Convert name into a string with dots
	name := make([]byte, C.TLS_MAX_SERVER_NAME_LEN)
	copy(name, rawSample)

	return strings.TrimSuffix(string(name), "\x00")
}

func (t *Tracer) listen(key string, rd *perf.Reader, f func(name string)) {
	for {
		record, err := rd.Read()
		if err != nil {
			if perf.IsClosed(err) {
				return
			}
			log.Errorf("Error while reading from perf event reader (%s): %s", key, err)
			return
		}

		if record.LostSamples != 0 {
			log.Warnf("Warning: perf event ring buffer full, dropped %d samples (%s)", record.LostSamples, key)
			continue
		}

		name := parseSNIEvent(record.RawSample)

		// TODO: Ideally, messages with name=="" should not be emitted
		// by the BPF program (see TODO in snisnoop.c).
		if len(name) > 0 {
			f(name)
		}
	}

}

func (t *Tracer) releaseLink(key string, l *link) {
	l.perfRd.Close()
	unix.Close(l.sockFd)
	l.collection.Close()
	delete(t.attachments, key)
}

func (t *Tracer) Detach(key string) error {
	if l, ok := t.attachments[key]; ok {
		l.users--
		if l.users == 0 {
			t.releaseLink(key, l)
		}
		return nil
	} else {
		return fmt.Errorf("key not attached: %q", key)
	}
}

func (t *Tracer) Close() {
	for key, l := range t.attachments {
		t.releaseLink(key, l)
	}
}
