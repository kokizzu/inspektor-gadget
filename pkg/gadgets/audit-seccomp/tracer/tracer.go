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
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	log "github.com/sirupsen/logrus"
)

// #include "bpf/audit-seccomp.h"
import "C"

const (
	BPF_PROG_NAME = "kprobe__audit_seccomp"
	BPF_MAP_NAME  = "events"
)

type Tracer struct {
	collection *ebpf.Collection
	eventMap   *ebpf.Map
	perfRd     *perf.Reader

	// progLink links the BPF program to the tracepoint.
	// A reference is kept so it can be closed it explicitly, otherwise
	// the garbage collector might unlink it via the finalizer at any
	// moment.
	progLink link.Link
}

func NewTracer(f func(syscall int)) (*Tracer, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ebpfProg))
	if err != nil {
		return nil, fmt.Errorf("failed to load asset: %s", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create BPF collection: %s", err)
	}

	rd, err := perf.NewReader(coll.Maps[BPF_MAP_NAME], os.Getpagesize())
	if err != nil {
		return nil, fmt.Errorf("failed to get a perf reader: %w", err)
	}

	t := &Tracer{
		collection: coll,
		eventMap:   coll.Maps[BPF_MAP_NAME],
		perfRd:     rd,
	}

	kprobeProg, ok := coll.Programs[BPF_PROG_NAME]
	if !ok {
		return nil, fmt.Errorf("failed to find BPF program %q", BPF_PROG_NAME)
	}

	t.progLink, err = link.Kprobe("audit_seccomp", kprobeProg)
	if err != nil {
		return nil, fmt.Errorf("failed to attach kprobe: %s", err)
	}

	go t.listen(rd, f)

	return t, nil
}

func parseEvent(rawSample []byte) (syscall int) {
	return 321
}

func (t *Tracer) listen(rd *perf.Reader, f func(syscall int)) {
	for {
		record, err := rd.Read()
		if err != nil {
			if perf.IsClosed(err) {
				return
			}
			log.Errorf("Error while reading from perf event reader: %s", err)
			return
		}

		if record.LostSamples != 0 {
			log.Warnf("Warning: perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		syscall := parseEvent(record.RawSample)
		f(syscall)
	}

}

func (t *Tracer) Close() {
	t.perfRd.Close()
	t.progLink.Close()
	t.collection.Close()
}
