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

package auditseccomp

import (
	"encoding/json"
	"fmt"
	"sync"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/api/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	auditseccomptracer "github.com/kinvolk/inspektor-gadget/pkg/gadgets/audit-seccomp/tracer"
	types "github.com/kinvolk/inspektor-gadget/pkg/gadgets/audit-seccomp/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

type Trace struct {
	resolver gadgets.Resolver

	started bool
}

type TraceFactory struct {
	gadgets.BaseFactory
}

type TraceSingleton struct {
	mu     sync.Mutex
	tracer *auditseccomptracer.Tracer
	users  int
}

var traceSingleton TraceSingleton

func NewFactory() gadgets.TraceFactory {
	return &TraceFactory{
		BaseFactory: gadgets.BaseFactory{DeleteTrace: deleteTrace},
	}
}

func (f *TraceFactory) Description() string {
	return `TODO`
}

func (f *TraceFactory) OutputModesSupported() map[string]struct{} {
	return map[string]struct{}{
		"Stream": {},
	}
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.started {
		traceSingleton.mu.Lock()
		defer traceSingleton.mu.Unlock()
		traceSingleton.users--
		if traceSingleton.users == 0 {
			traceSingleton.tracer.Close()
			traceSingleton.tracer = nil
		}
	}
}

func (f *TraceFactory) Operations() map[string]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{
			resolver: f.Resolver,
		}
	}
	return map[string]gadgets.TraceOperation{
		"start": {
			Doc: "Start recording audit seccomp",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		"stop": {
			Doc: "Stop recording audit seccomp",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
		},
	}
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if t.started {
		trace.Status.OperationError = ""
		trace.Status.Output = ""
		trace.Status.State = "Started"
		return
	}

	printEvent := func(syscall int) string {
		event := &types.Event{
			Event: eventtypes.Event{
				Node:      trace.Spec.Node,
				Namespace: "TODO",
				Pod:       "TODO",
			},
			Syscall: fmt.Sprint(syscall),
		}

		b, e := json.Marshal(event)
		if e != nil {
			return `{"err": "cannot marshal event"}`
		}
		return string(b)
	}

	traceName := gadgets.TraceName(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)
	newEventCallback := func(syscall int) {
		t.resolver.PublishEvent(
			traceName,
			printEvent(syscall),
		)
	}

	traceSingleton.mu.Lock()
	defer traceSingleton.mu.Unlock()
	if traceSingleton.tracer == nil {
		var err error
		traceSingleton.tracer, err = auditseccomptracer.NewTracer(newEventCallback)
		if err != nil {
			trace.Status.OperationError = fmt.Sprintf("Failed to start audit seccomp tracer: %s", err)
			return
		}
	}
	traceSingleton.users++
	t.started = true

	trace.Status.OperationError = ""
	trace.Status.Output = ""
	trace.Status.State = "Started"
	return
}

func (t *Trace) Stop(trace *gadgetv1alpha1.Trace) {
	if !t.started {
		trace.Status.OperationError = "Not started"
		return
	}

	traceSingleton.mu.Lock()
	defer traceSingleton.mu.Unlock()
	traceSingleton.users--
	if traceSingleton.users == 0 {
		traceSingleton.tracer.Close()
		traceSingleton.tracer = nil
	}

	t.started = false

	trace.Status.OperationError = ""
	trace.Status.State = "Stopped"
	return
}
