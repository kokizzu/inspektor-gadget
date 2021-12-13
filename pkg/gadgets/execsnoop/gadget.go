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

package execsnoop

import (
	"encoding/json"
	"fmt"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"

	execsnooptracer "github.com/kinvolk/inspektor-gadget/pkg/gadgets/execsnoop/tracer"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/execsnoop/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
)

type Trace struct {
	resolver gadgets.Resolver

	started bool
	tracer  *execsnooptracer.Tracer
}

type TraceFactory struct {
	gadgets.BaseFactory
}

func NewFactory() gadgets.TraceFactory {
	return &TraceFactory{
		BaseFactory: gadgets.BaseFactory{DeleteTrace: deleteTrace},
	}
}

func (f *TraceFactory) Description() string {
	return `execsnoop shows reads and writes by file, with container details.`
}

func (f *TraceFactory) OutputModesSupported() map[string]struct{} {
	return map[string]struct{}{
		"Stream": {},
	}
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	trace.tracer.Stop()
}

func (f *TraceFactory) Operations() map[string]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{
			resolver: f.Resolver,
		}
	}

	return map[string]gadgets.TraceOperation{
		"start": {
			Doc: "Start execsnoop gadget",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		"stop": {
			Doc: "Stop execsnoop gadget",
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

	traceName := gadgets.TraceName(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)

	// TODO: get these parameters from the trace once
	// https://github.com/kinvolk/inspektor-gadget/issues/420 is solved.
	config := &execsnooptracer.Config{
		//OutputRows: 100,
		//Interval:   time.Second,
		//SortBy:     types.ALL,
		MountnsMap: gadgets.TracePinPath(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name),
	}

	eventCallback := func(event types.Event) {
		r, err := json.Marshal(event)
		if err != nil {
			return
		}
		t.resolver.PublishEvent(traceName, string(r))
	}

	errorCallback := func(err error) {
		ev := &types.Event{
			Event: eventtypes.Event{
				Type:    eventtypes.ERR,
				Message: fmt.Sprintf("Gadget failed with: %v", err),
			},
		}
		r, err := json.Marshal(ev)
		if err != nil {
			return
		}
		t.resolver.PublishEvent(traceName, string(r))
	}

	tracer, err := execsnooptracer.NewTracer(config, t.resolver, eventCallback, errorCallback)
	if err != nil {
		return
	}

	t.tracer = tracer
	t.started = true

	trace.Status.OperationError = ""
	trace.Status.Output = ""
	trace.Status.State = "Started"
}

func (t *Trace) Stop(trace *gadgetv1alpha1.Trace) {
	if !t.started {
		trace.Status.OperationError = "Not started"
		return
	}

	t.tracer.Stop()
	t.tracer = nil
	t.started = false

	trace.Status.OperationError = ""
	trace.Status.State = "Stopped"
}
