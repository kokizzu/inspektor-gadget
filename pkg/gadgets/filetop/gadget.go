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

package filetop

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	filetoptracer "github.com/kinvolk/inspektor-gadget/pkg/gadgets/filetop/tracer"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/filetop/types"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
)

type Trace struct {
	resolver gadgets.Resolver

	started bool
	tracer  *filetoptracer.Tracer
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
	return `filetop shows reads and writes by file, with container details.`
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
			Doc: "Start filetop gadget",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		"stop": {
			Doc: "Stop filetop gadget",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
		},
	}
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if t.started {
		gadgets.CleanupTraceStatus(trace)
		trace.Status.State = "Started"
		return
	}

	traceName := gadgets.TraceName(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)

	outputRows := 20
	intervalSeconds := 1
	sortBy := types.RBYTES

	if trace.Spec.Parameters != nil {
		params := trace.Spec.Parameters
		var err error

		if val, ok := params["output_rows"]; ok {
			outputRows, err = strconv.Atoi(val)
			if err != nil {
				gadgets.CleanupTraceStatus(trace)
				trace.Status.OperationError = fmt.Sprintf("%q is not valid for ouput_rows", val)
				return
			}
		}

		if val, ok := params["interval"]; ok {
			intervalSeconds, err = strconv.Atoi(val)
			if err != nil {
				gadgets.CleanupTraceStatus(trace)
				trace.Status.OperationError = fmt.Sprintf("%q is not valid for interval", val)
				return
			}
		}

		if val, ok := params["sortby"]; ok {
			sortBy, err = types.ParseSortBy(val)
			if err != nil {
				gadgets.CleanupTraceStatus(trace)
				trace.Status.OperationError = fmt.Sprintf("%q is not valid for sortby", val)
				return
			}
		}
	}

	config := &filetoptracer.Config{
		OutputRows: outputRows,
		Interval:   time.Second * time.Duration(intervalSeconds),
		SortBy:     sortBy,
		MountnsMap: gadgets.TracePinPath(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name),
	}

	statsCallback := func(stats []types.Stats) {
		ev := types.Event{
			Node:  os.Getenv("NODE_NAME"),
			Stats: stats,
		}

		r, err := json.Marshal(ev)
		if err != nil {
			return
		}
		t.resolver.PublishEvent(traceName, string(r))
	}

	errorCallback := func(err error) {
		ev := types.Event{
			Error: fmt.Sprintf("Gadget failed with: %v", err),
			Node:  os.Getenv("NODE_NAME"),
		}
		r, err := json.Marshal(&ev)
		if err != nil {
			return
		}
		t.resolver.PublishEvent(traceName, string(r))
	}

	tracer, err := filetoptracer.NewTracer(config, t.resolver, statsCallback, errorCallback)
	if err != nil {
		return
	}

	t.tracer = tracer
	t.started = true

	gadgets.CleanupTraceStatus(trace)
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

	gadgets.CleanupTraceStatus(trace)
	trace.Status.State = "Stopped"
}
