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

package processcollector

import (
	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/api/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/process-collector/tracer"
)

type Trace struct {
	resolver gadgets.Resolver
}

type TraceFactory struct {
	gadgets.BaseFactory
}

func NewFactory() gadgets.TraceFactory {
	return &TraceFactory{}
}

func (f *TraceFactory) Description() string {
	return `The process-collector gadget gathers information about running processes`
}

func (f *TraceFactory) OutputModesSupported() map[string]struct{} {
	return map[string]struct{}{
		"Status": {},
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
			Doc: "Create a snapshot of the currently running processes. " +
				"Once taken, the snapshot is not updated automatically. " +
				"However one can call the start operation again at any time to update the snapshot.",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
	}
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	selector := gadgets.ContainerSelectorFromContainerFilter(trace.Spec.Filter)
	if len(t.resolver.GetContainersBySelector(selector)) == 0 {
		gadgets.CleanupTraceStatus(trace)
		trace.Status.OperationWarning = "No container matches the requested filter"
		return
	}

	output, err := tracer.RunCollector(
		gadgets.TracePinPath(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name),
	)
	if err != nil {
		gadgets.CleanupTraceStatus(trace)
		trace.Status.OperationError = err.Error()
		return
	}
	trace.Status.OperationError = ""
	trace.Status.Output = output
	trace.Status.State = "Completed"
}
