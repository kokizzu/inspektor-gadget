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

package containercollection

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetExpectedOwnerReference(t *testing.T) {
	cTrue := true
	cFalse := false
	table := []struct {
		description       string
		ownerReferences   []metav1.OwnerReference
		expectedResult    *metav1.OwnerReference
		nilExpectedResult bool
	}{
		{
			description:       "From empty list",
			ownerReferences:   []metav1.OwnerReference{},
			expectedResult:    nil,
			nilExpectedResult: true,
		},
		{
			description: "One element without expected kind",
			ownerReferences: []metav1.OwnerReference{
				{
					UID:  "abcde",
					Kind: "non-expected-kind",
				},
			},
			expectedResult:    nil,
			nilExpectedResult: true,
		},
		{
			description: "One element with expected kind",
			ownerReferences: []metav1.OwnerReference{
				{
					UID:  "abcde",
					Kind: "ReplicationController",
				},
			},
			expectedResult: &metav1.OwnerReference{
				UID: "abcde",
			},
			nilExpectedResult: false,
		},
		{
			description: "Neither controller reference nor expected kind",
			ownerReferences: []metav1.OwnerReference{
				{
					UID:        "abcde1",
					Kind:       "non-expected-kind",
					Controller: &cFalse,
				},
				{
					UID:        "abcde2",
					Kind:       "non-expected-kind",
					Controller: &cFalse,
				},
				{
					UID:        "abcde3",
					Kind:       "non-expected-kind",
					Controller: &cFalse,
				},
			},
			expectedResult:    nil,
			nilExpectedResult: true,
		},
		{
			description: "Controller reference but without expected kind",
			ownerReferences: []metav1.OwnerReference{
				{
					UID:        "abcde1",
					Kind:       "non-expected-kind",
					Controller: &cTrue,
				},
				{
					UID:        "abcde2",
					Kind:       "non-expected-kind",
					Controller: &cFalse,
				},
				{
					UID:        "abcde3",
					Kind:       "non-expected-kind",
					Controller: &cFalse,
				},
			},
			expectedResult:    nil,
			nilExpectedResult: true,
		},
		{
			description: "Selecting controller reference",
			ownerReferences: []metav1.OwnerReference{
				{
					UID:        "abcde1",
					Kind:       "non-expected-kind",
					Controller: &cFalse,
				},
				{
					UID:        "abcde2",
					Kind:       "Job",
					Controller: &cTrue,
				},
				{
					UID:        "abcde3",
					Kind:       "non-expected-kind",
					Controller: &cFalse,
				},
			},
			expectedResult: &metav1.OwnerReference{
				UID: "abcde2",
			},
			nilExpectedResult: false,
		},
		{
			description: "Selecting first expected kind reference (First element)",
			ownerReferences: []metav1.OwnerReference{
				{
					UID:        "abcde1",
					Kind:       "DaemonSet",
					Controller: &cFalse,
				},
				{
					UID:        "abcde2",
					Kind:       "non-expected-kind",
					Controller: &cFalse,
				},
				{
					UID:        "abcde3",
					Kind:       "non-expected-kind",
					Controller: &cFalse,
				},
			},
			expectedResult: &metav1.OwnerReference{
				UID: "abcde1",
			},
			nilExpectedResult: false,
		},
		{
			description: "Selecting first expected kind reference (Intermediate element)",
			ownerReferences: []metav1.OwnerReference{
				{
					UID:        "abcde1",
					Kind:       "non-expected-kind",
					Controller: &cFalse,
				},
				{
					UID:        "abcde2",
					Kind:       "Deployment",
					Controller: &cFalse,
				},
				{
					UID:        "abcde3",
					Kind:       "non-expected-kind",
					Controller: &cFalse,
				},
			},
			expectedResult: &metav1.OwnerReference{
				UID: "abcde2",
			},
			nilExpectedResult: false,
		},
		{
			description: "Selecting first expected kind reference (Last element)",
			ownerReferences: []metav1.OwnerReference{
				{
					UID:        "abcde1",
					Kind:       "non-expected-kind",
					Controller: &cFalse,
				},
				{
					UID:        "abcde2",
					Kind:       "non-expected-kind",
					Controller: &cFalse,
				},
				{
					UID:        "abcde3",
					Kind:       "StatefulSet",
					Controller: &cFalse,
				},
			},
			expectedResult: &metav1.OwnerReference{
				UID: "abcde3",
			},
			nilExpectedResult: false,
		},
	}

	for i, entry := range table {
		result := getExpectedOwnerReference(entry.ownerReferences)
		if entry.nilExpectedResult {
			if result != nil {
				t.Fatalf("Failed test %q (index %d): result %+v expected %+v",
					entry.description, i, result, entry.expectedResult)
			}
		} else if entry.expectedResult.UID != result.UID {
			t.Fatalf("Failed test %q (index %d): result %+v expected %+v",
				entry.description, i, result, entry.expectedResult)
		}
	}
}
