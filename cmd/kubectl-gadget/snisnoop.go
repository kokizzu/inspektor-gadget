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

package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	snitypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/snisnoop/types"
)

const (
	FMT_SNISNOOP_ALL   = "%-16.16s %-16.16s %-30.30s %s"
	FMT_SNISNOOP_SHORT = "%-30.30s %s"
)

var colSnisnoopLens = map[string]int{
	"name": 30,
}

var snisnoopCmd = &cobra.Command{
	Use:   "snisnoop",
	Short: "Trace SNI requests",
	Run: func(cmd *cobra.Command, args []string) {
		transform := snisnoopTransformLine

		switch {
		case params.OutputMode == utils.OutputModeJson: // don't print any header
		case params.OutputMode == utils.OutputModeCustomColumns:
			table := utils.NewTableFormater(params.CustomColumns, colSnisnoopLens)
			fmt.Println(table.GetHeader())
			transform = table.GetTransformFunc()
		case params.AllNamespaces:
			fmt.Printf(FMT_SNISNOOP_ALL+"\n",
				"NODE",
				"NAMESPACE",
				"POD",
				"NAME",
			)
		default:
			fmt.Printf(FMT_SNISNOOP_SHORT+"\n",
				"POD",
				"NAME",
			)
		}

		utils.GenericTraceCommand("snisnoop", &params, args, "Stream", nil, transform)
	},
}

func init() {
	rootCmd.AddCommand(snisnoopCmd)
	utils.AddCommonFlags(snisnoopCmd, &params)
}

func snisnoopTransformLine(line string) string {
	event := &snitypes.Event{}
	json.Unmarshal([]byte(line), event)

	podMsgSuffix := ""
	if event.Namespace != "" && event.Pod != "" {
		podMsgSuffix = ", pod " + event.Namespace + "/" + event.Pod
	}

	if event.Err != "" {
		return fmt.Sprintf("Error on node %s%s: %s: %s", event.Node, podMsgSuffix, event.Notice, event.Err)
	}
	if event.Notice != "" {
		if !params.Verbose {
			return ""
		}
		return fmt.Sprintf("Notice on node %s%s: %s", event.Node, podMsgSuffix, event.Notice)
	}
	if params.AllNamespaces {
		return fmt.Sprintf(FMT_SNISNOOP_ALL, event.Node, event.Namespace, event.Pod, event.Name)
	} else {
		return fmt.Sprintf(FMT_SNISNOOP_SHORT, event.Pod, event.Name)
	}
}
