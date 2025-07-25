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

package k8sutil

import (
	"errors"
	"fmt"
	"path/filepath"

	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"github.com/inspektor-gadget/inspektor-gadget/internal/version"
)

func NewKubeConfig(kubeconfigPath, userAgentComment string) (*rest.Config, error) {
	var config *rest.Config
	var err error
	if kubeconfigPath != "" {
		// kubeconfig is set explicitly (-kubeconfig flag or $KUBECONFIG variable)
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			return nil, err
		}
	} else {
		// kubeconfig from a pod Service Account token
		config, err = rest.InClusterConfig()
		if errors.Is(err, rest.ErrNotInCluster) {
			// kubeconfig from $HOME/.kube/config
			if home := homedir.HomeDir(); home != "" {
				config, err = clientcmd.BuildConfigFromFlags("", filepath.Join(home, ".kube", "config"))
				if err != nil {
					return nil, err
				}
			}
		} else if err != nil {
			return nil, fmt.Errorf("creating in-cluster config: %w", err)
		}
	}
	if config == nil {
		return nil, errors.New("no kubeconfig found, please set the KUBECONFIG environment variable or use the --kubeconfig flag")
	}
	config.UserAgent = version.UserAgent()
	if userAgentComment != "" {
		config.UserAgent += " (" + userAgentComment + ")"
	}

	return config, err
}

func NewClientset(kubeconfigPath, userAgentComment string) (*kubernetes.Clientset, error) {
	config, err := NewKubeConfig(kubeconfigPath, userAgentComment)
	if err != nil {
		return nil, err
	}

	apiclientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return apiclientset, nil
}

// NewClientsetWithProtobuf creates a client to talk to the Kubernetes API
// server using protobuf encoding.
func NewClientsetWithProtobuf(kubeconfigPath, userAgentComment string) (*kubernetes.Clientset, error) {
	config, err := NewKubeConfig(kubeconfigPath, userAgentComment)
	if err != nil {
		return nil, err
	}

	// Use protobuf instead of json as it's more efficient. This support was
	// introduced in Kubernetes 1.3, released in July 2016, we can assume it's
	// available.
	config.ContentType = "application/vnd.kubernetes.protobuf"
	config.AcceptContentTypes = "application/vnd.kubernetes.protobuf"

	apiclientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return apiclientset, nil
}

func NewClientsetFromConfigFlags(flags *genericclioptions.ConfigFlags) (*kubernetes.Clientset, error) {
	config, err := flags.ToRESTConfig()
	if err != nil {
		return nil, err
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return client, nil
}
