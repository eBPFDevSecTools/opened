/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package kube2store

import (
	"k8s.io/client-go/tools/cache"
	proxystore "sigs.k8s.io/kpng/server/proxystore"
)

type eventHandler struct {
	k8sConfig *K8sConfig
	s         *proxystore.Store
	informer  cache.SharedIndexInformer
	syncSet   bool
}

func (h *eventHandler) updateSync(set proxystore.Set, tx *proxystore.Tx) {
	if h.syncSet {
		return
	}

	if h.informer.HasSynced() {
		tx.SetSync(set)
		h.syncSet = true
	}
}
