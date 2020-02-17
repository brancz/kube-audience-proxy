/*
Copyright 2020 Frederic Branczyk All rights reserved.

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

package main

import (
	"crypto/tls"
	"sort"
	"strings"
	"sync"
)

type certCache struct {
	cache map[string]*tls.Certificate
	mtx   *sync.RWMutex
}

func newCertCache() *certCache {
	return &certCache{
		cache: map[string]*tls.Certificate{},
		mtx:   &sync.RWMutex{},
	}
}

func (c *certCache) Get(names ...string) (cert *tls.Certificate, exists bool) {
	sort.Strings(names)
	k := strings.Join(names, ",")

	c.mtx.RLock()
	defer c.mtx.RUnlock()
	cert, exists = c.cache[k]
	return
}

func (c *certCache) Set(cert *tls.Certificate, names ...string) {
	sort.Strings(names)
	k := strings.Join(names, ",")

	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.cache[k] = cert
}
