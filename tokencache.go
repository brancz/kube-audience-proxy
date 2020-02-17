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

import "sync"

type tokenCache struct {
	cache map[string]string
	mtx   *sync.RWMutex
}

func newTokenCache() *tokenCache {
	return &tokenCache{
		cache: map[string]string{},
		mtx:   &sync.RWMutex{},
	}
}

func (c *tokenCache) Get(audience string) (token string, exists bool) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	token, exists = c.cache[audience]
	return
}

func (c *tokenCache) Set(audience, token string) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.cache[audience] = token
}
