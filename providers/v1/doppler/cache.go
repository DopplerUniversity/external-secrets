/*
Copyright © 2025 ESO Maintainer Team

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package doppler

import (
	"strings"
	"sync"

	dclient "github.com/external-secrets/external-secrets/providers/v1/doppler/client"
	"github.com/external-secrets/external-secrets/runtime/cache"
)

type cacheEntry struct {
	etag    string
	secrets dclient.Secrets
	body    []byte
}

// Constant version because entries are invalidated explicitly on mutations.
const etagCacheVersion = ""

type secretsCache struct {
	cache  *cache.Cache[*cacheEntry]
	keys   map[string][]cache.Key // tracks keys per project/config for bulk invalidation
	keysMu sync.RWMutex
}

func newSecretsCache(size int) *secretsCache {
	if size <= 0 {
		return nil
	}
	return &secretsCache{
		cache: cache.Must(size, func(_ *cacheEntry) {}),
		keys:  make(map[string][]cache.Key),
	}
}

type storeIdentity struct {
	namespace string
	name      string
	kind      string
}

func cacheKey(store storeIdentity, project, config, format, nameTransformer string, secrets []string) cache.Key {
	secretsKey := ""
	if len(secrets) > 0 {
		secretsKey = strings.Join(secrets, ",")
	}
	return cache.Key{
		Name:      store.name + "|" + project + "|" + config + "|" + format + "|" + nameTransformer + "|" + secretsKey,
		Namespace: store.namespace,
		Kind:      store.kind,
	}
}

func prefixKey(store storeIdentity, project, config string) string {
	return store.namespace + "|" + store.name + "|" + store.kind + "|" + project + "|" + config
}

func (c *secretsCache) get(store storeIdentity, project, config, format, nameTransformer string, secrets []string) (*cacheEntry, bool) {
	if c == nil || c.cache == nil {
		return nil, false
	}
	key := cacheKey(store, project, config, format, nameTransformer, secrets)
	return c.cache.Get(etagCacheVersion, key)
}

func (c *secretsCache) set(store storeIdentity, project, config, format, nameTransformer string, secrets []string, entry *cacheEntry) {
	if c == nil || c.cache == nil {
		return
	}
	key := cacheKey(store, project, config, format, nameTransformer, secrets)
	c.cache.Add(etagCacheVersion, key, entry)

	c.keysMu.Lock()
	prefix := prefixKey(store, project, config)
	c.keys[prefix] = append(c.keys[prefix], key)
	c.keysMu.Unlock()
}

func (c *secretsCache) invalidate(store storeIdentity, project, config string) {
	if c == nil || c.cache == nil {
		return
	}

	c.keysMu.Lock()
	defer c.keysMu.Unlock()

	prefix := prefixKey(store, project, config)
	keys, exists := c.keys[prefix]
	if !exists {
		return
	}

	for _, key := range keys {
		if c.cache.Contains(key) {
			c.cache.Get("__invalidate__", key) // wrong version triggers eviction
		}
	}

	delete(c.keys, prefix)
}

var etagCache *secretsCache
