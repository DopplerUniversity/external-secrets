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
	"sync"

	dclient "github.com/external-secrets/external-secrets/providers/v1/doppler/client"
)

type secretsCache struct {
	cache sync.Map
}

type cacheEntry struct {
	etag    string
	secrets dclient.Secrets
	body    []byte
}

func cacheKey(project, config, format, nameTransformer string) string {
	return project + "|" + config + "|" + format + "|" + nameTransformer
}

func (c *secretsCache) get(project, config, format, nameTransformer string) (*cacheEntry, bool) {
	key := cacheKey(project, config, format, nameTransformer)
	if val, ok := c.cache.Load(key); ok {
		return val.(*cacheEntry), true
	}
	return nil, false
}

func (c *secretsCache) set(project, config, format, nameTransformer string, entry *cacheEntry) {
	key := cacheKey(project, config, format, nameTransformer)
	c.cache.Store(key, entry)
}

func (c *secretsCache) invalidate(project, config string) {
	prefix := project + "|" + config + "|"
	c.cache.Range(func(key, _ any) bool {
		if k, ok := key.(string); ok && len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			c.cache.Delete(key)
		}
		return true
	})
}

// global cache persists across client recreations during reconciliation loops.
var globalSecretsCache = &secretsCache{}
