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
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"

	esv1alpha1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
	"github.com/external-secrets/external-secrets/providers/v1/doppler/client"
	"github.com/external-secrets/external-secrets/providers/v1/doppler/fake"
)

const testETagValue = "etag-123"

func TestCacheKey(t *testing.T) {
	tests := []struct {
		project         string
		config          string
		format          string
		nameTransformer string
		expected        string
	}{
		{"my-project", "dev", "", "", "my-project|dev||"},
		{"my-project", "dev", "json", "", "my-project|dev|json|"},
		{"my-project", "dev", "", "lower-snake", "my-project|dev||lower-snake"},
		{"my-project", "dev", "env", "camel", "my-project|dev|env|camel"},
		{"", "dev", "", "", "|dev||"},
		{"my-project", "", "", "", "my-project|||"},
		{"", "", "", "", "|||"},
	}

	for _, tt := range tests {
		result := cacheKey(tt.project, tt.config, tt.format, tt.nameTransformer)
		if result != tt.expected {
			t.Errorf("cacheKey(%q, %q, %q, %q) = %q, want %q", tt.project, tt.config, tt.format, tt.nameTransformer, result, tt.expected)
		}
	}
}

func TestSecretsCacheGetSet(t *testing.T) {
	cache := &secretsCache{}

	entry, found := cache.get("project", "config", "", "")
	if found || entry != nil {
		t.Error("expected empty cache to return nil, false")
	}

	testEntry := &cacheEntry{
		etag:    "test-etag",
		secrets: client.Secrets{"KEY": "value"},
		body:    []byte("test body"),
	}
	cache.set("project", "config", "", "", testEntry)

	entry, found = cache.get("project", "config", "", "")
	if !found {
		t.Error("expected cache hit after set")
	}
	if entry.etag != testEntry.etag {
		t.Errorf("expected etag %q, got %q", testEntry.etag, entry.etag)
	}
	if !cmp.Equal(entry.secrets, testEntry.secrets) {
		t.Errorf("expected secrets %v, got %v", testEntry.secrets, entry.secrets)
	}

	entry, found = cache.get("other-project", "config", "", "")
	if found || entry != nil {
		t.Error("expected cache miss for different key")
	}

	entry, found = cache.get("project", "config", "env", "")
	if found || entry != nil {
		t.Error("expected cache miss for different format")
	}

	entry, found = cache.get("project", "config", "", "lower-snake")
	if found || entry != nil {
		t.Error("expected cache miss for different nameTransformer")
	}
}

func TestSecretsCacheInvalidate(t *testing.T) {
	cache := &secretsCache{}

	testEntry := &cacheEntry{
		etag:    "test-etag",
		secrets: client.Secrets{"KEY": "value"},
	}
	cache.set("project", "config", "", "", testEntry)
	cache.set("project", "config", "env", "", testEntry)
	cache.set("project", "config", "", "lower-snake", testEntry)
	cache.set("other-project", "config", "", "", testEntry)

	_, found := cache.get("project", "config", "", "")
	if !found {
		t.Error("expected cache hit before invalidate")
	}
	_, found = cache.get("project", "config", "env", "")
	if !found {
		t.Error("expected cache hit for env format before invalidate")
	}

	cache.invalidate("project", "config")

	_, found = cache.get("project", "config", "", "")
	if found {
		t.Error("expected cache miss after invalidate")
	}
	_, found = cache.get("project", "config", "env", "")
	if found {
		t.Error("expected cache miss for env format after invalidate")
	}
	_, found = cache.get("project", "config", "", "lower-snake")
	if found {
		t.Error("expected cache miss for lower-snake after invalidate")
	}

	_, found = cache.get("other-project", "config", "", "")
	if !found {
		t.Error("expected other-project cache to remain after invalidate")
	}
}

func TestSecretsCacheConcurrency(t *testing.T) {
	cache := &secretsCache{}
	const numGoroutines = 100
	const numIterations = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				entry := &cacheEntry{
					etag:    "etag",
					secrets: client.Secrets{"KEY": "value"},
				}
				cache.set("project", "config", "", "", entry)
				cache.get("project", "config", "", "")
				if j%10 == 0 {
					cache.invalidate("project", "config")
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestGetAllSecretsUsesCache(t *testing.T) {
	globalSecretsCache = &secretsCache{}

	fakeClient := &fake.DopplerClient{}

	var callCount atomic.Int32
	testSecrets := client.Secrets{"API_KEY": "secret-value", "DB_PASS": "password"}
	testETag := testETagValue

	fakeClient.WithSecretsFunc(func(request client.SecretsRequest) (*client.SecretsResponse, error) {
		count := callCount.Add(1)

		if request.ETag == "" {
			return &client.SecretsResponse{
				Modified: true,
				Secrets:  testSecrets,
				ETag:     testETag,
			}, nil
		}

		if request.ETag == testETag {
			return &client.SecretsResponse{
				Modified: false,
				Secrets:  nil,
				ETag:     testETag,
			}, nil
		}

		t.Errorf("unexpected call %d with ETag %q", count, request.ETag)
		return nil, nil
	})

	c := &Client{
		doppler: fakeClient,
		project: "test-project",
		config:  "test-config",
	}

	secrets, err := c.secrets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secrets) != 2 {
		t.Errorf("expected 2 secrets, got %d", len(secrets))
	}
	if string(secrets["API_KEY"]) != "secret-value" {
		t.Errorf("expected API_KEY=secret-value, got %s", secrets["API_KEY"])
	}

	secrets, err = c.secrets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if len(secrets) != 2 {
		t.Errorf("expected 2 secrets on second call, got %d", len(secrets))
	}

	if callCount.Load() != 2 {
		t.Errorf("expected 2 API calls, got %d", callCount.Load())
	}
}

func TestCacheInvalidationOnPushSecret(t *testing.T) {
	globalSecretsCache = &secretsCache{}

	fakeClient := &fake.DopplerClient{}

	var secretsCallCount atomic.Int32
	testSecrets := client.Secrets{"API_KEY": "original-value"}
	updatedSecrets := client.Secrets{"API_KEY": "updated-value"}
	testETag := testETagValue
	newETag := "etag-456"

	fakeClient.WithSecretsFunc(func(request client.SecretsRequest) (*client.SecretsResponse, error) {
		count := secretsCallCount.Add(1)

		switch count {
		case 1:
			return &client.SecretsResponse{
				Modified: true,
				Secrets:  testSecrets,
				ETag:     testETag,
			}, nil
		case 2:
			if request.ETag != "" {
				t.Errorf("expected no ETag after cache invalidation, got %q", request.ETag)
			}
			return &client.SecretsResponse{
				Modified: true,
				Secrets:  updatedSecrets,
				ETag:     newETag,
			}, nil
		default:
			t.Errorf("unexpected call %d", count)
			return nil, nil
		}
	})

	fakeClient.WithUpdateValue(client.UpdateSecretsRequest{
		Secrets: client.Secrets{validRemoteKey: validSecretValue},
		Project: "test-project",
		Config:  "test-config",
	}, nil)

	c := &Client{
		doppler: fakeClient,
		project: "test-project",
		config:  "test-config",
	}

	_, err := c.secrets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entry, found := globalSecretsCache.get("test-project", "test-config", "", "")
	if !found {
		t.Error("expected cache to be populated after first call")
	}
	if entry.etag != testETag {
		t.Errorf("expected ETag %q, got %q", testETag, entry.etag)
	}

	secret := &corev1.Secret{
		Data: map[string][]byte{
			validSecretName: []byte(validSecretValue),
		},
	}
	secretData := esv1alpha1.PushSecretData{
		Match: esv1alpha1.PushSecretMatch{
			SecretKey: validSecretName,
			RemoteRef: esv1alpha1.PushSecretRemoteRef{
				RemoteKey: validRemoteKey,
			},
		},
	}
	err = c.PushSecret(context.Background(), secret, secretData)
	if err != nil {
		t.Fatalf("unexpected error pushing secret: %v", err)
	}

	_, found = globalSecretsCache.get("test-project", "test-config", "", "")
	if found {
		t.Error("expected cache to be invalidated after push")
	}

	_, err = c.secrets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error after push: %v", err)
	}

	if secretsCallCount.Load() != 2 {
		t.Errorf("expected 2 secrets API calls, got %d", secretsCallCount.Load())
	}
}

func TestCacheInvalidationOnDeleteSecret(t *testing.T) {
	globalSecretsCache = &secretsCache{}

	fakeClient := &fake.DopplerClient{}

	testSecrets := client.Secrets{"API_KEY": "value"}
	testETag := testETagValue

	fakeClient.WithSecretsFunc(func(_ client.SecretsRequest) (*client.SecretsResponse, error) {
		return &client.SecretsResponse{
			Modified: true,
			Secrets:  testSecrets,
			ETag:     testETag,
		}, nil
	})

	fakeClient.WithUpdateValue(client.UpdateSecretsRequest{
		ChangeRequests: []client.Change{
			{
				Name:         validRemoteKey,
				OriginalName: validRemoteKey,
				ShouldDelete: true,
			},
		},
		Project: "test-project",
		Config:  "test-config",
	}, nil)

	c := &Client{
		doppler: fakeClient,
		project: "test-project",
		config:  "test-config",
	}

	_, err := c.secrets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, found := globalSecretsCache.get("test-project", "test-config", "", "")
	if !found {
		t.Error("expected cache to be populated")
	}

	remoteRef := &esv1alpha1.PushSecretRemoteRef{RemoteKey: validRemoteKey}
	err = c.DeleteSecret(context.Background(), remoteRef)
	if err != nil {
		t.Fatalf("unexpected error deleting secret: %v", err)
	}

	_, found = globalSecretsCache.get("test-project", "test-config", "", "")
	if found {
		t.Error("expected cache to be invalidated after delete")
	}
}

func TestCacheWithFormat(t *testing.T) {
	globalSecretsCache = &secretsCache{}

	fakeClient := &fake.DopplerClient{}

	var callCount atomic.Int32
	testBody := []byte("KEY=value\nDB_PASS=password")
	testETag := "etag-format-123"

	fakeClient.WithSecretsFunc(func(request client.SecretsRequest) (*client.SecretsResponse, error) {
		count := callCount.Add(1)

		if request.ETag == "" {
			return &client.SecretsResponse{
				Modified: true,
				Body:     testBody,
				ETag:     testETag,
			}, nil
		}

		if request.ETag == testETag {
			return &client.SecretsResponse{
				Modified: false,
				Body:     nil,
				ETag:     testETag,
			}, nil
		}

		t.Errorf("unexpected call %d with ETag %q", count, request.ETag)
		return nil, nil
	})

	c := &Client{
		doppler: fakeClient,
		project: "test-project",
		config:  "test-config",
		format:  "env",
	}

	secrets, err := c.secrets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(secrets["DOPPLER_SECRETS_FILE"], testBody) {
		t.Errorf("expected body %q, got %q", testBody, secrets["DOPPLER_SECRETS_FILE"])
	}

	secrets, err = c.secrets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if !bytes.Equal(secrets["DOPPLER_SECRETS_FILE"], testBody) {
		t.Errorf("expected cached body %q, got %q", testBody, secrets["DOPPLER_SECRETS_FILE"])
	}

	if callCount.Load() != 2 {
		t.Errorf("expected 2 API calls, got %d", callCount.Load())
	}
}
