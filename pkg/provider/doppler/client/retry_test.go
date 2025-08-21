/*
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

package client

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/external-secrets/external-secrets/pkg/provider/doppler/constants"
)

const (
	testRetryDelay = 1 * time.Second
)

// TestRetryProvider overrides SleepDuration() to exclude jitter and record
// expected sleep times while keeping the actual sleep time to a short 10ms duration.
type TestRetryProvider struct {
	defaultProvider *DefaultRetryProvider

	retryAmount          int
	retryDuration        time.Duration
	retryDurationHistory []int
}

func (rp *TestRetryProvider) defaultRetryProvider() *DefaultRetryProvider {
	if rp.defaultProvider == nil {
		rp.defaultProvider = &DefaultRetryProvider{
			retryAmount:   rp.retryAmount,
			retryDuration: rp.retryDuration,
		}
	}
	return rp.defaultProvider
}

func (rp *TestRetryProvider) MinRetryDelay() time.Duration {
	return rp.defaultRetryProvider().MinRetryDelay()
}

func (rp *TestRetryProvider) MaxRetryDelay() time.Duration {
	return rp.defaultRetryProvider().MaxRetryDelay()
}

func (rp *TestRetryProvider) MaxBackoffMultiplier() time.Duration {
	return rp.defaultRetryProvider().MaxBackoffMultiplier()
}

func (rp *TestRetryProvider) JitterDuration(delay time.Duration) time.Duration {
	return rp.defaultRetryProvider().JitterDuration(delay)
}

func (rp *TestRetryProvider) RetryAmount() int {
	return rp.retryAmount
}

func (rp *TestRetryProvider) RetryDuration() time.Duration {
	return rp.retryDuration
}

func (rp *TestRetryProvider) RetryDurationHistory() []int {
	return rp.retryDurationHistory
}

func (rp *TestRetryProvider) BackoffDuration(attempt int) time.Duration {
	return rp.defaultRetryProvider().BackoffDuration(attempt)
}

func (rp *TestRetryProvider) RatelimitDuration(retryAfterHeader string) time.Duration {
	return rp.defaultRetryProvider().RatelimitDuration(retryAfterHeader)
}

// We intentionally EXCLUDE the jitter from this calculation to make sleep times
// predictable for tests
func (rp *TestRetryProvider) SleepDuration(attempt int, retryAfterHeader string) time.Duration {
	var delay time.Duration

	// If there's a ratelimit retry-after header, jsut use that
	if ratelimitDelay := rp.RatelimitDuration(retryAfterHeader); ratelimitDelay > 0 {
		delay = ratelimitDelay
	} else {
		delay = rp.BackoffDuration(attempt)
	}

	// We record the expected duration time, but always return 10ms so tests
	// remain in constant time.
	rp.retryDurationHistory = append(rp.retryDurationHistory, int(delay.Seconds()))
	return 10 * time.Millisecond
}

// Test helpers and mock server setup for HTTP retry functionality

type mockRetryServer struct {
	mu           sync.Mutex
	server       *httptest.Server
	requestCount int
	responses    []mockResponse
	authHeaders  []string
	requestPaths []string
}

type mockResponse struct {
	statusCode int
	headers    map[string]string
	body       string
}

func newMockRetryServer(responses []mockResponse) *mockRetryServer {
	mrs := &mockRetryServer{responses: responses}

	mrs.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Track received data for verification
		mrs.mu.Lock()
		mrs.requestCount++
		count := mrs.requestCount
		mrs.authHeaders = append(mrs.authHeaders, r.Header.Get("Authorization"))
		mrs.requestPaths = append(mrs.requestPaths, r.URL.Path)
		mrs.mu.Unlock()

		// Use the response for this request count, or repeat the last one
		responseIndex := count - 1
		if responseIndex >= len(mrs.responses) {
			responseIndex = len(mrs.responses) - 1
		}

		response := mrs.responses[responseIndex]

		// Set headers
		for key, value := range response.headers {
			w.Header().Set(key, value)
		}

		// Set status and body
		w.WriteHeader(response.statusCode)
		w.Write([]byte(response.body))
	}))

	return mrs
}

func (mrs *mockRetryServer) Close() {
	mrs.server.Close()
}

func (mrs *mockRetryServer) RequestCount() int {
	mrs.mu.Lock()
	defer mrs.mu.Unlock()

	return mrs.requestCount
}

func (mrs *mockRetryServer) LastAuthHeader() string {
	mrs.mu.Lock()
	defer mrs.mu.Unlock()

	if len(mrs.authHeaders) == 0 {
		return ""
	}
	return mrs.authHeaders[len(mrs.authHeaders)-1]
}

func createTestDopplerClient(baseURL string, retryAmount int, retryDuration time.Duration) *DopplerClient {
	u, _ := url.Parse(baseURL)
	return &DopplerClient{
		baseURL:      u,
		DopplerToken: "test-token-12345",
		UserAgent:    "external-secrets-test/1.0",
		VerifyTLS:    true,
		retryProvider: &TestRetryProvider{
			retryAmount:          retryAmount,
			retryDuration:        retryDuration,
			retryDurationHistory: []int{},
		},
	}
}

/*
 * Default Settings (No Retries)
 */
func TestDopplerClient_DefaultSettings_NoRetries(t *testing.T) {
	t.Run("success_single_request", func(t *testing.T) {
		mockSrv := newMockRetryServer([]mockResponse{
			{statusCode: 200, body: `{"name": "API_KEY", "value": "secret123"}`},
		})
		defer mockSrv.Close()

		client := createTestDopplerClient(mockSrv.server.URL, 0, 0)

		response, err := client.performRequest("/v3/configs/config/secrets/API_KEY", "GET", nil, nil, nil)

		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if response == nil {
			t.Fatal("Expected response, got nil")
		}

		if mockSrv.RequestCount() != 1 {
			t.Errorf("Expected exactly 1 request, got %d", mockSrv.RequestCount())
		}

		retriesMade := len(client.retryProvider.RetryDurationHistory())
		if retriesMade > 0 {
			t.Errorf("Expected no retries, got %d", retriesMade)
		}

		// Verify Bearer token authentication
		expectedAuth := "Bearer test-token-12345"
		if mockSrv.LastAuthHeader() != expectedAuth {
			t.Errorf("Expected Authorization header '%s', got '%s'", expectedAuth, mockSrv.LastAuthHeader())
		}
	})

	t.Run("failure_no_retry", func(t *testing.T) {
		mockSrv := newMockRetryServer([]mockResponse{
			{statusCode: 500, body: `{"messages": ["Internal server error"]}`},
		})
		defer mockSrv.Close()

		client := createTestDopplerClient(mockSrv.server.URL, 0, 0)

		response, err := client.performRequest("/v3/configs/config/secrets/MISSING_KEY", "GET", nil, nil, nil)

		if err == nil {
			t.Fatal("Expected error for 500 status, got nil")
		}

		if response == nil {
			t.Fatal("Expected response even on error, got nil")
		}

		if mockSrv.RequestCount() != 1 {
			t.Errorf("Expected exactly 1 request (no retries), got %d", mockSrv.RequestCount())
		}
	})
}

/*
 * Retry logic
 */
func TestDopplerClient_RetryLogic(t *testing.T) {
	t.Run("basic_retry_count_verification", func(t *testing.T) {
		mockSrv := newMockRetryServer([]mockResponse{
			{statusCode: 500, body: `{"messages": ["Server error"]}`},
			{statusCode: 500, body: `{"messages": ["Server error"]}`},
			{statusCode: 200, body: `{"name": "API_KEY", "value": "success"}`},
		})
		defer mockSrv.Close()

		client := createTestDopplerClient(mockSrv.server.URL, 3, testRetryDelay)

		_, err := client.performRequest("/v3/configs/config/secrets/API_KEY", "GET", nil, nil, nil)

		if err != nil {
			t.Fatalf("Expected success after retries, got error: %v", err)
		}

		if mockSrv.RequestCount() != 3 {
			t.Errorf("Expected exactly 3 requests, got %d", mockSrv.RequestCount())
		}
	})

	t.Run("retry_exponential_backoff_min_duration", func(t *testing.T) {
		mockSrv := newMockRetryServer([]mockResponse{
			{statusCode: 500, body: `{"messages": ["Server error"]}`},
		})
		defer mockSrv.Close()

		client := createTestDopplerClient(mockSrv.server.URL, 10, constants.MinAllowedDelay)

		client.performRequest("/v3/configs/config/secrets/API_KEY", "GET", nil, nil, nil)

		if mockSrv.RequestCount() != 11 {
			t.Errorf("Expected exactly 11 requests, got %d", mockSrv.RequestCount())
		}

		expectedRetryDurations := []int{1, 2, 4, 8, 8, 8, 8, 8, 8, 8}
		actualRetryDurations := client.retryProvider.RetryDurationHistory()
		if !slices.Equal(actualRetryDurations, expectedRetryDurations) {
			t.Errorf("Expected %v retry durations, got %v", expectedRetryDurations, actualRetryDurations)
		}
	})

	t.Run("retry_exponential_backoff_max_duration", func(t *testing.T) {
		mockSrv := newMockRetryServer([]mockResponse{
			{statusCode: 500, body: `{"messages": ["Server error"]}`},
		})
		defer mockSrv.Close()

		client := createTestDopplerClient(mockSrv.server.URL, 10, constants.MaxAllowedDelay)

		client.performRequest("/v3/configs/config/secrets/API_KEY", "GET", nil, nil, nil)

		if mockSrv.RequestCount() != 11 {
			t.Errorf("Expected exactly 11 requests, got %d", mockSrv.RequestCount())
		}

		expectedRetryDurations := []int{10, 20, 40, 80, 80, 80, 80, 80, 80, 80}
		actualRetryDurations := client.retryProvider.RetryDurationHistory()
		if !slices.Equal(actualRetryDurations, expectedRetryDurations) {
			t.Errorf("Expected %v retry durations, got %v", expectedRetryDurations, actualRetryDurations)
		}
	})

	t.Run("retry_exponential_backoff_below_min", func(t *testing.T) {
		mockSrv := newMockRetryServer([]mockResponse{
			{statusCode: 500, body: `{"messages": ["Server error"]}`},
		})
		defer mockSrv.Close()

		client := createTestDopplerClient(mockSrv.server.URL, 1, constants.MinAllowedDelay/2)

		client.performRequest("/v3/configs/config/secrets/API_KEY", "GET", nil, nil, nil)

		if mockSrv.RequestCount() != 2 {
			t.Errorf("Expected exactly 2 requests, got %d", mockSrv.RequestCount())
		}

		expectedRetryDurations := []int{1}
		actualRetryDurations := client.retryProvider.RetryDurationHistory()
		if !slices.Equal(actualRetryDurations, expectedRetryDurations) {
			t.Errorf("Expected %v retry durations, got %v", expectedRetryDurations, actualRetryDurations)
		}
	})

	t.Run("retry_amount_ceiling", func(t *testing.T) {
		mockSrv := newMockRetryServer([]mockResponse{
			{statusCode: 500, body: `{"messages": ["Server error"]}`},
		})
		defer mockSrv.Close()

		// Request 15 retries, should be capped at 10
		client := createTestDopplerClient(mockSrv.server.URL, 15, testRetryDelay)
		_, err := client.performRequest("/v3/configs/config/secrets/API_KEY", "GET", nil, nil, nil)

		if err == nil {
			t.Fatal("Expected error after exhausting retries, got nil")
		}

		if mockSrv.RequestCount() != 11 {
			t.Errorf("Expected exactly 11 requests (1 initial + 10 retries capped), got %d", mockSrv.RequestCount())
		}
	})
}

/*
 * Rate limit handling
 */
func TestDopplerClient_RateLimitHandling(t *testing.T) {
	t.Run("respect_retry_after_header", func(t *testing.T) {
		mockSrv := newMockRetryServer([]mockResponse{
			{
				statusCode: 429,
				headers: map[string]string{
					"x-ratelimit-limit": "100",
					"retry-after":       "48",
				},
				body: `{"messages": ["Rate limit exceeded"]}`,
			},
			{statusCode: 200, body: `{"name": "API_KEY", "value": "success"}`},
		})
		defer mockSrv.Close()

		client := createTestDopplerClient(mockSrv.server.URL, 2, testRetryDelay)

		_, err := client.performRequest("/v3/configs/config/secrets/API_KEY", "GET", nil, nil, nil)

		if err != nil {
			t.Fatalf("Expected success after rate limit retry, got error: %v", err)
		}

		if mockSrv.RequestCount() != 2 {
			t.Errorf("Expected exactly 2 requests, got %d", mockSrv.RequestCount())
		}

		expectedRetryDurations := []int{48}
		actualRetryDurations := client.retryProvider.RetryDurationHistory()
		if !slices.Equal(actualRetryDurations, expectedRetryDurations) {
			t.Errorf("Expected %v retry durations, got %v", expectedRetryDurations, actualRetryDurations)
		}
	})

	// If an invalid retry-after header is encountered, we ignore it and process
	// it like a normal request failure, using the typical backoff sleep duration
	t.Run("handles_invalid_retry_after_header", func(t *testing.T) {
		mockSrv := newMockRetryServer([]mockResponse{
			{statusCode: 500, body: `{"messages": ["Server error"]}`},
			{statusCode: 500, body: `{"messages": ["Server error"]}`},
			{
				statusCode: 429,
				headers: map[string]string{
					"x-ratelimit-limit": "100",
					"retry-after":       "invalid-number",
				},
				body: `{"messages": ["Rate limit exceeded"]}`,
			},
			{statusCode: 200, body: `{"name": "API_KEY", "value": "success"}`},
		})
		defer mockSrv.Close()

		client := createTestDopplerClient(mockSrv.server.URL, 3, testRetryDelay)

		_, err := client.performRequest("/v3/configs/config/secrets/API_KEY", "GET", nil, nil, nil)

		if err != nil {
			t.Fatalf("Expected success after retry, got error: %v", err)
		}

		if mockSrv.RequestCount() != 4 {
			t.Errorf("Expected exactly 4 requests, got %d", mockSrv.RequestCount())
		}

		expectedRetryDurations := []int{1, 2, 4}
		actualRetryDurations := client.retryProvider.RetryDurationHistory()
		if !slices.Equal(actualRetryDurations, expectedRetryDurations) {
			t.Errorf("Expected %v retry durations, got %v", expectedRetryDurations, actualRetryDurations)
		}
	})
}

/*
 * Test network error handling
 */
func TestDopplerClient_NetworkErrors(t *testing.T) {
	t.Run("network_error_with_retries", func(t *testing.T) {
		// Create a server that we immediately close to simulate network errors
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		serverURL := server.URL
		server.Close() // Close immediately to cause connection errors

		client := createTestDopplerClient(serverURL, 2, testRetryDelay)

		_, err := client.performRequest("/v3/configs/config/secrets/API_KEY", "GET", nil, nil, nil)

		// Should get an error due to connection failure
		if err == nil {
			t.Fatal("Expected network error, got nil")
		}
	})
}
