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
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/external-secrets/external-secrets/pkg/provider/doppler/constants"
)

// RetryProvider allows for dynamically customizing various aspects of the retry
// behavior. Notably, we alter how SleepDuration() works in tests to avoid keep
// the tests in constant time while still being able check expected sleep durations.
type RetryProvider interface {
	MinRetryDelay() time.Duration
	MaxRetryDelay() time.Duration
	MaxBackoffMultiplier() time.Duration
	JitterDuration(delay time.Duration) time.Duration
	RetryAmount() int
	RetryDuration() time.Duration
	RetryDurationHistory() []int
	BackoffDuration(attempt int) time.Duration
	RatelimitDuration(retryAfterHeader string) time.Duration
	SleepDuration(attempt int, retryAfterHeader string) time.Duration
}

type DopplerClient struct {
	baseURL       *url.URL
	retryProvider RetryProvider
	DopplerToken  string
	VerifyTLS     bool
	UserAgent     string
}

type queryParams map[string]string

type headers map[string]string

type httpRequestBody []byte

type Secrets map[string]string

type Change struct {
	Name         string  `json:"name"`
	OriginalName string  `json:"originalName"`
	Value        *string `json:"value"`
	ShouldDelete bool    `json:"shouldDelete,omitempty"`
}

type APIError struct {
	Err     error
	Message string
	Data    string
}

type apiResponse struct {
	HTTPResponse *http.Response
	Body         []byte
}

type apiErrorResponse struct {
	Messages []string
	Success  bool
}

type SecretRequest struct {
	Name    string
	Project string
	Config  string
}

type SecretsRequest struct {
	Project         string
	Config          string
	NameTransformer string
	Format          string
	ETag            string // Specifying an ETag implies that the caller has implemented response caching
}

type UpdateSecretsRequest struct {
	Secrets        Secrets  `json:"secrets,omitempty"`
	ChangeRequests []Change `json:"change_requests,omitempty"`
	Project        string   `json:"project,omitempty"`
	Config         string   `json:"config,omitempty"`
}

type secretResponseBody struct {
	Name  string `json:"name,omitempty"`
	Value struct {
		Raw      *string `json:"raw"`
		Computed *string `json:"computed"`
	} `json:"value,omitempty"`
	Messages *[]string `json:"messages,omitempty"`
	Success  bool      `json:"success"`
}

type SecretResponse struct {
	Name  string
	Value string
}

type SecretsResponse struct {
	Secrets  Secrets
	Body     []byte
	Modified bool
	ETag     string
}

const (
	// HttpRequestTimeout is the timeout period we allow for HTTP requests
	HttpRequestTimeout = 10 * time.Second
)

type DefaultRetryProvider struct {
	retryAmount   int
	retryDuration time.Duration
}

func (rp *DefaultRetryProvider) MinRetryDelay() time.Duration {
	return constants.MinAllowedDelay
}

func (rp *DefaultRetryProvider) MaxRetryDelay() time.Duration {
	return constants.MaxAllowedDelay
}

func (rp *DefaultRetryProvider) MaxBackoffMultiplier() time.Duration {
	return constants.MaxBackoffMultiplier
}

func (rp *DefaultRetryProvider) JitterDuration(delay time.Duration) time.Duration {
	return time.Duration(float64(delay) * constants.JitterMultiplier * (2*rand.Float64() - 1))
}

func (rp *DefaultRetryProvider) RetryAmount() int {
	return rp.retryAmount
}

func (rp *DefaultRetryProvider) RetryDuration() time.Duration {
	return rp.retryDuration
}

// This is only used for tests, so we just return an empty slice here
func (rp *DefaultRetryProvider) RetryDurationHistory() []int {
	return []int{}
}

func (rp *DefaultRetryProvider) BackoffDuration(attempt int) time.Duration {
	minDelay := rp.MinRetryDelay()

	// Ensure the baseDelay doesn't exceed the max or minimum values
	baseDelay := max(rp.RetryDuration(), minDelay)
	baseDelay = min(baseDelay, rp.MaxRetryDelay())

	// Exponential backoff is 2^attempt, capped at MaxBackoffMultiplier
	multiplier := min(1<<uint(attempt), rp.MaxBackoffMultiplier())

	delay := baseDelay * time.Duration(multiplier)

	// Ensure delay never goes below the minimum
	delay = max(delay, minDelay)

	return delay
}

func (rp *DefaultRetryProvider) RatelimitDuration(retryAfterHeader string) time.Duration {
	if retryAfterHeader == "" {
		return 0
	}

	duration, err := time.ParseDuration(retryAfterHeader + "s")
	if err != nil {
		return 0
	}

	return duration
}

func (rp *DefaultRetryProvider) SleepDuration(attempt int, retryAfterHeader string) time.Duration {
	var delay time.Duration

	// If there's a ratelimit retry-after header, just use that
	if ratelimitDelay := rp.RatelimitDuration(retryAfterHeader); ratelimitDelay > 0 {
		delay = ratelimitDelay
	} else {
		delay = rp.BackoffDuration(attempt)

		// Introduce jitter to the delay time to avoid thundering herd
		delay += rp.JitterDuration(delay)
	}

	return delay
}

func NewDopplerClient(dopplerToken string, retryAmount int, retryDuration time.Duration) (*DopplerClient, error) {
	client := &DopplerClient{
		DopplerToken: dopplerToken,
		VerifyTLS:    true,
		UserAgent:    "doppler-external-secrets",
		retryProvider: &DefaultRetryProvider{
			retryAmount:   retryAmount,
			retryDuration: retryDuration,
		},
	}

	if err := client.SetBaseURL("https://api.doppler.com"); err != nil {
		return nil, &APIError{Err: err, Message: "setting base URL failed"}
	}

	return client, nil
}

func (c *DopplerClient) BaseURL() *url.URL {
	u := *c.baseURL
	return &u
}

func (c *DopplerClient) SetBaseURL(urlStr string) error {
	baseURL, err := url.Parse(strings.TrimSuffix(urlStr, "/"))

	if err != nil {
		return err
	}

	if baseURL.Scheme == "" {
		baseURL.Scheme = "https"
	}

	c.baseURL = baseURL
	return nil
}

func (c *DopplerClient) Authenticate() error {
	//  Choose projects as a lightweight endpoint for testing authentication
	if _, err := c.performRequest("/v3/projects", "GET", headers{}, queryParams{}, httpRequestBody{}); err != nil {
		return err
	}

	return nil
}

func (c *DopplerClient) GetSecret(request SecretRequest) (*SecretResponse, error) {
	params := request.buildQueryParams(request.Name)
	response, err := c.performRequest("/v3/configs/config/secret", "GET", headers{}, params, httpRequestBody{})
	if err != nil {
		return nil, err
	}

	var data secretResponseBody
	if err := json.Unmarshal(response.Body, &data); err != nil {
		return nil, &APIError{Err: err, Message: "unable to unmarshal secret payload", Data: string(response.Body)}
	}

	if data.Value.Computed == nil {
		return nil, &APIError{Message: fmt.Sprintf("secret '%s' not found", request.Name)}
	}

	return &SecretResponse{Name: data.Name, Value: *data.Value.Computed}, nil
}

// GetSecrets should only have an ETag supplied if Secrets are cached as SecretsResponse.Secrets will be nil if 304 (not modified) returned.
func (c *DopplerClient) GetSecrets(request SecretsRequest) (*SecretsResponse, error) {
	headers := headers{}
	if request.ETag != "" {
		headers["if-none-match"] = request.ETag
	}
	if request.Format != "" && request.Format != "json" {
		headers["accept"] = "text/plain"
	}

	params := request.buildQueryParams()
	response, apiErr := c.performRequest("/v3/configs/config/secrets/download", "GET", headers, params, httpRequestBody{})
	if apiErr != nil {
		return nil, apiErr
	}

	if response.HTTPResponse.StatusCode == 304 {
		return &SecretsResponse{Modified: false, Secrets: nil, ETag: request.ETag}, nil
	}

	eTag := response.HTTPResponse.Header.Get("etag")

	// Format defeats JSON parsing
	if request.Format != "" {
		return &SecretsResponse{Modified: true, Body: response.Body, ETag: eTag}, nil
	}

	var secrets Secrets
	if err := json.Unmarshal(response.Body, &secrets); err != nil {
		return nil, &APIError{Err: err, Message: "unable to unmarshal secrets payload"}
	}
	return &SecretsResponse{Modified: true, Secrets: secrets, Body: response.Body, ETag: eTag}, nil
}

func (c *DopplerClient) UpdateSecrets(request UpdateSecretsRequest) error {
	body, jsonErr := json.Marshal(request)
	if jsonErr != nil {
		return &APIError{Err: jsonErr, Message: "unable to unmarshal update secrets payload"}
	}
	_, err := c.performRequest("/v3/configs/config/secrets", "POST", headers{}, queryParams{}, body)
	if err != nil {
		return err
	}
	return nil
}

func (r *SecretRequest) buildQueryParams(name string) queryParams {
	params := queryParams{}
	params["name"] = name

	if r.Project != "" {
		params["project"] = r.Project
	}

	if r.Config != "" {
		params["config"] = r.Config
	}

	return params
}

func (r *SecretsRequest) buildQueryParams() queryParams {
	params := queryParams{}

	if r.Project != "" {
		params["project"] = r.Project
	}

	if r.Config != "" {
		params["config"] = r.Config
	}

	if r.NameTransformer != "" {
		params["name_transformer"] = r.NameTransformer
	}

	if r.Format != "" {
		params["format"] = r.Format
	}

	return params
}

func (c *DopplerClient) performRequest(path, method string, headers headers, params queryParams, body httpRequestBody) (*apiResponse, error) {
	maxRetries := min(c.retryProvider.RetryAmount(), constants.MaxAllowedRetries)

	var response *apiResponse
	var err error

	// <= ensures that we'll perform maxRetries+1 loops. The initial loop always
	// performs the initial request. If it fails, we then perform the user-specified
	// number of retries (with a RetryCeiling max).
	for attempt := 0; attempt <= maxRetries; attempt++ {
		response, err = c.doHTTPRequest(path, method, headers, params, body)

		if err == nil {
			return response, nil
		}

		// < here ensures that we don't sleep after our last retry attempt.
		if attempt < maxRetries {
			retryAfter := ""
			if response != nil && isRateLimited(response.HTTPResponse.StatusCode) {
				rateLimit := response.HTTPResponse.Header.Get("x-ratelimit-limit")
				retryAfter = response.HTTPResponse.Header.Get("retry-after")
				fmt.Printf("warn: Doppler ratelimit of %s reqs/min reached. retrying in %s second(s)...\n", rateLimit, retryAfter)
			}
			sleepDuration := c.retryProvider.SleepDuration(attempt, retryAfter)
			time.Sleep(sleepDuration)
		}
	}

	return response, err
}

// doHTTPRequest performs a single HTTP request without retry logic
func (c *DopplerClient) doHTTPRequest(path, method string, headers headers, params queryParams, body httpRequestBody) (*apiResponse, error) {
	urlStr := c.BaseURL().String() + path
	reqURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, &APIError{Err: err, Message: fmt.Sprintf("invalid API URL: %s", urlStr)}
	}

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, reqURL.String(), bodyReader)
	if err != nil {
		return nil, &APIError{Err: err, Message: "unable to form HTTP request"}
	}

	if method == "POST" && req.Header.Get("content-type") == "" {
		req.Header.Set("content-type", "application/json")
	}

	if req.Header.Get("accept") == "" {
		req.Header.Set("accept", "application/json")
	}
	req.Header.Set("user-agent", c.UserAgent)
	req.Header.Set("authorization", "Bearer "+c.DopplerToken)

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	query := req.URL.Query()
	for key, value := range params {
		query.Add(key, value)
	}
	req.URL.RawQuery = query.Encode()

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: !c.VerifyTLS,
	}

	httpClient := &http.Client{
		Timeout: HttpRequestTimeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   tlsConfig,
		},
	}

	r, err := httpClient.Do(req)
	if err != nil {
		return nil, &APIError{Err: err, Message: "unable to load response"}
	}
	defer func() {
		_ = r.Body.Close()
	}()

	bodyResponse, err := io.ReadAll(r.Body)
	if err != nil {
		return &apiResponse{HTTPResponse: r, Body: nil}, &APIError{Err: err, Message: "unable to read entire response body"}
	}

	response := &apiResponse{HTTPResponse: r, Body: bodyResponse}

	if !isSuccess(r.StatusCode) {
		return response, c.handleErrorResponse(r, bodyResponse)
	}

	return response, nil
}

func (c *DopplerClient) handleErrorResponse(resp *http.Response, bodyResponse []byte) error {
	contentType := resp.Header.Get("content-type")
	if strings.HasPrefix(contentType, "application/json") {
		var errResponse apiErrorResponse
		if err := json.Unmarshal(bodyResponse, &errResponse); err != nil {
			return &APIError{Err: err, Message: "unable to unmarshal error JSON payload"}
		}
		return &APIError{Err: nil, Message: strings.Join(errResponse.Messages, "\n")}
	}

	return &APIError{
		Err:     fmt.Errorf("%d status code; %d bytes", resp.StatusCode, len(bodyResponse)),
		Message: "unable to load response",
	}
}

func isSuccess(statusCode int) bool {
	return (statusCode >= 200 && statusCode <= 299) || (statusCode >= 300 && statusCode <= 399)
}

func isRateLimited(statusCode int) bool {
	return statusCode == 429
}

func (e *APIError) Error() string {
	message := fmt.Sprintf("Doppler API Client Error: %s", e.Message)
	if underlyingError := e.Err; underlyingError != nil {
		message = fmt.Sprintf("%s\n%s", message, underlyingError.Error())
	}
	if e.Data != "" {
		message = fmt.Sprintf("%s\nData: %s", message, e.Data)
	}
	return message
}
