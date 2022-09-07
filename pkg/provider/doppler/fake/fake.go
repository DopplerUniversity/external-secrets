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
package fake

import (
	"fmt"
	"net/url"

	"github.com/google/go-cmp/cmp"

	"github.com/external-secrets/external-secrets/pkg/provider/doppler/client"
)

type DopplerClient struct {
	baseURL         func() *url.URL
	authenticate    func() error
	getSecret       func(request client.SecretRequest) (*client.SecretResponse, error)
	getSecrets      func(request client.SecretsRequest) (*client.SecretsResponse, error)
	downloadSecrets func(request client.SecretsDownloadRequest) (*client.SecretsDownloadResponse, error)
}

func (dc *DopplerClient) BaseURL() *url.URL {
	return dc.baseURL()
}

func (dc *DopplerClient) Authenticate() error {
	return dc.authenticate()
}

func (dc *DopplerClient) GetSecret(request client.SecretRequest) (*client.SecretResponse, error) {
	return dc.getSecret(request)
}

func (dc *DopplerClient) GetSecrets(request client.SecretsRequest) (*client.SecretsResponse, error) {
	return dc.getSecrets(request)
}

func (dc *DopplerClient) DownloadSecrets(request client.SecretsDownloadRequest) (*client.SecretsDownloadResponse, error) {
	return dc.downloadSecrets(request)
}

func (dc *DopplerClient) WithValue(request client.SecretRequest, response *client.SecretResponse, err error) {
	if dc != nil {
		dc.getSecret = func(requestIn client.SecretRequest) (*client.SecretResponse, error) {
			if !cmp.Equal(requestIn, request) {
				return nil, fmt.Errorf("unexpected test argument")
			}
			return response, err
		}
	}
}
