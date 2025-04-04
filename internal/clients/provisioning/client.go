package provisioning

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/osbuild/logging/pkg/strc"
	"github.com/redhatinsights/identity"
)

type ProvisioningClient struct {
	url    string
	client *http.Client
}

type ProvisioningClientConfig struct {
	URL string
}

func NewClient(conf ProvisioningClientConfig) (*ProvisioningClient, error) {
	pc := ProvisioningClient{
		url:    conf.URL,
		client: &http.Client{},
	}

	return &pc, nil
}

func (pc *ProvisioningClient) request(ctx context.Context, method, url string, headers map[string]string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	return strc.NewTracingDoer(pc.client).Do(req)
}

func (pc *ProvisioningClient) GetUploadInfo(ctx context.Context, sourceID string) (*http.Response, error) {
	id, ok := identity.GetIdentityHeader(ctx)
	if !ok {
		return nil, fmt.Errorf("unable to get identity from context")
	}

	return pc.request(ctx, "GET", fmt.Sprintf("%s/sources/%s/upload_info", pc.url, sourceID), map[string]string{
		"x-rh-identity": id,
	}, nil)
}
