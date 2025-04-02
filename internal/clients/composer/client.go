package composer

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/osbuild/image-builder-crc/internal/oauth2"
)

type ComposerClientConfig struct {
	URL     string
	CA      string
	Tokener oauth2.TokenerDoer
}

func NewClientFromConfig(conf ComposerClientConfig) (*Client, error) {
	if conf.URL == "" {
		slog.Warn("composer URL not set, client will fail")
	}
	httpClient, err := createClient(conf.URL, conf.CA)
	if err != nil {
		return nil, fmt.Errorf("Error creating compose http client")
	}
	conf.Tokener.SetClient(httpClient)

	client, err := NewClient(fmt.Sprintf("%s/api/image-builder-composer/v2", conf.URL))
	if err != nil {
		return nil, fmt.Errorf("Error creating compose http client")
	}
	client.Client = conf.Tokener

	return client, nil
}

func createClient(composerURL string, ca string) (*http.Client, error) {
	if !strings.HasPrefix(composerURL, "https") || ca == "" {
		return &http.Client{}, nil
	}

	var tlsConfig *tls.Config
	caCert, err := os.ReadFile(filepath.Clean(ca))
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    caCertPool,
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	return &http.Client{Transport: transport}, nil
}
