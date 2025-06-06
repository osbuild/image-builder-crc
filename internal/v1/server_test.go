package v1_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"

	"github.com/osbuild/image-builder-crc/internal/clients/compliance"
	"github.com/osbuild/image-builder-crc/internal/clients/composer"
	"github.com/osbuild/image-builder-crc/internal/clients/content_sources"
	"github.com/osbuild/image-builder-crc/internal/clients/provisioning"
	"github.com/osbuild/image-builder-crc/internal/clients/recommendations"
	"github.com/osbuild/image-builder-crc/internal/common"
	"github.com/osbuild/image-builder-crc/internal/db"
	"github.com/osbuild/image-builder-crc/internal/distribution"
	"github.com/osbuild/image-builder-crc/internal/oauth2"
	"github.com/osbuild/image-builder-crc/internal/tutils"
	v1 "github.com/osbuild/image-builder-crc/internal/v1"
	"github.com/osbuild/image-builder-crc/internal/v1/mocks"
)

var dbc *tutils.PSQLContainer

func TestMain(m *testing.M) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	slog.SetDefault(logger)

	code := runTests(m)
	os.Exit(code)
}

func runTests(m *testing.M) int {
	d, err := tutils.NewPSQLContainer()
	if err != nil {
		panic(err)
	}

	dbc = d
	code := m.Run()
	defer func() {
		err = dbc.Stop()
		if err != nil {
			slog.Error("error stopping postgres container", "err", err)
		}
	}()
	return code
}

// Create a temporary file containing quotas, returns the file name as a string
func initQuotaFile(t *testing.T) (string, error) {
	// create quotas with only the default values
	quotas := map[string]common.Quota{
		"default": {Quota: common.DefaultQuota, SlidingWindow: common.DefaultSlidingWindow},
	}
	jsonQuotas, err := json.Marshal(quotas)
	if err != nil {
		return "", err
	}

	// get a temp file to store the quotas
	file, err := os.CreateTemp(t.TempDir(), "account_quotas.*.json")
	if err != nil {
		return "", err
	}

	// write to disk
	jsonFile, err := os.Create(file.Name())
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	_, err = jsonFile.Write(jsonQuotas)
	if err != nil {
		return "", err
	}
	err = jsonFile.Close()
	if err != nil {
		return "", err
	}
	return file.Name(), nil
}

func makeUploadOptions(t *testing.T, uploadOptions interface{}) *composer.UploadOptions {
	data, err := json.Marshal(uploadOptions)
	require.NoError(t, err)

	var result composer.UploadOptions
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	return &result
}

type testServerClientsConf struct {
	ComposerURL  string
	ProvURL      string
	RecommendURL string
	OAuthURL     string
	Proxy        string
}

type testServer struct {
	echo *echo.Echo

	URL string
	DB  db.DB

	tokenSrv *httptest.Server
	csSrv    *httptest.Server
}

func startServer(t *testing.T, tscc *testServerClientsConf, conf *v1.ServerConfig) *testServer {
	ctx := context.Background()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(struct {
			AccessToken string `json:"access_token"`
		}{
			AccessToken: "accesstoken",
		})
		require.NoError(t, err)
	}))

	dummyTokener := &oauth2.DummyToken{}
	compClient, err := composer.NewClient(composer.ComposerClientConfig{
		URL:     tscc.ComposerURL,
		Tokener: dummyTokener,
	})
	require.NoError(t, err)

	provClient, err := provisioning.NewClient(provisioning.ProvisioningClientConfig{
		URL: tscc.ProvURL,
	})
	require.NoError(t, err)

	csSrv := httptest.NewServer(http.HandlerFunc(mocks.ContentSources))
	csClient, err := content_sources.NewClient(content_sources.ContentSourcesClientConfig{
		URL: csSrv.URL,
	})
	require.NoError(t, err)

	var recommendToken oauth2.Tokener
	if tscc.OAuthURL != "" {
		recommendToken = &oauth2.LazyToken{
			Url:          tscc.OAuthURL,
			ClientId:     "id",
			ClientSecret: "secret",
			AccessToken:  "token",
		}
	} else {
		recommendToken = &oauth2.DummyToken{}
	}
	recommendClient, err := recommendations.NewClient(recommendations.RecommendationsClientConfig{
		URL:     tscc.RecommendURL,
		Proxy:   tscc.Proxy,
		Tokener: recommendToken,
	})
	require.NoError(t, err)

	complSrv := httptest.NewServer(mocks.Compliance())
	complianceClient := compliance.NewClient(compliance.ComplianceClientConfig{
		URL: complSrv.URL,
	})

	//store the quotas in a temporary file
	quotaFile, err := initQuotaFile(t)
	require.NoError(t, err)

	echoServer := echo.New()
	echoServer.Logger.SetOutput(io.Discard)
	echoServer.HideBanner = true
	serverConfig := conf
	if serverConfig == nil {
		serverConfig = &v1.ServerConfig{}
	}

	if serverConfig.DBase == nil {
		dbase, err := dbc.NewDB(ctx)
		require.NoError(t, err)
		serverConfig.DBase = dbase
	}
	serverConfig.EchoServer = echoServer
	serverConfig.CompClient = compClient
	serverConfig.ProvClient = provClient
	serverConfig.CSClient = csClient
	serverConfig.CSReposURL = "https://content-sources.org"
	serverConfig.CSReposPrefix = "/api/neat"
	serverConfig.RecommendClient = recommendClient
	serverConfig.ComplianceClient = complianceClient
	if serverConfig.QuotaFile == "" {
		serverConfig.QuotaFile = quotaFile
	}
	if serverConfig.DistributionsDir == "" {
		serverConfig.DistributionsDir = "../../distributions"
	}
	if serverConfig.AllDistros == nil {
		adr, err := distribution.LoadDistroRegistry(serverConfig.DistributionsDir)
		require.NoError(t, err)
		serverConfig.AllDistros = adr
	}

	server, err := v1.Attach(serverConfig)
	require.NoError(t, err)

	// execute in parallel b/c .Run() will block execution
	addr := "localhost:8086"
	URL := "http://" + addr
	go func() {
		err = echoServer.Start(addr)
		if !errors.Is(err, http.ErrServerClosed) {
			panic(fmt.Errorf("starting test server failed %w", err))
		}
	}()

	// wait until server is ready
	tries := 0
	for tries < 5 {
		resp, err := tutils.GetResponseError(URL + "/status")
		if err == nil {
			defer resp.Body.Close()
		}
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		} else if tries == 4 {
			require.NoError(t, err)
		}
		time.Sleep(time.Second)
		tries += 1
	}

	return &testServer{echoServer, URL, server.GetDB(), tokenServer, csSrv}
}

func (ts *testServer) Shutdown(t *testing.T) {
	require.NoError(t, ts.echo.Shutdown(context.Background()))
	ts.tokenSrv.Close()
	ts.csSrv.Close()
}
