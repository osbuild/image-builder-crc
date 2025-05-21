package v1_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/osbuild/image-builder-crc/internal/tutils"
	v1 "github.com/osbuild/image-builder-crc/internal/v1"
)

func TestRecommendPackage(t *testing.T) {
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer accesstoken", r.Header.Get("Authorization"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		result := v1.RecommendationsResponse{
			Packages: []string{
				"recommended1",
			},
		}

		err := json.NewEncoder(w).Encode(result)
		require.NoError(t, err)
	}))
	defer apiSrv.Close()

	srv := startServer(t, &testServerClientsConf{RecommendURL: apiSrv.URL}, &v1.ServerConfig{})
	defer srv.Shutdown(t)

	payload := v1.RecommendPackageRequest{
		Distribution: "rhel-8",
		Packages: []string{
			"some",
			"packages",
		},
		RecommendedPackages: 1,
	}

	code, body := tutils.PostResponseBody(t, srv.URL+"/api/image-builder/v1/experimental/recommendations", payload)
	require.Equal(t, http.StatusOK, code)

	var result v1.RecommendationsResponse
	expectedResult := v1.RecommendationsResponse{
		Packages: []string{"recommended1"},
	}

	err := json.Unmarshal([]byte(body), &result)
	require.NoError(t, err)
	require.Equal(t, expectedResult, result)
}
