package tutils

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	fedora_identity "github.com/osbuild/community-gateway/oidc-authorizer/pkg/identity"
	"github.com/stretchr/testify/require"
)

// org_id 000000
var AuthString0 = GetCompleteBase64Header("000000")
var AuthString0WithoutEntitlements = GetBase64HeaderWithoutEntitlements("000000")

// org_id 000001
var AuthString1 = GetCompleteBase64Header("000001")

var FedAuth = getBase64Header(fedoraHeader, "User")

func GetResponseError(url string) (*http.Response, error) {
	client := &http.Client{}
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Add("x-rh-identity", AuthString0)

	return client.Do(request)
}

func responseBody(t *testing.T, method, url string, auth *string, body interface{}) (int, string) {
	client := http.Client{}
	var request *http.Request
	var err error

	if body != nil {
		buf, err := json.Marshal(body)
		require.NoError(t, err)
		request, err = http.NewRequest(method, url, bytes.NewReader(buf))
		require.NoError(t, err)
		request.Header.Add("Content-Type", "application/json")
	} else {
		request, err = http.NewRequest(method, url, nil)
		require.NoError(t, err)
	}

	if auth != nil {
		request.Header.Add("x-rh-identity", *auth)
		request.Header.Add(fedora_identity.FedoraIDHeader, *auth)
	}

	response, err := client.Do(request)
	require.NoError(t, err)
	if err != nil {
		/* #nosec G307 */
		defer response.Body.Close()
	}
	respBody, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	return response.StatusCode, string(respBody)
}

func GetResponseBody(t *testing.T, url string, auth *string) (int, string) {
	return responseBody(t, http.MethodGet, url, auth, nil)
}

func PostResponseBody(t *testing.T, url string, body interface{}) (int, string) {
	return responseBody(t, http.MethodPost, url, &AuthString0, body)
}

func PutResponseBody(t *testing.T, url string, body interface{}) (int, string) {
	return responseBody(t, http.MethodPut, url, &AuthString0, body)
}

func DeleteResponseBody(t *testing.T, url string) (int, string) {
	return responseBody(t, http.MethodDelete, url, &AuthString0, nil)
}
