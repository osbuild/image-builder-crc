package oauth2

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/osbuild/logging/pkg/strc"
)

func do(client *http.Client, tokener Tokener, req *http.Request) (*http.Response, error) {
	if client == nil {
		panic("client must be set before calling Do()")
	}

	var bodyBytes []byte
	var err error
	if req.Body != nil {
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}

		err = req.Body.Close()
		if err != nil {
			return nil, err
		}

		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	token, err := tokener.Token(req.Context())
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := strc.NewTracingDoer(client).Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		token, err = tokener.ForceRefresh(req.Context())
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

		if req.Body != nil {
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}
		resp, err = strc.NewTracingDoer(client).Do(req)
		if err != nil {
			return nil, err
		}
	}

	return resp, err
}
