package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/osbuild/logging/pkg/strc"
)

// Tokener is an interface that defines the AccessToken method.
type Tokener interface {
	Token(context.Context) (string, error)
	ForceRefresh(context.Context) (string, error)
}

// Doer is an interface that defines the Do method for making HTTP requests.
type Doer interface {
	// SetClients sets HTTP client for the Do method.
	SetClient(*http.Client)

	// Do performs an HTTP request and returns the response.
	Do(req *http.Request) (*http.Response, error)
}

// TokenerDoer is an interface that combines the Tokener and Doer interfaces.
type TokenerDoer interface {
	Tokener
	Doer
}

type LazyToken struct {
	// Url represents the URL used for acquiring the token.
	Url string
	// ClientId is the client ID used for authentication.
	ClientId string
	// ClientSecret is the client secret used for authentication.
	ClientSecret string
	// AccessToken string holds the currently cached token.
	AccessToken string
	// Expiration stores the expiration time of the current token.
	Expiration time.Time

	// HTTP client for Do method
	client *http.Client
	// mutex ensures safe concurrent access to the token and expiration fields.
	mutex sync.Mutex
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// SetClient sets the HTTP client for the Do method. This client is used to delegate the call to.
func (lt *LazyToken) SetClient(c *http.Client) {
	lt.client = c
}

// Do is a method that performs an HTTP request with the lazy token.
// It sets the Authorization header with the token and handles token refresh if needed.
// It returns the HTTP response or an error if the request fails.
// The method reads the request body, sets the Authorization header, and performs the HTTP request.
// If the response status code is 401 or 403, it refreshes the token and retries the request.
// Client must be set before calling this method, otherwise it panics.
func (lt *LazyToken) Do(req *http.Request) (*http.Response, error) {
	return do(lt.client, lt, req)
}

func (lt *LazyToken) acquireNewToken(ctx context.Context, forceRefresh bool) (string, error) {
	lt.mutex.Lock()
	defer lt.mutex.Unlock()

	if forceRefresh || lt.AccessToken == "" || time.Now().Add(time.Minute).After(lt.Expiration) {
		tokenRes, err := lt.requestToken(ctx)
		if err != nil {
			return "", err
		}

		lt.AccessToken = tokenRes.AccessToken
		lt.Expiration = time.Now().Add(time.Duration(tokenRes.ExpiresIn) * time.Second)

		slog.DebugContext(ctx, "acquired new token", "expiration", lt.Expiration)
	}

	return lt.AccessToken, nil
}

func (lt *LazyToken) Token(ctx context.Context) (string, error) {
	return lt.acquireNewToken(ctx, false)
}

// ForceRefresh is a function that responsible for fetching a new access token.
func (lt *LazyToken) ForceRefresh(ctx context.Context) (string, error) {
	return lt.acquireNewToken(ctx, true)
}

// ForceRefresh forces the acquisition of a new access token by clearing the current AccessToken and calling Token().
func (lt *LazyToken) requestToken(ctx context.Context) (*tokenResponse, error) {
	span, _ := strc.Start(ctx, "oauth2 token request")
	defer span.End()

	data := url.Values{}
	data.Set("client_id", lt.ClientId)
	if lt.ClientSecret != "" {
		data.Set("grant_type", "client_credentials")
		data.Set("client_secret", lt.ClientSecret)
	} else {
		return nil, fmt.Errorf("client Id, client Secret and token must be set")
	}
	resp, err := http.PostForm(lt.Url, data)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			// Handle error reading response body
			return nil, fmt.Errorf("failed to read response body: %v", err)
		}
		defer resp.Body.Close()
		return nil, fmt.Errorf("request failed with status code %d: %s", resp.StatusCode, body)
	}

	var tokenResp tokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling token response: %v", err)
	}

	return &tokenResp, nil
}
