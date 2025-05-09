package oauth2

import (
	"context"
	"net/http"
	"sync"
)

// DummyToken is a dummy implementation of the Tokener interface.
type DummyToken struct {
	c *http.Client
	m sync.Mutex
}

// Token returns a static "testtoken" string.
func (dt *DummyToken) Token(ctx context.Context) (string, error) {

	return "accesstoken", nil
}

func (dt *DummyToken) ForceRefresh(ctx context.Context) (string, error) {
	return "", nil
}

func (dt *DummyToken) SetClient(c *http.Client) {
	dt.m.Lock()
	defer dt.m.Unlock()

	dt.c = c
}

func (dt *DummyToken) Do(req *http.Request) (*http.Response, error) {
	dt.m.Lock()
	defer dt.m.Unlock()

	if dt.c == nil {
		dt.c = http.DefaultClient
	}

	return do(dt.c, dt, req)
}
