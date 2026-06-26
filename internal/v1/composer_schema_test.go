package v1_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/require"
)

var (
	composerSpecOnce sync.Once
	composerSpec     *openapi3.T
	composerSpecErr  error
)

// loadComposerSpec loads the composer OpenAPI spec from the file system once
// and returns a pointer to it.
func loadComposerSpec(t *testing.T) *openapi3.T {
	t.Helper()
	composerSpecOnce.Do(func() {
		loader := openapi3.NewLoader()
		composerSpec, composerSpecErr = loader.LoadFromFile("../../internal/clients/composer/openapi.v2.yml")
	})
	require.NoError(t, composerSpecErr)
	return composerSpec
}

// validatingComposerHandler wraps an http.Handler and validates every
// POST /compose request body against the composer ComposeRequest schema.
func validatingComposerHandler(t *testing.T, inner http.Handler) http.Handler {
	t.Helper()
	spec := loadComposerSpec(t)
	schemaRef := spec.Components.Schemas["ComposeRequest"]

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/compose") {
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			r.Body = io.NopCloser(bytes.NewReader(body))

			var raw any
			require.NoError(t, json.Unmarshal(body, &raw))
			err = schemaRef.Value.VisitJSON(raw)
			require.NoError(t, err, "composer ComposeRequest schema validation failed:\n%s", body)
		}
		inner.ServeHTTP(w, r)
	})
}
