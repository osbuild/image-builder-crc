package v1_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/osbuild/image-builder-crc/internal/tutils"
	v1 "github.com/osbuild/image-builder-crc/internal/v1"
)

func TestHandlers_BlueprintRuleChecking(t *testing.T) {
	_, srvURL, shutdownFn := makeTestServer(t, nil)
	defer shutdownFn(t)

	// Test cases structure
	testCases := []struct {
		name                 string
		customizations       map[string]any
		expectError          bool
		errorTitle           string
		expectMultipleErrors bool
		expectedErrorCount   int
		expectedErrors       []v1.HTTPError
	}{
		// Files - Positive cases
		{
			name: "valid file customization - simple",
			customizations: map[string]any{
				"files": []map[string]any{
					{"path": "/etc/myconfig.conf", "data": "config content"},
				},
			},
			expectError: false,
		},
		{
			name: "valid file customization - with mode and user",
			customizations: map[string]any{
				"files": []map[string]any{
					{
						"path":  "/opt/app/config.json",
						"data":  `{"key": "value"}`,
						"mode":  "644",
						"user":  "root",
						"group": "root",
					},
				},
			},
			expectError: false,
		},
		// Files - Negative cases
		{
			name: "invalid file path - relative",
			customizations: map[string]any{
				"files": []map[string]any{
					{"path": "config.txt", "data": "content"},
				},
			},
			expectError: true,
			errorTitle:  "file rule violation",
		},
		{
			name: "invalid file path - trailing slash",
			customizations: map[string]any{
				"files": []map[string]any{
					{"path": "/etc/config/", "data": "content"},
				},
			},
			expectError: true,
			errorTitle:  "file rule violation",
		},
		{
			name: "invalid file path - restricted system path /usr/share",
			customizations: map[string]any{
				"files": []map[string]any{
					{"path": "/usr/share/nginx/html/index.html", "data": "Hello World"},
				},
			},
			expectError: true,
			errorTitle:  "file rule violation",
		},
		{
			name: "invalid file path - restricted /usr (but /usr/local allowed)",
			customizations: map[string]any{
				"files": []map[string]any{
					{"path": "/usr/bin/myapp", "data": "#!/bin/bash"},
				},
			},
			expectError: true,
			errorTitle:  "file rule violation",
		},
		{
			name: "valid file path - /usr/local is allowed",
			customizations: map[string]any{
				"files": []map[string]any{
					{"path": "/usr/local/bin/myapp", "data": "#!/bin/bash"},
				},
			},
			expectError: false,
		},
		// Directories - Positive cases
		{
			name: "valid directory customization - simple",
			customizations: map[string]any{
				"directories": []map[string]any{
					{"path": "/opt/myapp"},
				},
			},
			expectError: false,
		},
		{
			name: "valid directory customization - with mode and ensure_parents",
			customizations: map[string]any{
				"directories": []map[string]any{
					{
						"path":           "/var/lib/myservice",
						"mode":           "755",
						"user":           "service",
						"group":          "service",
						"ensure_parents": true,
					},
				},
			},
			expectError: false,
		},
		// Directories - Negative cases
		{
			name: "invalid directory path - relative",
			customizations: map[string]any{
				"directories": []map[string]any{
					{"path": "mydir"},
				},
			},
			expectError: true,
			errorTitle:  "directory rule violation",
		},
		{
			name: "invalid directory path - trailing slash",
			customizations: map[string]any{
				"directories": []map[string]any{
					{"path": "/opt/myapp/"},
				},
			},
			expectError: true,
			errorTitle:  "directory rule violation",
		},
		// Filesystem - Positive cases
		{
			name: "valid filesystem customization - root",
			customizations: map[string]any{
				"filesystem": []map[string]any{
					{"mountpoint": "/", "min_size": 10737418240}, // 10GB
				},
			},
			expectError: false,
		},
		{
			name: "valid filesystem customization - var with size",
			customizations: map[string]any{
				"filesystem": []map[string]any{
					{"mountpoint": "/var", "min_size": 5368709120}, // 5GB
				},
			},
			expectError: false,
		},
		// Filesystem - Negative cases
		{
			name: "invalid filesystem mountpoint - relative",
			customizations: map[string]any{
				"filesystem": []map[string]any{
					{"mountpoint": "var", "min_size": 1073741824},
				},
			},
			expectError: true,
			errorTitle:  "filesystem rule violation",
		},
		{
			name: "invalid filesystem mountpoint - non-canonical",
			customizations: map[string]any{
				"filesystem": []map[string]any{
					{"mountpoint": "/var/../tmp", "min_size": 1073741824},
				},
			},
			expectError: true,
			errorTitle:  "filesystem rule violation",
		},
		{
			name: "invalid filesystem min_size - too small",
			customizations: map[string]any{
				"filesystem": []map[string]any{
					{"mountpoint": "/var", "min_size": 512}, // 512 bytes, less than 1MB
				},
			},
			expectError: true,
			errorTitle:  "filesystem rule violation",
		},
		// Multiple violations - test that all violations are collected and returned
		{
			name: "multiple file violations - two invalid files",
			customizations: map[string]any{
				"files": []map[string]any{
					{"path": "relative.txt", "data": "content"}, // relative path
					{"path": "/etc/config/", "data": "content"}, // trailing slash
				},
			},
			expectError:          true,
			expectMultipleErrors: true,
			expectedErrorCount:   2,
			expectedErrors: []v1.HTTPError{
				{
					Title:  "file rule violation",
					Detail: `file "relative.txt": path "relative.txt" must be absolute`,
				},
				{
					Title:  "file rule violation",
					Detail: `file "/etc/config/": path "/etc/config/" must be canonical`,
				},
			},
		},
		{
			name: "multiple violations across different types",
			customizations: map[string]any{
				"files": []map[string]any{
					{"path": "badfile.txt", "data": "content"}, // relative path
				},
				"directories": []map[string]any{
					{"path": "baddir"}, // relative path
				},
				"filesystem": []map[string]any{
					{"mountpoint": "var", "min_size": 1073741824}, // relative mountpoint
				},
			},
			expectError:          true,
			expectMultipleErrors: true,
			expectedErrorCount:   3,
			expectedErrors: []v1.HTTPError{
				{
					Title:  "file rule violation",
					Detail: `file "badfile.txt": path "badfile.txt" must be absolute`,
				},
				{
					Title:  "directory rule violation",
					Detail: `directory "baddir": path "baddir" must be absolute`,
				},
				{
					Title:  "filesystem rule violation",
					Detail: `mountpoint "var" must be absolute`,
				},
			},
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create blueprint request with test customizations
			body := map[string]any{
				"name":           fmt.Sprintf("test-blueprint-%d", time.Now().UnixNano()),
				"description":    "Test blueprint for rule checking",
				"customizations": tc.customizations,
				"distribution":   "centos-9",
				"image_requests": []map[string]any{
					{
						"architecture": "x86_64",
						"image_type":   "aws",
						"upload_request": map[string]any{
							"type": "aws",
							"options": map[string]any{
								"share_with_accounts": []string{"test-account"},
							},
						},
					},
				},
			}

			statusCode, resp := tutils.PostResponseBody(t, srvURL+"/api/image-builder/v1/blueprints", body)

			if tc.expectError {
				// Should return rule violation error
				require.Equal(t, http.StatusUnprocessableEntity, statusCode)

				var jsonResp v1.HTTPErrorList
				err := json.Unmarshal([]byte(resp), &jsonResp)
				require.NoError(t, err)
				require.NotEmpty(t, jsonResp.Errors)

				if tc.expectMultipleErrors {
					require.Equal(t, tc.expectedErrorCount, len(jsonResp.Errors))

					// If expectedErrors is specified, check each error in detail
					if len(tc.expectedErrors) > 0 {
						require.Equal(t, len(tc.expectedErrors), len(jsonResp.Errors))
						for i, expectedError := range tc.expectedErrors {
							require.Equal(t, expectedError.Title, jsonResp.Errors[i].Title)
							require.Equal(t, expectedError.Detail, jsonResp.Errors[i].Detail)
						}
					} else {
						// For multiple errors without specific expectations, verify all are rule violations
						for _, error := range jsonResp.Errors {
							require.NotEmpty(t, error.Title)
							require.NotEmpty(t, error.Detail)
						}
					}
				} else {
					require.Equal(t, tc.errorTitle, jsonResp.Errors[0].Title)
				}
			} else {
				// Should succeed
				require.Equal(t, http.StatusCreated, statusCode)

				var result v1.CreateBlueprintResponse
				err := json.Unmarshal([]byte(resp), &result)
				require.NoError(t, err)
				require.NotEmpty(t, result.Id)
			}
		})
	}
}
