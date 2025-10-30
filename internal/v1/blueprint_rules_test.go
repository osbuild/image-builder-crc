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
		name           string
		customizations map[string]interface{}
		expectError    bool
		errorTitle     string
	}{
		// Files - Positive cases
		{
			name: "valid file customization - simple",
			customizations: map[string]interface{}{
				"files": []map[string]interface{}{
					{"path": "/etc/myconfig.conf", "data": "config content"},
				},
			},
			expectError: false,
		},
		{
			name: "valid file customization - with mode and user",
			customizations: map[string]interface{}{
				"files": []map[string]interface{}{
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
			customizations: map[string]interface{}{
				"files": []map[string]interface{}{
					{"path": "config.txt", "data": "content"},
				},
			},
			expectError: true,
			errorTitle:  "File rule violation",
		},
		{
			name: "invalid file path - trailing slash",
			customizations: map[string]interface{}{
				"files": []map[string]interface{}{
					{"path": "/etc/config/", "data": "content"},
				},
			},
			expectError: true,
			errorTitle:  "File rule violation",
		},
		// Directories - Positive cases
		{
			name: "valid directory customization - simple",
			customizations: map[string]interface{}{
				"directories": []map[string]interface{}{
					{"path": "/opt/myapp"},
				},
			},
			expectError: false,
		},
		{
			name: "valid directory customization - with mode and ensure_parents",
			customizations: map[string]interface{}{
				"directories": []map[string]interface{}{
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
			customizations: map[string]interface{}{
				"directories": []map[string]interface{}{
					{"path": "mydir"},
				},
			},
			expectError: true,
			errorTitle:  "Directory rule violation",
		},
		{
			name: "invalid directory path - trailing slash",
			customizations: map[string]interface{}{
				"directories": []map[string]interface{}{
					{"path": "/opt/myapp/"},
				},
			},
			expectError: true,
			errorTitle:  "Directory rule violation",
		},
		// Filesystem - Positive cases
		{
			name: "valid filesystem customization - root",
			customizations: map[string]interface{}{
				"filesystem": []map[string]interface{}{
					{"mountpoint": "/", "min_size": 10737418240}, // 10GB
				},
			},
			expectError: false,
		},
		{
			name: "valid filesystem customization - var with size",
			customizations: map[string]interface{}{
				"filesystem": []map[string]interface{}{
					{"mountpoint": "/var", "min_size": 5368709120}, // 5GB
				},
			},
			expectError: false,
		},
		// Filesystem - Negative cases
		{
			name: "invalid filesystem mountpoint - relative",
			customizations: map[string]interface{}{
				"filesystem": []map[string]interface{}{
					{"mountpoint": "var", "min_size": 1073741824},
				},
			},
			expectError: true,
			errorTitle:  "Filesystem rule violation",
		},
		{
			name: "invalid filesystem mountpoint - non-canonical",
			customizations: map[string]interface{}{
				"filesystem": []map[string]interface{}{
					{"mountpoint": "/var/../tmp", "min_size": 1073741824},
				},
			},
			expectError: true,
			errorTitle:  "Filesystem rule violation",
		},
		{
			name: "invalid filesystem min_size - too small",
			customizations: map[string]interface{}{
				"filesystem": []map[string]interface{}{
					{"mountpoint": "/var", "min_size": 512}, // 512 bytes, less than 1MB
				},
			},
			expectError: true,
			errorTitle:  "Filesystem rule violation",
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create blueprint request with test customizations
			body := map[string]interface{}{
				"name":           fmt.Sprintf("test-blueprint-%d", time.Now().UnixNano()),
				"description":    "Test blueprint for rule checking",
				"customizations": tc.customizations,
				"distribution":   "centos-9",
				"image_requests": []map[string]interface{}{
					{
						"architecture": "x86_64",
						"image_type":   "aws",
						"upload_request": map[string]interface{}{
							"type": "aws",
							"options": map[string]interface{}{
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
				require.Equal(t, tc.errorTitle, jsonResp.Errors[0].Title)
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
