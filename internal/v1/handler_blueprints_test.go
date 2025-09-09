package v1_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/osbuild/image-builder-crc/internal/clients/composer"
	"github.com/osbuild/image-builder-crc/internal/clients/content_sources"
	"github.com/osbuild/image-builder-crc/internal/common"
	"github.com/osbuild/image-builder-crc/internal/db"
	"github.com/osbuild/image-builder-crc/internal/tutils"
	v1 "github.com/osbuild/image-builder-crc/internal/v1"
	"github.com/osbuild/image-builder-crc/internal/v1/mocks"
)

type BlueprintExportResponseUnmarshal struct {
	ContentSources []content_sources.ApiRepositoryExportResponse `json:"content_sources,omitempty"`
	Customizations v1.Customizations                             `json:"customizations"`
	Description    string                                        `json:"description"`
	Distribution   v1.Distributions                              `json:"distribution"`
	Metadata       v1.BlueprintMetadata                          `json:"metadata"`
	Name           string                                        `json:"name"`
	SnapshotDate   *string                                       `json:"snapshot_date,omitempty"`
}

func makeTestServer(t *testing.T, apiSrv *string) (dbase db.DB, srvURL string, shutdown func(t *testing.T)) {
	srv := startServer(t, &testServerClientsConf{
		ComposerURL: func() string {
			if apiSrv != nil {
				return *apiSrv
			}
			return ""
		}(),
	}, &v1.ServerConfig{
		DBase:            dbase,
		DistributionsDir: "../../distributions",
		CSReposURL:       "https://content-sources.org",
	})

	return srv.DB, srv.URL, func(t *testing.T) {
		srv.Shutdown(t)
	}
}

func TestHandlers_CreateBlueprint(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("crypt() not supported on darwin")
	}

	var jsonResp v1.HTTPErrorList
	ctx := context.Background()
	dbase, srvURL, shutdownFn := makeTestServer(t, nil)
	defer shutdownFn(t)

	body := map[string]interface{}{
		"name":        "Blueprint",
		"description": "desc",
		"customizations": map[string]interface{}{
			"packages": []string{"nginx"},
			"users": []map[string]interface{}{
				{"name": "user", "password": "test"},
				{"name": "user2", "ssh_key": "ssh-rsa AAAAB3NzaC1"},
			},
			"aap_registration": map[string]interface{}{
				"ansible_callback_url":      "https://aap-gw.example.com/api/controller/v2/job_templates/42/callback/",
				"host_config_key":           "test-host-config-key-12345",
				"tls_certificate_authority": "-----BEGIN CERTIFICATE-----\nMIIC0DCCAbigAwIBAgIUI...\n-----END CERTIFICATE-----",
				"skip_tls_verification":     false,
			},
		},
		"distribution": "centos-9",
		"image_requests": []map[string]interface{}{
			{
				"architecture":     "x86_64",
				"image_type":       "aws",
				"upload_request":   map[string]interface{}{"type": "aws", "options": map[string]interface{}{"share_with_accounts": []string{"test-account"}}},
				"content_template": mocks.TemplateID,
			},
		},
	}
	statusCodePost, respPost := tutils.PostResponseBody(t, srvURL+"/api/image-builder/v1/blueprints", body)
	require.Equal(t, http.StatusCreated, statusCodePost)

	var result v1.CreateBlueprintResponse
	err := json.Unmarshal([]byte(respPost), &result)
	require.NoError(t, err)

	be, err := dbase.GetBlueprint(ctx, result.Id, "000000", nil)
	require.NoError(t, err)
	require.Nil(t, be.Metadata)

	blueprint, err := v1.BlueprintFromEntry(be)
	require.NoError(t, err)
	require.NotNil(t, blueprint.Customizations.AAPRegistration)
	require.Equal(t, "https://aap-gw.example.com/api/controller/v2/job_templates/42/callback/", blueprint.Customizations.AAPRegistration.AnsibleCallbackUrl)
	require.Equal(t, "test-host-config-key-12345", blueprint.Customizations.AAPRegistration.HostConfigKey)
	require.Equal(t, "-----BEGIN CERTIFICATE-----\nMIIC0DCCAbigAwIBAgIUI...\n-----END CERTIFICATE-----", blueprint.Customizations.AAPRegistration.TlsCertificateAuthority)
	require.NotNil(t, blueprint.Customizations.AAPRegistration.SkipTlsVerification)
	require.False(t, *blueprint.Customizations.AAPRegistration.SkipTlsVerification)

	// Test unique name constraint
	statusCode, resp := tutils.PostResponseBody(t, srvURL+"/api/image-builder/v1/blueprints", body)
	require.Equal(t, http.StatusUnprocessableEntity, statusCode)
	err = json.Unmarshal([]byte(resp), &jsonResp)
	require.NoError(t, err)
	require.Equal(t, "Name not unique", jsonResp.Errors[0].Title)

	// Test non empty name constraint
	body["name"] = ""
	statusCode, resp = tutils.PostResponseBody(t, srvURL+"/api/image-builder/v1/blueprints", body)
	require.Equal(t, http.StatusUnprocessableEntity, statusCode)
	err = json.Unmarshal([]byte(resp), &jsonResp)
	require.NoError(t, err)
	require.Equal(t, "Invalid blueprint name", jsonResp.Errors[0].Title)

	// Test the content template ID was saved to the blueprint
	blueprintResp, err := v1.BlueprintFromEntry(be)
	require.NoError(t, err)
	require.Equal(t, *blueprintResp.ImageRequests[0].ContentTemplate, mocks.TemplateID)
}

func TestUser_MergeForUpdate(t *testing.T) {
	tests := []struct {
		name          string
		newUser       v1.User
		existingUsers []v1.User
		wantPass      *string
		wantSsh       *string
		wantErr       bool
	}{
		{
			name: "Both password and ssh_key are provided, no need to fetch user from DB",
			newUser: v1.User{
				Name:     "test",
				Password: common.ToPtr("password"),
				SshKey:   common.ToPtr("ssh key"),
			},
			existingUsers: []v1.User{},
			wantPass:      common.ToPtr("password"),
			wantSsh:       common.ToPtr("ssh key"),
			wantErr:       false,
		},
		{
			name: "User found in DB, merge should keep new values",
			newUser: v1.User{
				Name:     "test",
				Password: common.ToPtr("password"),
				SshKey:   common.ToPtr("ssh key"),
			},
			existingUsers: []v1.User{
				{
					Name:     "test",
					Password: common.ToPtr("old password"),
					SshKey:   common.ToPtr("old ssh key"),
				},
			},
			wantPass: common.ToPtr("password"),
			wantSsh:  common.ToPtr("ssh key"),
			wantErr:  false,
		},
		{
			name: "New user, empty password set to nil",
			newUser: v1.User{
				Name:     "test",
				Password: common.ToPtr(""),
				SshKey:   common.ToPtr("ssh key"),
			},
			existingUsers: []v1.User{},
			wantPass:      nil,
			wantSsh:       common.ToPtr("ssh key"),
			wantErr:       false,
		},
		{
			name: "Existing user, empty password set to nil = change to only 'ssh key' user",
			newUser: v1.User{
				Name:     "test",
				Password: common.ToPtr(""),
				SshKey:   common.ToPtr("ssh key"),
			},
			existingUsers: []v1.User{
				{
					Name:     "test",
					Password: common.ToPtr("old password"),
					SshKey:   nil,
				},
			},
			wantPass: nil,
			wantSsh:  common.ToPtr("ssh key"),
			wantErr:  false,
		},
		{
			name: "New user, empty ssh_key set to nil",
			newUser: v1.User{
				Name:     "test",
				Password: common.ToPtr("password"),
				SshKey:   common.ToPtr(""),
			},
			existingUsers: []v1.User{},
			wantPass:      common.ToPtr("password"),
			wantSsh:       nil,
			wantErr:       false,
		},
		{
			name: "Existing user, empty ssh key set to nil = change to 'password' user",
			newUser: v1.User{
				Name:     "test",
				Password: common.ToPtr("password"),
				SshKey:   common.ToPtr(""),
			},
			existingUsers: []v1.User{
				{
					Name:     "test",
					Password: nil,
					SshKey:   common.ToPtr("old ssh key"),
				},
			},
			wantPass: common.ToPtr("password"),
			wantSsh:  nil,
			wantErr:  false,
		},
		{
			name: "Both password and ssh_key are empty, valid",
			newUser: v1.User{
				Name:     "test",
				Password: common.ToPtr(""),
				SshKey:   common.ToPtr(""),
			},
			existingUsers: []v1.User{},
			wantPass:      nil,
			wantSsh:       nil,
			wantErr:       false,
		},
		{
			name: "Both password and ssh_key are nil, no existing user, valid",
			newUser: v1.User{
				Name: "test",
			},
			existingUsers: []v1.User{},
			wantPass:      nil,
			wantSsh:       nil,
			wantErr:       false,
		},
		{
			name: "Both password and ssh_key are nil, existing user, keep old values",
			newUser: v1.User{
				Name: "test",
			},
			existingUsers: []v1.User{
				{
					Name:     "test",
					Password: common.ToPtr("old password"),
					SshKey:   common.ToPtr("old ssh key"),
				},
			},
			wantPass: common.ToPtr("old password"),
			wantSsh:  common.ToPtr("old ssh key"),
			wantErr:  false,
		},
		{
			name: "Empty password, existing user only with password",
			newUser: v1.User{
				Name:     "test",
				Password: common.ToPtr(""),
				SshKey:   nil,
			},
			existingUsers: []v1.User{
				{
					Name:     "test",
					Password: common.ToPtr("old password"),
					SshKey:   nil,
				},
			},
			wantPass: nil,
			wantSsh:  nil,
			wantErr:  false,
		},
		{
			name: "Empty ssh key, existing user only with ssh key",
			newUser: v1.User{
				Name:     "test",
				SshKey:   common.ToPtr(""),
				Password: nil,
			},
			existingUsers: []v1.User{
				{
					Name:     "test",
					Password: nil,
					SshKey:   common.ToPtr("old ssh key"),
				},
			},
			wantPass: nil,
			wantSsh:  nil,
			wantErr:  false,
		},
		{
			name: "Add new user to one already existing user",
			newUser: v1.User{
				Name:     "test2",
				SshKey:   nil,
				Password: nil,
			},
			existingUsers: []v1.User{
				{
					Name:     "test",
					SshKey:   common.ToPtr("old password"),
					Password: nil,
				},
			},
			wantPass: nil,
			wantSsh:  nil,
			wantErr:  false,
		},
		{
			name: "Add new user to one already existing user",
			newUser: v1.User{
				Name:     "test2",
				SshKey:   common.ToPtr("ssh key"),
				Password: nil,
			},
			existingUsers: []v1.User{
				{
					Name:     "test",
					SshKey:   common.ToPtr("old password"),
					Password: nil,
				},
			},
			wantPass: nil,
			wantSsh:  common.ToPtr("ssh key"),
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.newUser.MergeForUpdate(tt.existingUsers)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.wantPass, tt.newUser.Password)
				require.Equal(t, tt.wantSsh, tt.newUser.SshKey)
			}
		})
	}
}

func TestHandlers_UpdateBlueprint_CustomizationUser(t *testing.T) {
	dbase, srvURL, shutdownFn := makeTestServer(t, nil)
	defer shutdownFn(t)

	ctx := context.Background()
	body := map[string]interface{}{
		"name":           "Blueprint",
		"description":    "desc",
		"customizations": map[string]interface{}{},
		"distribution":   "centos-9",
		"image_requests": []map[string]interface{}{
			{
				"architecture":   "x86_64",
				"image_type":     "aws",
				"upload_request": map[string]interface{}{"type": "aws", "options": map[string]interface{}{"share_with_accounts": []string{"test-account"}}},
			},
		},
	}

	var result v1.ComposeResponse

	// No users in the blueprint = SUCCESS
	statusCode, responseBody := tutils.PostResponseBody(t, srvURL+"/api/image-builder/v1/blueprints", body)
	require.Equal(t, http.StatusCreated, statusCode)
	err := json.Unmarshal([]byte(responseBody), &result)
	require.NoError(t, err)

	// Add new user with password = SUCCESS
	body["customizations"] = map[string]interface{}{"users": []map[string]interface{}{{"name": "test", "password": "test"}}}
	statusCode, _ = tutils.PutResponseBody(t, fmt.Sprintf("%s/api/image-builder/v1/blueprints/%s", srvURL, result.Id), body)
	require.Equal(t, http.StatusCreated, statusCode)

	blueprintEntry, err := dbase.GetBlueprint(ctx, result.Id, "000000", nil)
	require.NoError(t, err)
	updatedBlueprint, err := v1.BlueprintFromEntry(blueprintEntry)
	require.NoError(t, err)
	require.NotEmpty(t, (*updatedBlueprint.Customizations.Users)[0].Password) // hashed, can't compare with plaintext value
	require.Nil(t, (*updatedBlueprint.Customizations.Users)[0].SshKey)

	// Update with hashed password = SUCCESS
	userHashedPassword := "$6$foo"
	body["customizations"] = map[string]interface{}{"users": []map[string]interface{}{{"name": "test", "password": userHashedPassword}}}
	statusCode, _ = tutils.PutResponseBody(t, fmt.Sprintf("%s/api/image-builder/v1/blueprints/%s", srvURL, result.Id), body)
	require.Equal(t, http.StatusCreated, statusCode)

	blueprintEntry, err = dbase.GetBlueprint(ctx, result.Id, "000000", nil)
	require.NoError(t, err)
	updatedBlueprint, err = v1.BlueprintFromEntry(blueprintEntry)
	require.NoError(t, err)

	existingPassword := (*updatedBlueprint.Customizations.Users)[0].Password
	require.NotNil(t, existingPassword)
	require.Equal(t, userHashedPassword, *existingPassword)
	require.Nil(t, (*updatedBlueprint.Customizations.Users)[0].SshKey)
	// keep ssh key and remove password = SUCCESS
	body["customizations"] = map[string]interface{}{"users": []map[string]interface{}{{"name": "test", "password": ""}}}
	statusCode, _ = tutils.PutResponseBody(t, fmt.Sprintf("http://localhost:8086/api/image-builder/v1/blueprints/%s", result.Id), body)
	require.Equal(t, http.StatusCreated, statusCode)

	// add ssh key and remove password = SUCCESS
	body["customizations"] = map[string]interface{}{"users": []map[string]interface{}{{"name": "test", "password": "", "ssh_key": "ssh key"}}}
	statusCode, _ = tutils.PutResponseBody(t, fmt.Sprintf("%s/api/image-builder/v1/blueprints/%s", srvURL, result.Id), body)
	require.Equal(t, http.StatusCreated, statusCode)

	blueprintEntry, err = dbase.GetBlueprint(ctx, result.Id, "000000", nil)
	require.NoError(t, err)

	updatedBlueprint, err = v1.BlueprintFromEntry(
		blueprintEntry,
		v1.WithRedactedPasswords(),
	)
	require.NoError(t, err)
	require.Nil(t, (*updatedBlueprint.Customizations.Users)[0].Password)

	updatedBlueprint, err = v1.BlueprintFromEntry(blueprintEntry)
	require.NoError(t, err)
	sshKey := (*updatedBlueprint.Customizations.Users)[0].SshKey
	require.NotNil(t, sshKey)
	require.Equal(t, "ssh key", *sshKey)
	require.Nil(t, (*updatedBlueprint.Customizations.Users)[0].Password)

	// add new user without password or ssh_key = SUCCESS
	users := []map[string]any{
		{"name": "test"},
		{"name": "test2"},
	}
	body["customizations"] = map[string]any{"users": users}
	statusCode, _ = tutils.PutResponseBody(t, fmt.Sprintf("%s/api/image-builder/v1/blueprints/%s", srvURL, result.Id), body)
	require.Equal(t, http.StatusCreated, statusCode)

	// add new user with password and ssh_key = SUCCESS
	users = []map[string]any{
		{"name": "test"}, // keep old values
		{"name": "test2", "password": "test", "ssh_key": "ssh key"},
	}
	body["customizations"] = map[string]any{"users": users}
	statusCode, _ = tutils.PutResponseBody(t, fmt.Sprintf("%s/api/image-builder/v1/blueprints/%s", srvURL, result.Id), body)
	require.Equal(t, http.StatusCreated, statusCode)

	blueprintEntry, err = dbase.GetBlueprint(ctx, result.Id, "000000", nil)
	require.NoError(t, err)
	updatedBlueprint, err = v1.BlueprintFromEntry(blueprintEntry)
	require.NoError(t, err)
	require.Len(t, *updatedBlueprint.Customizations.Users, 2)
	user1 := (*updatedBlueprint.Customizations.Users)[0]
	require.NotNil(t, user1.SshKey)
	require.Equal(t, "ssh key", *user1.SshKey)
	require.Nil(t, user1.Password)

	user2 := (*updatedBlueprint.Customizations.Users)[1]
	require.Equal(t, "test2", user2.Name)
	require.NotNil(t, user2.Password)
	require.NotNil(t, user2.SshKey)
}

func TestHandlers_UpdateBlueprint(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("crypt() not supported on darwin")
	}

	var jsonResp v1.HTTPErrorList
	_, srvURL, shutdownFn := makeTestServer(t, nil)
	defer shutdownFn(t)

	body := map[string]interface{}{
		"name":           "Blueprint",
		"description":    "desc",
		"customizations": map[string]interface{}{"packages": []string{"nginx"}},
		"distribution":   "centos-9",
		"image_requests": []map[string]interface{}{
			{
				"architecture":   "x86_64",
				"image_type":     "aws",
				"upload_request": map[string]interface{}{"type": "aws", "options": map[string]interface{}{"share_with_accounts": []string{"test-account"}}},
			},
		},
	}
	statusCode, resp := tutils.PostResponseBody(t, srvURL+"/api/image-builder/v1/blueprints", body)
	require.Equal(t, http.StatusCreated, statusCode)
	var result v1.ComposeResponse
	err := json.Unmarshal([]byte(resp), &result)
	require.NoError(t, err)

	// Test non empty name constraint
	body["name"] = ""
	statusCode, resp = tutils.PutResponseBody(t, srvURL+fmt.Sprintf("/api/image-builder/v1/blueprints/%s", result.Id), body)
	require.Equal(t, http.StatusUnprocessableEntity, statusCode)
	err = json.Unmarshal([]byte(resp), &jsonResp)
	require.NoError(t, err)
	require.Equal(t, "Invalid blueprint name", jsonResp.Errors[0].Title)

	// Test non-existing blueprint
	body["name"] = "Changing to correct body"
	respStatusCodeNotFound, _ := tutils.PutResponseBody(t, srvURL+fmt.Sprintf("/api/image-builder/v1/blueprints/%s", uuid.New()), body)
	require.Equal(t, http.StatusNotFound, respStatusCodeNotFound)

	body["customizations"] = map[string]interface{}{"users": []map[string]interface{}{{"name": "test", "password": "test"}}}
	statusCode, _ = tutils.PutResponseBody(t, srvURL+fmt.Sprintf("/api/image-builder/v1/blueprints/%s", uuid.New()), body)
	require.Equal(t, http.StatusNotFound, statusCode)
}

func TestHandlers_ComposeBlueprint(t *testing.T) {
	ctx := context.Background()

	composeRequests := []composer.ComposeRequest{}
	ids := []uuid.UUID{}
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		newId := uuid.New()
		if r.Header.Get("Authorization") == "Bearer" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		require.Equal(t, "Bearer accesstoken", r.Header.Get("Authorization"))

		var creq composer.ComposeRequest
		err := json.NewDecoder(r.Body).Decode(&creq)
		require.NoError(t, err)
		composeRequests = append(composeRequests, creq)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)

		result := composer.ComposeId{
			Id: newId,
		}
		ids = append(ids, newId)
		encodeErr := json.NewEncoder(w).Encode(result)
		require.NoError(t, encodeErr)
	}))
	defer apiSrv.Close()

	srv := startServer(t, &testServerClientsConf{ComposerURL: apiSrv.URL}, nil)
	defer srv.Shutdown(t)

	id := uuid.New()
	versionId := uuid.New()

	uploadOptions := v1.UploadRequest_Options{}
	err := uploadOptions.FromAWSUploadRequestOptions(v1.AWSUploadRequestOptions{
		ShareWithAccounts: common.ToPtr([]string{"test-account"}),
	})
	require.NoError(t, err)
	name := "Blueprint Human Name"
	description := "desc"
	blueprint := v1.BlueprintBody{
		Customizations: v1.Customizations{
			Packages: common.ToPtr([]string{"nginx"}),
			Users: common.ToPtr([]v1.User{
				{
					Name:     "user1",
					Password: common.ToPtr("$6$password123"),
				},
				{
					Name:   "user2",
					SshKey: common.ToPtr("ssh-rsa AAAAB3NzaC1"),
				},
			}),
		},
		Distribution: "centos-9",
		ImageRequests: []v1.ImageRequest{
			{
				Architecture: v1.ImageRequestArchitectureX8664,
				ImageType:    v1.ImageTypesAws,
				UploadRequest: v1.UploadRequest{
					Type:    v1.UploadTypesAws,
					Options: uploadOptions,
				},
			},
			{
				Architecture: v1.ImageRequestArchitectureAarch64,
				ImageType:    v1.ImageTypesAws,
				UploadRequest: v1.UploadRequest{
					Type:    v1.UploadTypesAws,
					Options: uploadOptions,
				},
			},
			{
				Architecture: v1.ImageRequestArchitectureAarch64,
				ImageType:    v1.ImageTypesGuestImage,
				UploadRequest: v1.UploadRequest{
					Type:    v1.UploadTypesAwsS3,
					Options: uploadOptions,
				},
			},
		},
	}

	var message []byte
	message, err = json.Marshal(blueprint)
	require.NoError(t, err)
	err = srv.DB.InsertBlueprint(ctx, id, versionId, "000000", "000000", name, description, message, nil, nil)
	require.NoError(t, err)

	repos := []composer.Repository{
		{
			Baseurl:  common.ToPtr("http://mirror.stream.centos.org/9-stream/BaseOS/x86_64/os/"),
			CheckGpg: common.ToPtr(true),
			Gpgkey:   common.ToPtr("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQINBFzMWxkBEADHrskpBgN9OphmhRkc7P/YrsAGSvvl7kfu+e9KAaU6f5MeAVyn\nrIoM43syyGkgFyWgjZM8/rur7EMPY2yt+2q/1ZfLVCRn9856JqTIq0XRpDUe4nKQ\n8BlA7wDVZoSDxUZkSuTIyExbDf0cpw89Tcf62Mxmi8jh74vRlPy1PgjWL5494b3X\n5fxDidH4bqPZyxTBqPrUFuo+EfUVEqiGF94Ppq6ZUvrBGOVo1V1+Ifm9CGEK597c\naevcGc1RFlgxIgN84UpuDjPR9/zSndwJ7XsXYvZ6HXcKGagRKsfYDWGPkA5cOL/e\nf+yObOnC43yPUvpggQ4KaNJ6+SMTZOKikM8yciyBwLqwrjo8FlJgkv8Vfag/2UR7\nJINbyqHHoLUhQ2m6HXSwK4YjtwidF9EUkaBZWrrskYR3IRZLXlWqeOi/+ezYOW0m\nvufrkcvsh+TKlVVnuwmEPjJ8mwUSpsLdfPJo1DHsd8FS03SCKPaXFdD7ePfEjiYk\nnHpQaKE01aWVSLUiygn7F7rYemGqV9Vt7tBw5pz0vqSC72a5E3zFzIIuHx6aANry\nGat3aqU3qtBXOrA/dPkX9cWE+UR5wo/A2UdKJZLlGhM2WRJ3ltmGT48V9CeS6N9Y\nm4CKdzvg7EWjlTlFrd/8WJ2KoqOE9leDPeXRPncubJfJ6LLIHyG09h9kKQARAQAB\ntDpDZW50T1MgKENlbnRPUyBPZmZpY2lhbCBTaWduaW5nIEtleSkgPHNlY3VyaXR5\nQGNlbnRvcy5vcmc+iQI3BBMBAgAhBQJczFsZAhsDBgsJCAcDAgYVCAIJCgsDFgIB\nAh4BAheAAAoJEAW1VbOEg8ZdjOsP/2ygSxH9jqffOU9SKyJDlraL2gIutqZ3B8pl\nGy/Qnb9QD1EJVb4ZxOEhcY2W9VJfIpnf3yBuAto7zvKe/G1nxH4Bt6WTJQCkUjcs\nN3qPWsx1VslsAEz7bXGiHym6Ay4xF28bQ9XYIokIQXd0T2rD3/lNGxNtORZ2bKjD\nvOzYzvh2idUIY1DgGWJ11gtHFIA9CvHcW+SMPEhkcKZJAO51ayFBqTSSpiorVwTq\na0cB+cgmCQOI4/MY+kIvzoexfG7xhkUqe0wxmph9RQQxlTbNQDCdaxSgwbF2T+gw\nbyaDvkS4xtR6Soj7BKjKAmcnf5fn4C5Or0KLUqMzBtDMbfQQihn62iZJN6ZZ/4dg\nq4HTqyVpyuzMXsFpJ9L/FqH2DJ4exGGpBv00ba/Zauy7GsqOc5PnNBsYaHCply0X\n407DRx51t9YwYI/ttValuehq9+gRJpOTTKp6AjZn/a5Yt3h6jDgpNfM/EyLFIY9z\nV6CXqQQ/8JRvaik/JsGCf+eeLZOw4koIjZGEAg04iuyNTjhx0e/QHEVcYAqNLhXG\nrCTTbCn3NSUO9qxEXC+K/1m1kaXoCGA0UWlVGZ1JSifbbMx0yxq/brpEZPUYm+32\no8XfbocBWljFUJ+6aljTvZ3LQLKTSPW7TFO+GXycAOmCGhlXh2tlc6iTc41PACqy\nyy+mHmSv\n=kkH7\n-----END PGP PUBLIC KEY BLOCK-----\n"),
			Rhsm:     common.ToPtr(false),
		},
		{
			Baseurl:  common.ToPtr("http://mirror.stream.centos.org/9-stream/AppStream/x86_64/os/"),
			CheckGpg: common.ToPtr(true),
			Gpgkey:   common.ToPtr("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQINBFzMWxkBEADHrskpBgN9OphmhRkc7P/YrsAGSvvl7kfu+e9KAaU6f5MeAVyn\nrIoM43syyGkgFyWgjZM8/rur7EMPY2yt+2q/1ZfLVCRn9856JqTIq0XRpDUe4nKQ\n8BlA7wDVZoSDxUZkSuTIyExbDf0cpw89Tcf62Mxmi8jh74vRlPy1PgjWL5494b3X\n5fxDidH4bqPZyxTBqPrUFuo+EfUVEqiGF94Ppq6ZUvrBGOVo1V1+Ifm9CGEK597c\naevcGc1RFlgxIgN84UpuDjPR9/zSndwJ7XsXYvZ6HXcKGagRKsfYDWGPkA5cOL/e\nf+yObOnC43yPUvpggQ4KaNJ6+SMTZOKikM8yciyBwLqwrjo8FlJgkv8Vfag/2UR7\nJINbyqHHoLUhQ2m6HXSwK4YjtwidF9EUkaBZWrrskYR3IRZLXlWqeOi/+ezYOW0m\nvufrkcvsh+TKlVVnuwmEPjJ8mwUSpsLdfPJo1DHsd8FS03SCKPaXFdD7ePfEjiYk\nnHpQaKE01aWVSLUiygn7F7rYemGqV9Vt7tBw5pz0vqSC72a5E3zFzIIuHx6aANry\nGat3aqU3qtBXOrA/dPkX9cWE+UR5wo/A2UdKJZLlGhM2WRJ3ltmGT48V9CeS6N9Y\nm4CKdzvg7EWjlTlFrd/8WJ2KoqOE9leDPeXRPncubJfJ6LLIHyG09h9kKQARAQAB\ntDpDZW50T1MgKENlbnRPUyBPZmZpY2lhbCBTaWduaW5nIEtleSkgPHNlY3VyaXR5\nQGNlbnRvcy5vcmc+iQI3BBMBAgAhBQJczFsZAhsDBgsJCAcDAgYVCAIJCgsDFgIB\nAh4BAheAAAoJEAW1VbOEg8ZdjOsP/2ygSxH9jqffOU9SKyJDlraL2gIutqZ3B8pl\nGy/Qnb9QD1EJVb4ZxOEhcY2W9VJfIpnf3yBuAto7zvKe/G1nxH4Bt6WTJQCkUjcs\nN3qPWsx1VslsAEz7bXGiHym6Ay4xF28bQ9XYIokIQXd0T2rD3/lNGxNtORZ2bKjD\nvOzYzvh2idUIY1DgGWJ11gtHFIA9CvHcW+SMPEhkcKZJAO51ayFBqTSSpiorVwTq\na0cB+cgmCQOI4/MY+kIvzoexfG7xhkUqe0wxmph9RQQxlTbNQDCdaxSgwbF2T+gw\nbyaDvkS4xtR6Soj7BKjKAmcnf5fn4C5Or0KLUqMzBtDMbfQQihn62iZJN6ZZ/4dg\nq4HTqyVpyuzMXsFpJ9L/FqH2DJ4exGGpBv00ba/Zauy7GsqOc5PnNBsYaHCply0X\n407DRx51t9YwYI/ttValuehq9+gRJpOTTKp6AjZn/a5Yt3h6jDgpNfM/EyLFIY9z\nV6CXqQQ/8JRvaik/JsGCf+eeLZOw4koIjZGEAg04iuyNTjhx0e/QHEVcYAqNLhXG\nrCTTbCn3NSUO9qxEXC+K/1m1kaXoCGA0UWlVGZ1JSifbbMx0yxq/brpEZPUYm+32\no8XfbocBWljFUJ+6aljTvZ3LQLKTSPW7TFO+GXycAOmCGhlXh2tlc6iTc41PACqy\nyy+mHmSv\n=kkH7\n-----END PGP PUBLIC KEY BLOCK-----\n"),
			Rhsm:     common.ToPtr(false),
		},
	}
	reposAarch := []composer.Repository{
		{
			Baseurl:  common.ToPtr("http://mirror.stream.centos.org/9-stream/BaseOS/aarch64/os/"),
			CheckGpg: common.ToPtr(true),
			Gpgkey:   common.ToPtr("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQINBFzMWxkBEADHrskpBgN9OphmhRkc7P/YrsAGSvvl7kfu+e9KAaU6f5MeAVyn\nrIoM43syyGkgFyWgjZM8/rur7EMPY2yt+2q/1ZfLVCRn9856JqTIq0XRpDUe4nKQ\n8BlA7wDVZoSDxUZkSuTIyExbDf0cpw89Tcf62Mxmi8jh74vRlPy1PgjWL5494b3X\n5fxDidH4bqPZyxTBqPrUFuo+EfUVEqiGF94Ppq6ZUvrBGOVo1V1+Ifm9CGEK597c\naevcGc1RFlgxIgN84UpuDjPR9/zSndwJ7XsXYvZ6HXcKGagRKsfYDWGPkA5cOL/e\nf+yObOnC43yPUvpggQ4KaNJ6+SMTZOKikM8yciyBwLqwrjo8FlJgkv8Vfag/2UR7\nJINbyqHHoLUhQ2m6HXSwK4YjtwidF9EUkaBZWrrskYR3IRZLXlWqeOi/+ezYOW0m\nvufrkcvsh+TKlVVnuwmEPjJ8mwUSpsLdfPJo1DHsd8FS03SCKPaXFdD7ePfEjiYk\nnHpQaKE01aWVSLUiygn7F7rYemGqV9Vt7tBw5pz0vqSC72a5E3zFzIIuHx6aANry\nGat3aqU3qtBXOrA/dPkX9cWE+UR5wo/A2UdKJZLlGhM2WRJ3ltmGT48V9CeS6N9Y\nm4CKdzvg7EWjlTlFrd/8WJ2KoqOE9leDPeXRPncubJfJ6LLIHyG09h9kKQARAQAB\ntDpDZW50T1MgKENlbnRPUyBPZmZpY2lhbCBTaWduaW5nIEtleSkgPHNlY3VyaXR5\nQGNlbnRvcy5vcmc+iQI3BBMBAgAhBQJczFsZAhsDBgsJCAcDAgYVCAIJCgsDFgIB\nAh4BAheAAAoJEAW1VbOEg8ZdjOsP/2ygSxH9jqffOU9SKyJDlraL2gIutqZ3B8pl\nGy/Qnb9QD1EJVb4ZxOEhcY2W9VJfIpnf3yBuAto7zvKe/G1nxH4Bt6WTJQCkUjcs\nN3qPWsx1VslsAEz7bXGiHym6Ay4xF28bQ9XYIokIQXd0T2rD3/lNGxNtORZ2bKjD\nvOzYzvh2idUIY1DgGWJ11gtHFIA9CvHcW+SMPEhkcKZJAO51ayFBqTSSpiorVwTq\na0cB+cgmCQOI4/MY+kIvzoexfG7xhkUqe0wxmph9RQQxlTbNQDCdaxSgwbF2T+gw\nbyaDvkS4xtR6Soj7BKjKAmcnf5fn4C5Or0KLUqMzBtDMbfQQihn62iZJN6ZZ/4dg\nq4HTqyVpyuzMXsFpJ9L/FqH2DJ4exGGpBv00ba/Zauy7GsqOc5PnNBsYaHCply0X\n407DRx51t9YwYI/ttValuehq9+gRJpOTTKp6AjZn/a5Yt3h6jDgpNfM/EyLFIY9z\nV6CXqQQ/8JRvaik/JsGCf+eeLZOw4koIjZGEAg04iuyNTjhx0e/QHEVcYAqNLhXG\nrCTTbCn3NSUO9qxEXC+K/1m1kaXoCGA0UWlVGZ1JSifbbMx0yxq/brpEZPUYm+32\no8XfbocBWljFUJ+6aljTvZ3LQLKTSPW7TFO+GXycAOmCGhlXh2tlc6iTc41PACqy\nyy+mHmSv\n=kkH7\n-----END PGP PUBLIC KEY BLOCK-----\n"),
			Rhsm:     common.ToPtr(false),
		},
		{
			Baseurl:  common.ToPtr("http://mirror.stream.centos.org/9-stream/AppStream/aarch64/os/"),
			CheckGpg: common.ToPtr(true),
			Gpgkey:   common.ToPtr("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQINBFzMWxkBEADHrskpBgN9OphmhRkc7P/YrsAGSvvl7kfu+e9KAaU6f5MeAVyn\nrIoM43syyGkgFyWgjZM8/rur7EMPY2yt+2q/1ZfLVCRn9856JqTIq0XRpDUe4nKQ\n8BlA7wDVZoSDxUZkSuTIyExbDf0cpw89Tcf62Mxmi8jh74vRlPy1PgjWL5494b3X\n5fxDidH4bqPZyxTBqPrUFuo+EfUVEqiGF94Ppq6ZUvrBGOVo1V1+Ifm9CGEK597c\naevcGc1RFlgxIgN84UpuDjPR9/zSndwJ7XsXYvZ6HXcKGagRKsfYDWGPkA5cOL/e\nf+yObOnC43yPUvpggQ4KaNJ6+SMTZOKikM8yciyBwLqwrjo8FlJgkv8Vfag/2UR7\nJINbyqHHoLUhQ2m6HXSwK4YjtwidF9EUkaBZWrrskYR3IRZLXlWqeOi/+ezYOW0m\nvufrkcvsh+TKlVVnuwmEPjJ8mwUSpsLdfPJo1DHsd8FS03SCKPaXFdD7ePfEjiYk\nnHpQaKE01aWVSLUiygn7F7rYemGqV9Vt7tBw5pz0vqSC72a5E3zFzIIuHx6aANry\nGat3aqU3qtBXOrA/dPkX9cWE+UR5wo/A2UdKJZLlGhM2WRJ3ltmGT48V9CeS6N9Y\nm4CKdzvg7EWjlTlFrd/8WJ2KoqOE9leDPeXRPncubJfJ6LLIHyG09h9kKQARAQAB\ntDpDZW50T1MgKENlbnRPUyBPZmZpY2lhbCBTaWduaW5nIEtleSkgPHNlY3VyaXR5\nQGNlbnRvcy5vcmc+iQI3BBMBAgAhBQJczFsZAhsDBgsJCAcDAgYVCAIJCgsDFgIB\nAh4BAheAAAoJEAW1VbOEg8ZdjOsP/2ygSxH9jqffOU9SKyJDlraL2gIutqZ3B8pl\nGy/Qnb9QD1EJVb4ZxOEhcY2W9VJfIpnf3yBuAto7zvKe/G1nxH4Bt6WTJQCkUjcs\nN3qPWsx1VslsAEz7bXGiHym6Ay4xF28bQ9XYIokIQXd0T2rD3/lNGxNtORZ2bKjD\nvOzYzvh2idUIY1DgGWJ11gtHFIA9CvHcW+SMPEhkcKZJAO51ayFBqTSSpiorVwTq\na0cB+cgmCQOI4/MY+kIvzoexfG7xhkUqe0wxmph9RQQxlTbNQDCdaxSgwbF2T+gw\nbyaDvkS4xtR6Soj7BKjKAmcnf5fn4C5Or0KLUqMzBtDMbfQQihn62iZJN6ZZ/4dg\nq4HTqyVpyuzMXsFpJ9L/FqH2DJ4exGGpBv00ba/Zauy7GsqOc5PnNBsYaHCply0X\n407DRx51t9YwYI/ttValuehq9+gRJpOTTKp6AjZn/a5Yt3h6jDgpNfM/EyLFIY9z\nV6CXqQQ/8JRvaik/JsGCf+eeLZOw4koIjZGEAg04iuyNTjhx0e/QHEVcYAqNLhXG\nrCTTbCn3NSUO9qxEXC+K/1m1kaXoCGA0UWlVGZ1JSifbbMx0yxq/brpEZPUYm+32\no8XfbocBWljFUJ+6aljTvZ3LQLKTSPW7TFO+GXycAOmCGhlXh2tlc6iTc41PACqy\nyy+mHmSv\n=kkH7\n-----END PGP PUBLIC KEY BLOCK-----\n"),
			Rhsm:     common.ToPtr(false),
		},
	}

	creq1 := composer.ComposeRequest{
		Customizations: &composer.Customizations{
			Packages: common.ToPtr([]string{"nginx"}),
			Users: common.ToPtr([]composer.User{
				{
					Name:     "user1",
					Password: common.ToPtr("$6$password123"),
				},
				{
					Name: "user2",
					Key:  common.ToPtr("ssh-rsa AAAAB3NzaC1"),
				},
			}),
		},
		Distribution: "centos-9",
		ImageRequest: &composer.ImageRequest{
			Architecture: "x86_64",
			ImageType:    composer.ImageTypesAws,
			Repositories: repos,
			UploadOptions: makeUploadOptions(t, composer.AWSEC2UploadOptions{
				ShareWithAccounts: []string{"test-account"},
			}),
		},
	}
	creq2 := composer.ComposeRequest{
		Customizations: &composer.Customizations{
			Packages: common.ToPtr([]string{"nginx"}),
			Users: common.ToPtr([]composer.User{
				{
					Name:     "user1",
					Password: common.ToPtr("$6$password123"),
				},
				{
					Name: "user2",
					Key:  common.ToPtr("ssh-rsa AAAAB3NzaC1"),
				},
			}),
		},
		Distribution: "centos-9",
		ImageRequest: &composer.ImageRequest{
			Architecture: "aarch64",
			ImageType:    composer.ImageTypesAws,
			Repositories: reposAarch,
			UploadOptions: makeUploadOptions(t, composer.AWSEC2UploadOptions{
				ShareWithAccounts: []string{"test-account"},
			}),
		},
	}
	creq3 := composer.ComposeRequest{
		Customizations: &composer.Customizations{
			Packages: common.ToPtr([]string{"nginx"}),
			Users: common.ToPtr([]composer.User{
				{
					Name:     "user1",
					Password: common.ToPtr("$6$password123"),
				},
				{
					Name: "user2",
					Key:  common.ToPtr("ssh-rsa AAAAB3NzaC1"),
				},
			}),
		},
		Distribution: "centos-9",
		ImageRequest: &composer.ImageRequest{
			Architecture:  "aarch64",
			ImageType:     composer.ImageTypesGuestImage,
			Repositories:  reposAarch,
			UploadOptions: makeUploadOptions(t, composer.AWSS3UploadOptions{}),
		},
	}

	tests := map[string]struct {
		payload         any
		composeRequests []composer.ComposeRequest
		expectedImages  int
	}{
		"empty targets": {
			payload:         strings.NewReader(""),
			composeRequests: []composer.ComposeRequest{creq1, creq2, creq3},
			expectedImages:  3,
		},
		"multiple targets": {
			payload:         v1.ComposeBlueprintJSONBody{ImageTypes: &[]v1.ImageTypes{"aws", "guest-image", "gcp"}},
			composeRequests: []composer.ComposeRequest{creq1, creq2, creq3},
			expectedImages:  3,
		},
		"one target": {
			payload:         v1.ComposeBlueprintJSONBody{ImageTypes: &[]v1.ImageTypes{"guest-image"}},
			composeRequests: []composer.ComposeRequest{creq3},
			expectedImages:  1,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			composeRequests = []composer.ComposeRequest{}

			respStatusCode, body := tutils.PostResponseBody(t, srv.URL+fmt.Sprintf("/api/image-builder/v1/blueprints/%s/compose", id.String()), tc.payload)
			require.Equal(t, http.StatusCreated, respStatusCode)

			var result []v1.ComposeResponse
			err = json.Unmarshal([]byte(body), &result)
			require.NoError(t, err)
			require.ElementsMatch(t, tc.composeRequests, composeRequests)
			require.Len(t, result, tc.expectedImages)
			for i := 0; i < tc.expectedImages; i++ {
				require.Equal(t, ids[len(ids)-tc.expectedImages+i], result[i].Id)
			}
		})
	}

	t.Run("non-existing blueprint", func(t *testing.T) {
		respStatusCode, _ := tutils.PostResponseBody(t, srv.URL+fmt.Sprintf("/api/image-builder/v1/blueprints/%s/compose", uuid.New()), v1.ComposeBlueprintJSONBody{})
		require.Equal(t, http.StatusNotFound, respStatusCode)
	})
}

func TestHandlers_GetBlueprintComposes(t *testing.T) {
	ctx := context.Background()
	blueprintId := uuid.New()
	versionId := uuid.New()
	version2Id := uuid.New()
	imageName := "MyImageName"
	clientId := "ui"

	dbase, srvURL, shutdownFn := makeTestServer(t, nil)
	defer shutdownFn(t)

	var result v1.ComposesResponse

	err := dbase.InsertBlueprint(ctx, blueprintId, versionId, "000000", "500000", "blueprint", "blueprint desc", json.RawMessage(`{"image_requests": [{"image_type": "aws"}]}`), nil, nil)
	require.NoError(t, err)
	id1 := uuid.New()
	err = dbase.InsertCompose(ctx, id1, "500000", "user100000@test.test", "000000", &imageName, json.RawMessage(`{"image_requests": [{"image_type": "edge-installer"}]}`), &clientId, &versionId)
	require.NoError(t, err)
	id2 := uuid.New()
	err = dbase.InsertCompose(ctx, id2, "500000", "user100000@test.test", "000000", &imageName, json.RawMessage(`{"image_requests": [{"image_type": "aws"}]}`), &clientId, &versionId)
	require.NoError(t, err)

	err = dbase.UpdateBlueprint(ctx, version2Id, blueprintId, "000000", "blueprint", "desc2", json.RawMessage(`{"image_requests": [{"image_type": "aws"}, {"image_type": "gcp"}]}`), nil)
	require.NoError(t, err)
	id3 := uuid.New()
	err = dbase.InsertCompose(ctx, id3, "500000", "user100000@test.test", "000000", &imageName, json.RawMessage(`{"image_requests": [{"image_type": "aws"}]}`), &clientId, &version2Id)
	require.NoError(t, err)
	id4 := uuid.New()
	err = dbase.InsertCompose(ctx, id4, "500000", "user100000@test.test", "000000", &imageName, json.RawMessage(`{"image_requests": [{"image_type": "gcp"}]}`), &clientId, &version2Id)
	require.NoError(t, err)

	respStatusCode, body := tutils.GetResponseBody(t, srvURL+fmt.Sprintf("/api/image-builder/v1/blueprints/%s/composes", blueprintId.String()), &tutils.AuthString0)
	require.NoError(t, err)

	require.Equal(t, 200, respStatusCode)
	err = json.Unmarshal([]byte(body), &result)
	require.NoError(t, err)
	require.Equal(t, blueprintId, *result.Data[0].BlueprintId)
	require.Equal(t, 2, *result.Data[0].BlueprintVersion)
	require.Equal(t, fmt.Sprintf("/api/image-builder/v1.0/composes?blueprint_id=%s&limit=100&offset=0", blueprintId.String()), result.Links.First)
	require.Equal(t, fmt.Sprintf("/api/image-builder/v1.0/composes?blueprint_id=%s&limit=100&offset=0", blueprintId.String()), result.Links.Last)
	require.Equal(t, 4, len(result.Data))
	require.Equal(t, 4, result.Meta.Count)

	// get composes for specific version
	respStatusCode, body = tutils.GetResponseBody(t, srvURL+fmt.Sprintf("/api/image-builder/v1/blueprints/%s/composes?blueprint_version=2", blueprintId.String()), &tutils.AuthString0)
	require.NoError(t, err)

	require.Equal(t, 200, respStatusCode)
	err = json.Unmarshal([]byte(body), &result)
	require.NoError(t, err)
	require.Equal(t, blueprintId, *result.Data[0].BlueprintId)
	require.Equal(t, 2, *result.Data[0].BlueprintVersion)
	require.Equal(t, fmt.Sprintf("/api/image-builder/v1.0/composes?blueprint_id=%s&blueprint_version=2&limit=100&offset=0", blueprintId.String()), result.Links.First)
	require.Equal(t, fmt.Sprintf("/api/image-builder/v1.0/composes?blueprint_id=%s&blueprint_version=2&limit=100&offset=0", blueprintId.String()), result.Links.Last)
	require.Equal(t, 2, len(result.Data))
	require.Equal(t, 2, result.Meta.Count)

	// get composes for latest version
	respStatusCode, body = tutils.GetResponseBody(t, srvURL+fmt.Sprintf("/api/image-builder/v1/blueprints/%s/composes?blueprint_version=-1", blueprintId.String()), &tutils.AuthString0)
	require.NoError(t, err)

	require.Equal(t, 200, respStatusCode)
	err = json.Unmarshal([]byte(body), &result)
	require.NoError(t, err)
	require.Equal(t, blueprintId, *result.Data[0].BlueprintId)
	require.Equal(t, 2, *result.Data[0].BlueprintVersion)

	// get composes for non-existing blueprint
	respStatusCode, _ = tutils.GetResponseBody(t, srvURL+fmt.Sprintf("/api/image-builder/v1/blueprints/%s/composes?blueprint_version=1", uuid.New().String()), &tutils.AuthString0)
	require.Equal(t, 404, respStatusCode)

	// get composes for a blueprint that does not have any composes
	id5 := uuid.New()
	versionId2 := uuid.New()
	err = dbase.InsertBlueprint(ctx, id5, versionId2, "000000", "500000", "newBlueprint", "blueprint desc", json.RawMessage(`{"image_requests": [{"image_type": "aws"}]}`), nil, nil)
	require.NoError(t, err)
	respStatusCode, body = tutils.GetResponseBody(t, srvURL+fmt.Sprintf("/api/image-builder/v1/blueprints/%s/composes?blueprint_version=1", id5), &tutils.AuthString0)
	require.Equal(t, 200, respStatusCode)
	err = json.Unmarshal([]byte(body), &result)
	require.NoError(t, err)
	require.Equal(t, 0, len(result.Data))
	require.Equal(t, 0, result.Meta.Count)
}

func TestHandlers_BlueprintFromEntryWithRedactedPasswords(t *testing.T) {
	t.Run("plain password", func(t *testing.T) {
		body := []byte(`{"name": "Blueprint", "description": "desc", "customizations": {"users": [{"name": "user", "password": "foo"}]}, "distribution": "centos-9"}`)
		be := &db.BlueprintEntry{
			Body: body,
		}
		result, err := v1.BlueprintFromEntry(
			be,
			v1.WithRedactedPasswords(),
		)
		require.NoError(t, err)
		require.NotEqual(t, common.ToPtr("foo"), (*result.Customizations.Users)[0].Password)
		require.True(t, *(*result.Customizations.Users)[0].HasPassword)
	})
	t.Run("already hashed password", func(t *testing.T) {
		body := []byte(`{"name": "Blueprint", "description": "desc", "customizations": {"users": [{"name": "user", "password": "$6$foo"}]}, "distribution": "centos-9"}`)
		be := &db.BlueprintEntry{
			Body: body,
		}
		result, err := v1.BlueprintFromEntry(
			be,
			v1.WithRedactedPasswords(),
		)
		require.NoError(t, err)

		require.Nil(t, (*result.Customizations.Users)[0].Password)
		require.True(t, *(*result.Customizations.Users)[0].HasPassword)
	})
}

func TestHandlers_BlueprintFromEntryRedactedForExport(t *testing.T) {
	t.Run("bp with cacerts and only satellite files", func(t *testing.T) {
		body := []byte(`{"name": "Blueprint", "description": "desc", "customizations": {"cacerts":  { "pemcerts": ["---BEGIN CERTIFICATE---\nMIIC0DCCAbigAwIBAgIUI...\n---END CERTIFICATE---"] },
				"files": [
				  {
					"data": "WeNeedToGetRidOfThisFile",
					"data_encoding": "base64",
					"ensure_parents": true,
					"path": "/etc/systemd/system/register-satellite.service"
				  },
				  {
					"data": "ThisOneToo",
					"data_encoding": "base64",
					"ensure_parents": true,
					"path": "/usr/local/sbin/register-satellite"
				  }
				],
				"distribution": "centos-9"}}`)
		be := &db.BlueprintEntry{
			Body: body,
		}
		result, err := v1.BlueprintFromEntry(
			be,
			v1.WithRedactedPasswords(),
			v1.WithRedactedFiles([]string{
				"/etc/systemd/system/register-satellite.service",
				"/usr/local/sbin/register-satellite",
			}),
		)
		require.NoError(t, err)
		require.NotNil(t, result.Customizations.Cacerts)
		require.Nil(t, result.Customizations.Files)
	})

	t.Run("blueprint with two satellite files and one different file", func(t *testing.T) {
		body := []byte(`{"name": "Blueprint", "description": "desc", "customizations": {"files": [
				  {
					"data": "WeNeedToGetRidOfThisFile",
					"data_encoding": "base64",
					"ensure_parents": true,
					"path": "/etc/systemd/system/register-satellite.service"
				  },
				  {
					"data": "ThisOneToo",
					"data_encoding": "base64",
					"ensure_parents": true,
					"path": "/usr/local/sbin/register-satellite"
				  },
				  {
					"data": "Let's keep this one",
					"data_encoding": "base64",
					"ensure_parents": true,
					"path": "/usr/local/sbin/some-firstboot-script"
				  }
				],
				"distribution": "centos-9"}}`)
		be := &db.BlueprintEntry{
			Body: body,
		}
		result, err := v1.BlueprintFromEntry(
			be,
			v1.WithRedactedPasswords(),
			v1.WithRedactedFiles([]string{
				"/etc/systemd/system/register-satellite.service",
				"/usr/local/sbin/register-satellite",
			}),
		)

		require.NoError(t, err)
		require.Nil(t, result.Customizations.Cacerts)
		require.Len(t, *result.Customizations.Files, 1)
		require.Equal(t, "/usr/local/sbin/some-firstboot-script", (*result.Customizations.Files)[0].Path)
	})
}

func TestHandlers_GetBlueprint(t *testing.T) {
	ctx := context.Background()
	dbase, srvURL, shutdownFn := makeTestServer(t, nil)
	defer shutdownFn(t)

	id := uuid.New()
	versionId := uuid.New()

	uploadOptions := v1.UploadRequest_Options{}
	err := uploadOptions.FromAWSUploadRequestOptions(v1.AWSUploadRequestOptions{
		ShareWithAccounts: common.ToPtr([]string{"test-account"}),
	})
	require.NoError(t, err)
	name := "blueprint"
	description := "desc"
	blueprint := v1.BlueprintBody{
		Customizations: v1.Customizations{
			Packages: common.ToPtr([]string{"nginx"}),
			Users: common.ToPtr([]v1.User{
				{
					Name:     "user",
					Password: common.ToPtr("password123"),
				},
			}),
		},
		Distribution: "centos-9",
		ImageRequests: []v1.ImageRequest{
			{
				Architecture: v1.ImageRequestArchitectureX8664,
				ImageType:    v1.ImageTypesAws,
				UploadRequest: v1.UploadRequest{
					Type:    v1.UploadTypesAws,
					Options: uploadOptions,
				},
			},
			{
				Architecture: v1.ImageRequestArchitectureAarch64,
				ImageType:    v1.ImageTypesAws,
				UploadRequest: v1.UploadRequest{
					Type:    v1.UploadTypesAws,
					Options: uploadOptions,
				},
			},
		},
	}

	var message []byte
	message, err = json.Marshal(blueprint)
	require.NoError(t, err)
	err = dbase.InsertBlueprint(ctx, id, versionId, "000000", "000000", name, description, message, nil, nil)
	require.NoError(t, err)

	be, err := dbase.GetBlueprint(ctx, id, "000000", nil)
	require.NoError(t, err)
	require.Nil(t, be.Metadata)

	respStatusCode, body := tutils.GetResponseBody(t, srvURL+fmt.Sprintf("/api/image-builder/v1/blueprints/%s", id.String()), &tutils.AuthString0)
	require.Equal(t, http.StatusOK, respStatusCode)

	var result v1.BlueprintResponse
	require.Equal(t, 200, respStatusCode)
	err = json.Unmarshal([]byte(body), &result)
	require.NoError(t, err)
	require.Equal(t, id, result.Id)
	require.Equal(t, description, result.Description)
	require.Equal(t, name, result.Name)
	require.Equal(t, blueprint.ImageRequests, result.ImageRequests)
	require.Equal(t, blueprint.Distribution, result.Distribution)
	require.Equal(t, blueprint.Customizations.Packages, result.Customizations.Packages)
	// Check that the password returned is redacted
	for _, u := range *result.Customizations.Users {
		require.Nil(t, u.Password)
	}

	respStatusCodeNotFound, _ := tutils.GetResponseBody(t, srvURL+fmt.Sprintf("/api/image-builder/v1/blueprints/%s", uuid.New()), &tutils.AuthString0)
	require.Equal(t, http.StatusNotFound, respStatusCodeNotFound)

	// fetch specific version
	version2Id := uuid.New()
	version2Body := v1.BlueprintBody{}
	err = json.Unmarshal(message, &version2Body)
	require.NoError(t, err)
	version2Body.Customizations.Packages = common.ToPtr([]string{"nginx", "httpd"})
	var message2 []byte
	message2, err = json.Marshal(version2Body)
	require.NoError(t, err)
	err = dbase.UpdateBlueprint(ctx, version2Id, id, "000000", name, description, message2, nil)
	require.NoError(t, err)

	respStatusCode, body = tutils.GetResponseBody(t, srvURL+fmt.Sprintf("/api/image-builder/v1/blueprints/%s?version=%d", id.String(), -1), &tutils.AuthString0)
	require.Equal(t, http.StatusOK, respStatusCode)
	err = json.Unmarshal([]byte(body), &result)
	require.NoError(t, err)
	require.Equal(t, version2Body.Customizations.Packages, result.Customizations.Packages)
	for _, u := range *result.Customizations.Users {
		require.Nil(t, u.Password)
	}

	respStatusCode, body = tutils.GetResponseBody(t, srvURL+fmt.Sprintf("/api/image-builder/v1/blueprints/%s?version=%d", id.String(), 2), &tutils.AuthString0)
	require.Equal(t, http.StatusOK, respStatusCode)
	err = json.Unmarshal([]byte(body), &result)
	require.NoError(t, err)
	require.Equal(t, version2Body.Customizations.Packages, result.Customizations.Packages)
	for _, u := range *result.Customizations.Users {
		require.Nil(t, u.Password)
	}

	respStatusCode, body = tutils.GetResponseBody(t, srvURL+fmt.Sprintf("/api/image-builder/v1/blueprints/%s?version=%d", id.String(), 1), &tutils.AuthString0)
	require.Equal(t, http.StatusOK, respStatusCode)
	err = json.Unmarshal([]byte(body), &result)
	require.NoError(t, err)
	require.Equal(t, blueprint.Customizations.Packages, result.Customizations.Packages)
	for _, u := range *result.Customizations.Users {
		require.Nil(t, u.Password)
	}
}

func compareOutputExportBlueprint(t *testing.T, jsonResponse string) {
	// exported_at is dynamically generated, we need to change it
	var jsonResponseUnmarshal map[string]interface{}
	err := json.Unmarshal([]byte(jsonResponse), &jsonResponseUnmarshal)
	require.NoError(t, err)
	metadata, ok := jsonResponseUnmarshal["metadata"].(map[string]interface{})
	metadata["exported_at"] = "2013-06-13 00:00:00 +0000 UTC"
	require.Equal(t, true, ok)

	// Now let's wrap the data again
	data, err := json.Marshal(jsonResponseUnmarshal)
	require.NoError(t, err)
	var responseDataUnmarshal interface{}
	err = json.Unmarshal(data, &responseDataUnmarshal)
	require.NoError(t, err)
	generatedData, err := json.MarshalIndent(jsonResponseUnmarshal, "", "  ")
	require.NoError(t, err)

	// Do the same for our fixture
	exportedBlueprintFile := "../common/testdata/exported_blueprint.json"
	fixtureData, err := os.ReadFile(exportedBlueprintFile)
	require.NoError(t, err)

	var fixtureDataUnmarshal interface{}
	err = json.Unmarshal(fixtureData, &fixtureDataUnmarshal)
	require.NoError(t, err)
	expectedData, err := json.MarshalIndent(fixtureDataUnmarshal, "", "  ")
	require.NoError(t, err)

	require.JSONEq(t, string(expectedData), string(generatedData))

	require.NoError(t, err)
}

func TestHandlers_ExportBlueprint(t *testing.T) {
	ctx := context.Background()

	var composeId uuid.UUID
	var composerRequest composer.ComposeRequest
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		require.Equal(t, "Bearer accesstoken", r.Header.Get("Authorization"))
		err := json.NewDecoder(r.Body).Decode(&composerRequest)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		composeId = uuid.New()
		result := composer.ComposeId{
			Id: composeId,
		}
		err = json.NewEncoder(w).Encode(result)
		require.NoError(t, err)
	}))
	defer apiSrv.Close()

	dbase, srvURL, shutdownFn := makeTestServer(t, &apiSrv.URL)
	defer shutdownFn(t)

	idString := "f43a4ec2-5447-4a25-8a62-e258ff11a2d9"
	id, err := uuid.Parse(idString)
	require.NoError(t, err)
	versionId := uuid.New()

	uploadOptions := v1.UploadRequest_Options{}
	err = uploadOptions.FromAWSUploadRequestOptions(v1.AWSUploadRequestOptions{
		ShareWithAccounts: common.ToPtr([]string{"test-account"}),
	})
	require.NoError(t, err)
	name := "blueprint"
	description := "desc"
	blueprint := v1.BlueprintBody{
		Customizations: v1.Customizations{
			Packages: common.ToPtr([]string{"nginx"}),
			Subscription: &v1.Subscription{
				ActivationKey: "aaa",
			},
			AAPRegistration: &v1.AAPRegistration{
				AnsibleCallbackUrl:      "https://aap-gw.example.com/api/controller/v2/job_templates/42/callback/",
				HostConfigKey:           "test-host-config-key-12345",
				TlsCertificateAuthority: "-----BEGIN CERTIFICATE-----\nMIIC0DCCAbigAwIBAgIUI...\n-----END CERTIFICATE-----",
				SkipTlsVerification:     common.ToPtr(false),
			},
			Users: common.ToPtr([]v1.User{
				{
					Name:     "user",
					Password: common.ToPtr("password123"),
				},
			}),
			CustomRepositories: &[]v1.CustomRepository{
				{
					Baseurl: &[]string{"http://snappy-url/snappy/baseos"},
					Name:    common.ToPtr("baseos"),
					Gpgkey:  &[]string{mocks.RhelGPG},
					Id:      mocks.RepoBaseID,
				},
			},
		},
		Distribution: "centos-9",
		ImageRequests: []v1.ImageRequest{
			{
				Architecture: v1.ImageRequestArchitectureX8664,
				ImageType:    v1.ImageTypesAws,
				UploadRequest: v1.UploadRequest{
					Type:    v1.UploadTypesAws,
					Options: uploadOptions,
				},
				SnapshotDate: common.ToPtr("2012-12-20"),
			},
			{
				Architecture: v1.ImageRequestArchitectureAarch64,
				ImageType:    v1.ImageTypesAws,
				UploadRequest: v1.UploadRequest{
					Type:    v1.UploadTypesAws,
					Options: uploadOptions,
				},
				SnapshotDate: common.ToPtr("2012-12-21"),
			},
		},
	}

	var message []byte
	message, err = json.Marshal(blueprint)
	require.NoError(t, err)

	parentId := uuid.New()
	require.NoError(t, err)
	exportedAt := time.RFC3339
	metadata := v1.BlueprintMetadata{
		ParentId:   &parentId,
		ExportedAt: exportedAt,
	}
	var metadataMessage []byte
	metadataMessage, err = json.Marshal(metadata)
	require.NoError(t, err)

	err = dbase.InsertBlueprint(ctx, id, versionId, "000000", "000000", name, description, message, metadataMessage, nil)
	require.NoError(t, err)

	respStatusCode, body := tutils.GetResponseBody(t, srvURL+fmt.Sprintf("/api/image-builder/v1/blueprints/%s/export", id.String()), &tutils.AuthString0)
	require.Equal(t, http.StatusOK, respStatusCode)

	compareOutputExportBlueprint(t, body)
	var result BlueprintExportResponseUnmarshal
	require.Equal(t, 200, respStatusCode)
	err = json.Unmarshal([]byte(body), &result)
	require.NoError(t, err)
	require.Equal(t, description, result.Description)
	require.Equal(t, name, result.Name)
	require.Equal(t, blueprint.Distribution, result.Distribution)
	require.Equal(t, blueprint.Customizations.Packages, result.Customizations.Packages)
	require.Equal(t, "baseos", *result.ContentSources[0].Name)
	require.Equal(t, "http://snappy-url/snappy/baseos", *result.ContentSources[0].Url)
	require.Equal(t, mocks.RhelGPG, *result.ContentSources[0].GpgKey)
	require.Equal(t, "2012-12-20", *result.SnapshotDate)
	require.Len(t, result.ContentSources, 1)
	// Check that the password returned is redacted
	for _, u := range *result.Customizations.Users {
		require.Nil(t, u.Password)
	}
	require.Nil(t, result.Customizations.Subscription)
	require.Equal(t, &id, result.Metadata.ParentId)
	require.NotEqual(t, metadata.ExportedAt, result.Metadata.ExportedAt)

	nameMeta := "blueprint with metadata"
	parentIdMeta := "be75e486-7f2b-4b0d-a0f2-de152dcd344a"
	bodyToImport := map[string]interface{}{
		"name":           nameMeta,
		"description":    "desc",
		"customizations": map[string]interface{}{"packages": []string{"nginx"}},
		"distribution":   "centos-9",
		"image_requests": []map[string]interface{}{
			{
				"architecture":   "x86_64",
				"image_type":     "aws",
				"upload_request": map[string]interface{}{"type": "aws", "options": map[string]interface{}{"share_with_accounts": []string{"test-account"}}},
			},
		},
		"metadata": map[string]interface{}{
			"parent_id":   parentIdMeta,
			"exported_at": exportedAt,
		},
	}

	statusPost, respPost := tutils.PostResponseBody(t, srvURL+"/api/image-builder/v1/blueprints", bodyToImport)
	require.Equal(t, http.StatusCreated, statusPost)

	var resultPost v1.CreateBlueprintResponse
	err = json.Unmarshal([]byte(respPost), &resultPost)
	require.NoError(t, err)

	be, err := dbase.GetBlueprint(ctx, resultPost.Id, "000000", nil)
	require.NoError(t, err)

	var resultMeta v1.BlueprintMetadata
	require.NotNil(t, be.Metadata)
	err = json.Unmarshal(be.Metadata, &resultMeta)
	require.NoError(t, err)

	require.Equal(t, parentIdMeta, resultMeta.ParentId.String())
	require.Equal(t, exportedAt, resultMeta.ExportedAt)

	respStatusCodeNoCustomRepos, _ := tutils.GetResponseBody(t, srvURL+fmt.Sprintf("/api/image-builder/v1/blueprints/%s/export", id.String()), &tutils.AuthString0)
	require.Equal(t, http.StatusOK, respStatusCodeNoCustomRepos)

	id2 := uuid.New()
	versionId2 := uuid.New()
	moreRepos := v1.BlueprintBody{
		Customizations: v1.Customizations{
			Packages: common.ToPtr([]string{"nginx"}),
			Subscription: &v1.Subscription{
				ActivationKey: "aaa",
			},
			AAPRegistration: &v1.AAPRegistration{
				AnsibleCallbackUrl:      "https://aap-gw.example.com/api/controller/v2/job_templates/42/callback/",
				HostConfigKey:           "test-host-config-key-12345",
				TlsCertificateAuthority: "-----BEGIN CERTIFICATE-----\nMIIC0DCCAbigAwIBAgIUI...\n-----END CERTIFICATE-----",
				SkipTlsVerification:     common.ToPtr(false),
			},
			Users: common.ToPtr([]v1.User{
				{
					Name:     "user",
					Password: common.ToPtr("password123"),
				},
			}),
			CustomRepositories: &[]v1.CustomRepository{
				{
					Baseurl: &[]string{"http://snappy-url/snappy/baseos"},
					Name:    common.ToPtr("baseos"),
					Gpgkey:  &[]string{mocks.RhelGPG},
					Id:      mocks.RepoBaseID,
				},
				{
					Baseurl: &[]string{"http://snappy-url/snappy/appstream"},
					Name:    common.ToPtr("appstream"),
					Gpgkey:  &[]string{mocks.RhelGPG},
					Id:      mocks.RepoAppstrID,
				},
			},
		},
		Distribution: "centos-9",
	}

	var message2 []byte
	message2, err = json.Marshal(moreRepos)
	require.NoError(t, err)

	err = dbase.InsertBlueprint(ctx, id2, versionId2, "000000", "000000", "blueprint2", "", message2, metadataMessage, nil)
	require.NoError(t, err)

	respStatusCodeMoreRepos, bodyMoreRepos := tutils.GetResponseBody(t, srvURL+fmt.Sprintf("/api/image-builder/v1/blueprints/%s/export", id2.String()), &tutils.AuthString0)
	require.Equal(t, http.StatusOK, respStatusCodeMoreRepos)

	var result2 BlueprintExportResponseUnmarshal
	err = json.Unmarshal([]byte(bodyMoreRepos), &result2)
	require.NoError(t, err)
	require.Len(t, result2.ContentSources, 2)
	require.Equal(t, "baseos", *result2.ContentSources[0].Name)
	require.Equal(t, "http://snappy-url/snappy/baseos", *result2.ContentSources[0].Url)
	require.Equal(t, mocks.RhelGPG, *result2.ContentSources[0].GpgKey)
	require.Equal(t, "appstream", *result2.ContentSources[1].Name)
	require.Equal(t, "http://snappy-url/snappy/appstream", *result2.ContentSources[1].Url)
	require.Equal(t, mocks.RhelGPG, *result2.ContentSources[1].GpgKey)
}

func TestHandlers_GetBlueprints(t *testing.T) {
	ctx := context.Background()

	dbase, srvURL, shutdownFn := makeTestServer(t, nil)
	defer shutdownFn(t)

	blueprintId := uuid.New()
	versionId := uuid.New()
	err := dbase.InsertBlueprint(ctx, blueprintId, versionId, "000000", "000000", "blueprint", "blueprint desc", json.RawMessage(`{}`), nil, nil)
	require.NoError(t, err)
	blueprintId2 := uuid.New()
	versionId2 := uuid.New()
	err = dbase.InsertBlueprint(ctx, blueprintId2, versionId2, "000000", "000000", "Blueprint2", "blueprint desc", json.RawMessage(`{}`), nil, nil)
	require.NoError(t, err)

	var result v1.BlueprintsResponse
	respStatusCode, body := tutils.GetResponseBody(t, srvURL+"/api/image-builder/v1/blueprints?name=blueprint", &tutils.AuthString0)
	require.Equal(t, http.StatusOK, respStatusCode)
	err = json.Unmarshal([]byte(body), &result)
	require.NoError(t, err)
	require.Len(t, result.Data, 1)
	require.Equal(t, blueprintId, result.Data[0].Id)
	require.Equal(t, 1, result.Meta.Count)
	require.Equal(t, "/api/image-builder/v1.0/blueprints?limit=100&name=blueprint&offset=0", result.Links.First)
	require.Equal(t, "/api/image-builder/v1.0/blueprints?limit=100&name=blueprint&offset=0", result.Links.Last)

	respStatusCode, body = tutils.GetResponseBody(t, srvURL+"/api/image-builder/v1/blueprints?name=Blueprint", &tutils.AuthString0)
	require.Equal(t, http.StatusOK, respStatusCode)
	err = json.Unmarshal([]byte(body), &result)
	require.NoError(t, err)
	require.Len(t, result.Data, 0)
	require.Equal(t, 0, result.Meta.Count)
	require.Equal(t, "/api/image-builder/v1.0/blueprints?limit=100&name=Blueprint&offset=0", result.Links.First)
	require.Equal(t, "/api/image-builder/v1.0/blueprints?limit=100&name=Blueprint&offset=0", result.Links.Last)
}

func TestHandlers_DeleteBlueprint(t *testing.T) {
	ctx := context.Background()
	blueprintId := uuid.New()
	versionId := uuid.New()
	version2Id := uuid.New()
	clientId := "ui"
	imageName := "MyImageName"

	dbase, srvURL, shutdownFn := makeTestServer(t, nil)
	defer shutdownFn(t)

	blueprintName := "blueprint"
	err := dbase.InsertBlueprint(ctx, blueprintId, versionId, "000000", "000000", blueprintName, "blueprint desc", json.RawMessage(`{"image_requests": [{"image_type": "aws"}]}`), nil, nil)
	require.NoError(t, err)
	id1 := uuid.New()
	err = dbase.InsertCompose(ctx, id1, "000000", "user100000@test.test", "000000", &imageName, json.RawMessage(`{"image_requests": [{"image_type": "edge-installer"}]}`), &clientId, &versionId)
	require.NoError(t, err)

	id2 := uuid.New()
	err = dbase.InsertCompose(ctx, id2, "000000", "user100000@test.test", "000000", &imageName, json.RawMessage(`{"image_requests": [{"image_type": "aws"}]}`), &clientId, &versionId)
	require.NoError(t, err)

	err = dbase.UpdateBlueprint(ctx, version2Id, blueprintId, "000000", "blueprint", "desc2", json.RawMessage(`{"image_requests": [{"image_type": "aws"}, {"image_type": "gcp"}]}`), nil)
	require.NoError(t, err)
	id3 := uuid.New()
	err = dbase.InsertCompose(ctx, id3, "000000", "user100000@test.test", "000000", &imageName, json.RawMessage(`{"image_requests": [{"image_type": "aws"}]}`), &clientId, &version2Id)
	require.NoError(t, err)
	id4 := uuid.New()
	err = dbase.InsertCompose(ctx, id4, "000000", "user100000@test.test", "000000", &imageName, json.RawMessage(`{"image_requests": [{"image_type": "gcp"}]}`), &clientId, &version2Id)
	require.NoError(t, err)

	respStatusCode, body := tutils.DeleteResponseBody(t, srvURL+fmt.Sprintf("/api/image-builder/v1/blueprints/%s", blueprintId.String()))
	require.Equal(t, 204, respStatusCode)
	require.Equal(t, "", body)

	var errorResponse v1.HTTPErrorList
	notFoundCode, body := tutils.DeleteResponseBody(t, srvURL+fmt.Sprintf("/api/image-builder/v1/blueprints/%s", blueprintId.String()))
	require.Equal(t, 404, notFoundCode)
	err = json.Unmarshal([]byte(body), &errorResponse)
	require.NoError(t, err)
	require.Equal(t, "Not Found", errorResponse.Errors[0].Detail)

	_, err = dbase.GetBlueprint(ctx, blueprintId, "000000", nil)
	require.ErrorIs(t, err, db.ErrBlueprintNotFound)

	// We should not be able to list deleted blueprint
	var result v1.BlueprintsResponse
	respStatusCode, body = tutils.GetResponseBody(t, srvURL+"/api/image-builder/v1/blueprints?name=blueprint", &tutils.AuthString0)
	require.Equal(t, http.StatusOK, respStatusCode)
	err = json.Unmarshal([]byte(body), &result)
	require.NoError(t, err)
	require.Len(t, result.Data, 0)

	// We should not be able to update deleted blueprint
	id5 := uuid.New()
	err = dbase.UpdateBlueprint(ctx, id5, blueprintId, "000000", "newName", "desc2", json.RawMessage(`{"image_requests": [{"image_type": "aws"}, {"image_type": "gcp"}]}`), nil)
	require.ErrorIs(t, err, db.ErrBlueprintNotFound)

	// Composes should not be assigned to the blueprint anymore
	respStatusCode, _ = tutils.GetResponseBody(t, srvURL+fmt.Sprintf("/api/image-builder/v1/blueprints/%s/composes", blueprintId.String()), &tutils.AuthString0)
	require.Equal(t, 404, respStatusCode)

	// We should be able to create a Blueprint with same name
	blueprintId2 := uuid.New()
	versionId2 := uuid.New()
	err = dbase.InsertBlueprint(ctx, blueprintId2, versionId2, "000000", "000000", blueprintName, "blueprint desc", json.RawMessage(`{"image_requests": [{"image_type": "aws"}]}`), nil, nil)
	require.NoError(t, err)

	bpComposes, err := dbase.GetBlueprintComposes(ctx, "000000", blueprintId2, nil, (time.Hour * 24 * 14), 10, 0, nil)
	require.Len(t, bpComposes, 0)
	require.NoError(t, err)
}

func TestBlueprintBody_CryptPasswords(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("crypt() not supported on darwin")
	}

	// Create a sample blueprint body with users
	passwordToHash := "password123"
	blueprint := &v1.BlueprintBody{
		Customizations: v1.Customizations{
			Users: &[]v1.User{
				{
					Name:     "user1",
					Password: common.ToPtr(passwordToHash),
				},
				{
					Name:   "user2",
					SshKey: common.ToPtr("ssh-key-string"),
				},
			},
		},
	}

	err := blueprint.CryptPasswords()
	require.NoError(t, err)

	// Password hashed
	require.NotEqual(t, (*blueprint.Customizations.Users)[0].Password, passwordToHash)
	// No change with no password
	require.Nil(t, (*blueprint.Customizations.Users)[1].Password)
}

func TestUser_RedactPassword(t *testing.T) {
	user := &v1.User{
		Name:     "test",
		Password: common.ToPtr("password123"),
	}

	user.RedactPassword()
	require.Nil(t, user.Password)
}

func TestLintBlueprint(t *testing.T) {
	srv := startServer(t, &testServerClientsConf{}, nil)
	defer srv.Shutdown(t)

	var oscap v1.OpenSCAP
	require.NoError(t, oscap.FromOpenSCAPCompliance(v1.OpenSCAPCompliance{
		PolicyId: uuid.MustParse(mocks.PolicyID),
	}))
	var oscap2 v1.OpenSCAP
	require.NoError(t, oscap2.FromOpenSCAPCompliance(v1.OpenSCAPCompliance{
		PolicyId: uuid.MustParse(mocks.PolicyID2),
	}))
	var oscap3 v1.OpenSCAP
	require.NoError(t, oscap3.FromOpenSCAPCompliance(v1.OpenSCAPCompliance{
		PolicyId: uuid.MustParse(mocks.MinimalPolicyID),
	}))

	cases := []struct {
		blueprint  v1.BlueprintBody
		lintErrors []v1.BlueprintLintItem
	}{
		{
			blueprint: v1.BlueprintBody{
				Distribution: "rhel-8",
				Customizations: v1.Customizations{
					Openscap: &oscap,
				},
			},
			lintErrors: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "package required-by-compliance required by policy is not present"},
				{Name: "Compliance", Description: "service enabled-required-by-compliance required as enabled by policy is not present"},
				{Name: "Compliance", Description: "service masked-required-by-compliance required as masked by policy is not present"},
				{Name: "Compliance", Description: "FIPS required 'true' by policy but not set"},
			},
		},
		{
			blueprint: v1.BlueprintBody{
				Distribution: "rhel-8",
				Customizations: v1.Customizations{
					Openscap: &oscap,
					Packages: &[]string{
						"required-by-compliance",
					},
					Services: &v1.Services{
						Enabled: &[]string{
							"enabled-required-by-compliance",
						},
						Masked: &[]string{
							"masked-required-by-compliance",
						},
					},
					Fips: &v1.FIPS{
						Enabled: common.ToPtr(true),
					},
				},
			},
			lintErrors: []v1.BlueprintLintItem{},
		},
		{
			blueprint: v1.BlueprintBody{
				Distribution: "rhel-8",
				Customizations: v1.Customizations{
					Openscap: &oscap2,
				},
			},
			lintErrors: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "mountpoint /tmp required by policy is not present"},
				{Name: "Compliance", Description: "mountpoint /var required by policy is not present"},
				{Name: "Compliance", Description: "kernel command line parameter '-compliance' required by policy not set"},
			},
		},
		{
			blueprint: v1.BlueprintBody{
				Distribution: "rhel-8",
				Customizations: v1.Customizations{
					Openscap: &oscap2,
					Kernel: &v1.Kernel{
						Append: common.ToPtr("-somearg -compliance -anotherarg"),
					},
					Filesystem: &[]v1.Filesystem{
						{
							Mountpoint: "/tmp",
							MinSize:    5000,
						},
						{
							Mountpoint: "/var",
							MinSize:    4000,
						},
					},
				},
			},
			lintErrors: []v1.BlueprintLintItem{},
		},
		{
			blueprint: v1.BlueprintBody{
				Distribution: "rhel-89",
				Customizations: v1.Customizations{
					Openscap: &oscap2,
				},
			},
			lintErrors: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "Compliance policy does not have a definition for the latest minor version"},
			},
		},
		{
			blueprint: v1.BlueprintBody{
				Distribution: "rhel-89",
				Customizations: v1.Customizations{
					Openscap: &oscap2,
				},
			},
			lintErrors: []v1.BlueprintLintItem{
				// this error is unfixable for now
				{Name: "Compliance", Description: "Compliance policy does not have a definition for the latest minor version"},
			},
		},
		{
			blueprint: v1.BlueprintBody{
				Distribution: "rhel-8",
				Customizations: v1.Customizations{
					Openscap: &oscap3,
				},
			},
			lintErrors: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "package required-by-compliance required by policy is not present"},
			},
		},
	}

	for idx, c := range cases {
		fmt.Printf("TestLintBlueprint case %d\n", idx)

		bpID := uuid.New()
		bpjson, err := json.Marshal(c.blueprint)
		require.NoError(t, err)
		require.NoError(t, srv.DB.InsertBlueprint(context.Background(), bpID, uuid.New(), "000000", "000000", "bp1", "", bpjson, nil, nil))

		var result v1.BlueprintResponse
		respStatusCode, body := tutils.GetResponseBody(t, fmt.Sprintf("%s/api/image-builder/v1/blueprints/%s", srv.URL, bpID), &tutils.AuthString0)
		require.Equal(t, http.StatusOK, respStatusCode)
		require.NoError(t, json.Unmarshal([]byte(body), &result))
		require.ElementsMatch(t, c.lintErrors, result.Lint.Errors)

		require.NoError(t, srv.DB.DeleteBlueprint(context.Background(), bpID, "000000"))
	}
}

func TestFixupBlueprint(t *testing.T) {
	srv := startServer(t, &testServerClientsConf{}, nil)
	defer srv.Shutdown(t)

	var oscap v1.OpenSCAP
	require.NoError(t, oscap.FromOpenSCAPCompliance(v1.OpenSCAPCompliance{
		PolicyId: uuid.MustParse(mocks.PolicyID),
	}))
	var oscap2 v1.OpenSCAP
	require.NoError(t, oscap2.FromOpenSCAPCompliance(v1.OpenSCAPCompliance{
		PolicyId: uuid.MustParse(mocks.PolicyID2),
	}))

	var uo v1.UploadRequest_Options
	require.NoError(t, uo.FromAWSS3UploadRequestOptions(v1.AWSS3UploadRequestOptions{}))

	cases := []struct {
		blueprint   v1.CreateBlueprintRequest
		name        string
		description string
		lintErrors  []v1.BlueprintLintItem
	}{
		{
			blueprint: v1.CreateBlueprintRequest{
				Name:         "bp-fixup-0",
				Description:  common.ToPtr("fixup test"),
				Distribution: "rhel-8",
				Customizations: v1.Customizations{
					Openscap: &oscap,
				},
				ImageRequests: []v1.ImageRequest{
					{
						Architecture: "x86_64",
						ImageType:    v1.ImageTypesAws,
						UploadRequest: v1.UploadRequest{
							Type:    v1.UploadTypesAwsS3,
							Options: uo,
						},
					},
				},
			},
			lintErrors: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "package required-by-compliance required by policy is not present"},
				{Name: "Compliance", Description: "service enabled-required-by-compliance required as enabled by policy is not present"},
				{Name: "Compliance", Description: "service masked-required-by-compliance required as masked by policy is not present"},
				{Name: "Compliance", Description: "FIPS required 'true' by policy but not set"},
			},
		},
		{
			blueprint: v1.CreateBlueprintRequest{
				Name:         "bp-fixup-1",
				Description:  common.ToPtr("fixup test"),
				Distribution: "rhel-8",
				Customizations: v1.Customizations{
					Openscap: &oscap2,
				},
				ImageRequests: []v1.ImageRequest{
					{
						Architecture: "x86_64",
						ImageType:    v1.ImageTypesAws,
						UploadRequest: v1.UploadRequest{
							Type:    v1.UploadTypesAwsS3,
							Options: uo,
						},
					},
				},
			},
			lintErrors: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "mountpoint /tmp required by policy is not present"},
				{Name: "Compliance", Description: "mountpoint /var required by policy is not present"},
				{Name: "Compliance", Description: "kernel command line parameter '-compliance' required by policy not set"},
			},
		},
	}

	for idx, c := range cases {
		fmt.Printf("TestLintBlueprint case %d\n", idx)

		respStatusCode, respBody := tutils.PostResponseBody(t, srv.URL+"/api/image-builder/v1/blueprints", c.blueprint)
		require.Equal(t, http.StatusCreated, respStatusCode)
		var created v1.CreateBlueprintResponse
		require.NoError(t, json.Unmarshal([]byte(respBody), &created))

		beforeFixup, err := srv.DB.GetBlueprint(context.Background(), created.Id, "000000", nil)
		require.NoError(t, err)
		snapshotBeforeFixup := beforeFixup.ServiceSnapshots

		respStatusCode, _ = tutils.PostResponseBody(t, fmt.Sprintf("%s/api/image-builder/v1/experimental/blueprints/%s/fixup", srv.URL, created.Id), nil)
		require.Equal(t, http.StatusCreated, respStatusCode)

		respStatusCode, body := tutils.GetResponseBody(t, fmt.Sprintf("%s/api/image-builder/v1/blueprints/%s", srv.URL, created.Id), &tutils.AuthString0)
		require.Equal(t, http.StatusOK, respStatusCode)

		var result v1.BlueprintResponse
		require.NoError(t, json.Unmarshal([]byte(body), &result))
		require.Empty(t, result.Lint.Errors)

		afterFixup, err := srv.DB.GetBlueprint(context.Background(), created.Id, "000000", nil)
		require.NoError(t, err)
		require.Equal(t, snapshotBeforeFixup, afterFixup.ServiceSnapshots)

		var ss db.ServiceSnapshots
		require.NoError(t, json.Unmarshal(afterFixup.ServiceSnapshots, &ss))
		require.NotNil(t, ss.Compliance)
		require.NoError(t, srv.DB.DeleteBlueprint(context.Background(), created.Id, "000000"))
	}
}

func TestBlueprintComplianceSnapshot(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("crypt() not supported on darwin")
	}

	ctx := context.Background()
	dbase, srvURL, shutdownFn := makeTestServer(t, nil)
	defer shutdownFn(t)

	body := map[string]interface{}{
		"name":        "BlueprintWithCompliance",
		"description": "Blueprint with compliance policy",
		"customizations": map[string]interface{}{
			"packages": []string{"nginx"},
			"openscap": map[string]interface{}{
				"policy_id": mocks.PolicyID,
			},
		},
		"distribution": "rhel-8",
		"image_requests": []map[string]interface{}{
			{
				"architecture":   "x86_64",
				"image_type":     "aws",
				"upload_request": map[string]interface{}{"type": "aws", "options": map[string]interface{}{"share_with_accounts": []string{"test-account"}}},
			},
		},
	}

	statusCode, respBody := tutils.PostResponseBody(t, srvURL+"/api/image-builder/v1/blueprints", body)
	require.Equal(t, http.StatusCreated, statusCode)

	var result v1.CreateBlueprintResponse
	err := json.Unmarshal([]byte(respBody), &result)
	require.NoError(t, err)

	blueprintEntry, err := dbase.GetBlueprint(ctx, result.Id, "000000", nil)
	require.NoError(t, err)
	require.NotNil(t, blueprintEntry.ServiceSnapshots)

	var serviceSnapshots db.ServiceSnapshots
	err = json.Unmarshal(blueprintEntry.ServiceSnapshots, &serviceSnapshots)
	require.NoError(t, err)
	require.NotNil(t, serviceSnapshots.Compliance)
	require.Equal(t, mocks.PolicyID, serviceSnapshots.Compliance.PolicyId.String())
	require.NotEmpty(t, serviceSnapshots.Compliance.PolicyCustomizations)

	var policyCustomizations map[string]interface{}
	err = json.Unmarshal(serviceSnapshots.Compliance.PolicyCustomizations, &policyCustomizations)
	require.NoError(t, err, "PolicyCustomizations should be valid JSON")
	require.NotEmpty(t, policyCustomizations)

	require.NoError(t, dbase.DeleteBlueprint(ctx, result.Id, "000000"))
}

func TestBlueprintCreationRollbackOnPolicyFailure(t *testing.T) {
	ctx := context.Background()
	dbase, srvURL, shutdownFn := makeTestServer(t, nil)
	defer shutdownFn(t)

	// This triggers a 500: the compliance mock has no tailorings for rhel-9,
	// so building compliance snapshots fails and the creation rolls back.
	body := map[string]interface{}{
		"name":        "BlueprintShouldRollback",
		"description": "Blueprint that should be rolled back",
		"customizations": map[string]interface{}{
			"packages": []string{"nginx"},
			"openscap": map[string]interface{}{
				"policy_id": mocks.PolicyID,
			},
		},
		"distribution": "rhel-9",
		"image_requests": []map[string]interface{}{
			{
				"architecture":   "x86_64",
				"image_type":     "aws",
				"upload_request": map[string]interface{}{"type": "aws", "options": map[string]interface{}{"share_with_accounts": []string{"test-account"}}},
			},
		},
	}

	statusCode, respBody := tutils.PostResponseBody(t, srvURL+"/api/image-builder/v1/blueprints", body)

	t.Logf("Response status: %d, body: %s", statusCode, respBody)
	require.Equal(t, http.StatusInternalServerError, statusCode)

	blueprints, _, err := dbase.GetBlueprints(ctx, "000000", 100, 0)
	require.NoError(t, err)

	require.Empty(t, blueprints)
}

func TestBlueprintUpdateAddsSnapshot(t *testing.T) {
	srv := startServer(t, &testServerClientsConf{}, nil)
	defer srv.Shutdown(t)

	// Create blueprint WITHOUT openscap → no snapshot
	createBody := map[string]any{
		"name":           "bp-update-snapshot",
		"description":    "test update adds snapshot",
		"distribution":   "rhel-8",
		"customizations": map[string]any{},
		"image_requests": []map[string]any{
			{
				"architecture":   "x86_64",
				"image_type":     "aws",
				"upload_request": map[string]any{"type": "aws", "options": map[string]any{"share_with_accounts": []string{"test-account"}}},
			},
		},
	}
	respStatusCode, respBody := tutils.PostResponseBody(t, srv.URL+"/api/image-builder/v1/blueprints", createBody)
	require.Equal(t, http.StatusCreated, respStatusCode)
	var created v1.CreateBlueprintResponse
	require.NoError(t, json.Unmarshal([]byte(respBody), &created))

	beBefore, err := srv.DB.GetBlueprint(context.Background(), created.Id, "000000", nil)
	require.NoError(t, err)
	require.True(t, len(beBefore.ServiceSnapshots) == 0)

	// Update blueprint to ADD openscap → server builds snapshot on update
	updateBody := map[string]any{
		"name":         "bp-update-snapshot",
		"description":  "test update adds snapshot",
		"distribution": "rhel-8",
		"customizations": map[string]any{
			"openscap": map[string]any{"policy_id": mocks.PolicyID},
		},
		"image_requests": []map[string]any{
			{
				"architecture":   "x86_64",
				"image_type":     "aws",
				"upload_request": map[string]any{"type": "aws", "options": map[string]any{"share_with_accounts": []string{"test-account"}}},
			},
		},
	}
	respStatusCode, _ = tutils.PutResponseBody(t, fmt.Sprintf("%s/api/image-builder/v1/blueprints/%s", srv.URL, created.Id), updateBody)
	require.Equal(t, http.StatusCreated, respStatusCode)

	beAfterUpdate, err := srv.DB.GetBlueprint(context.Background(), created.Id, "000000", nil)
	require.NoError(t, err)
	require.True(t, len(beAfterUpdate.ServiceSnapshots) != 0)

	require.NoError(t, srv.DB.DeleteBlueprint(context.Background(), created.Id, "000000"))
}
