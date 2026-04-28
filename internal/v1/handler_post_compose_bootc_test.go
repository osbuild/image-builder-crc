package v1_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/osbuild/image-builder-crc/internal/clients/composer"
	"github.com/osbuild/image-builder-crc/internal/tutils"
	v1 "github.com/osbuild/image-builder-crc/internal/v1"
)

func TestComposeBootcReferenceWithQuery(t *testing.T) {
	distsDir := "../../distributions"

	tests := []struct {
		name          string
		queryExtra    string
		wantReference string
		imageType     v1.ImageTypes
		uploadType    v1.UploadTypes
		uploadOpts    func(t *testing.T) v1.UploadRequest_Options
	}{
		{
			name:          "aws uses bootc container reference from query",
			queryExtra:    "distro=rhel-10.1&arch=x86_64&type=aws",
			wantReference: "quay.io/redhat-services-prod/insights-management-tenant/image-builder-bootc-foundry/rhel-10.1-ec2:latest",
			imageType:     v1.ImageTypesAws,
			uploadType:    v1.UploadTypesAws,
			uploadOpts: func(t *testing.T) v1.UploadRequest_Options {
				var uo v1.UploadRequest_Options
				require.NoError(t, uo.FromAWSUploadRequestOptions(v1.AWSUploadRequestOptions{
					ShareWithAccounts: &[]string{"test-account"},
				}))
				return uo
			},
		},
		{
			name:          "guest-image uses bootc container reference from query",
			queryExtra:    "distro=rhel-10.1&arch=x86_64&type=guest-image",
			wantReference: "quay.io/redhat-services-prod/insights-management-tenant/image-builder-bootc-foundry/rhel-10.1-qcow2:latest",
			imageType:     v1.ImageTypesGuestImage,
			uploadType:    v1.UploadTypesAwsS3,
			uploadOpts: func(t *testing.T) v1.UploadRequest_Options {
				var uo v1.UploadRequest_Options
				require.NoError(t, uo.FromAWSS3UploadRequestOptions(v1.AWSS3UploadRequestOptions{}))
				return uo
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantComposeID := uuid.New()
			var gotComposer composer.ComposeRequest

			apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "Bearer accesstoken", r.Header.Get("Authorization"))
				err := json.NewDecoder(r.Body).Decode(&gotComposer)
				require.NoError(t, err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				err = json.NewEncoder(w).Encode(composer.ComposeId{Id: wantComposeID})
				require.NoError(t, err)
			}))
			defer apiSrv.Close()

			srv := startServer(t, &testServerClientsConf{ComposerURL: apiSrv.URL}, &v1.ServerConfig{
				DistributionsDir: distsDir,
			})
			defer srv.Shutdown(t)

			distURL := srv.URL + "/api/image-builder/v1/distributions?kind=bootc&" + tt.queryExtra
			status, body := tutils.GetResponseBody(t, distURL, &tutils.AuthString0)
			require.Equal(t, http.StatusOK, status, body)
			var bootcItems []v1.BootcDistributionItem
			require.NoError(t, json.Unmarshal([]byte(body), &bootcItems))
			require.Len(t, bootcItems, 1, body)
			ref := bootcItems[0].Reference
			require.NotEmpty(t, ref)
			require.Equal(t, tt.wantReference, ref)

			payload := v1.ComposeRequest{
				Bootc: &v1.BootcBody{
					Reference: ref,
				},
				ImageRequests: []v1.ImageRequest{
					{
						Architecture: "x86_64",
						ImageType:    tt.imageType,
						UploadRequest: v1.UploadRequest{
							Type:    tt.uploadType,
							Options: tt.uploadOpts(t),
						},
					},
				},
			}

			status, body = tutils.PostResponseBody(t, srv.URL+"/api/image-builder/v1/compose", payload)
			require.Equal(t, http.StatusCreated, status, body)
			var composeResp v1.ComposeResponse
			require.NoError(t, json.Unmarshal([]byte(body), &composeResp))
			require.Equal(t, wantComposeID, composeResp.Id)

			require.NotNil(t, gotComposer.Bootc)
			require.Equal(t, tt.wantReference, gotComposer.Bootc.Reference)
			require.Nil(t, gotComposer.Distribution)
		})
	}
}

func TestComposeBootcUnknownReferenceRejected(t *testing.T) {
	srv := startServer(t, &testServerClientsConf{}, &v1.ServerConfig{
		DistributionsDir: "../../distributions",
	})
	defer srv.Shutdown(t)

	var uo v1.UploadRequest_Options
	require.NoError(t, uo.FromAWSUploadRequestOptions(v1.AWSUploadRequestOptions{
		ShareWithAccounts: &[]string{"test-account"},
	}))
	payload := v1.ComposeRequest{
		Bootc: &v1.BootcBody{
			Reference: "quay.io/example/this-reference-is-not-in-the-distro-list:latest",
		},
		ImageRequests: []v1.ImageRequest{
			{
				Architecture: "x86_64",
				ImageType:    v1.ImageTypesAws,
				UploadRequest: v1.UploadRequest{
					Type:    v1.UploadTypesAws,
					Options: uo,
				},
			},
		},
	}
	status, body := tutils.PostResponseBody(t, srv.URL+"/api/image-builder/v1/compose", payload)
	require.Equal(t, http.StatusBadRequest, status, body)
	require.Contains(t, body, "bootc reference 'quay.io/example/this-reference-is-not-in-the-distro-list:latest' not found")
}

func TestComposeBootableContainerIso(t *testing.T) {
	distsDir := "../../distributions"

	installerRef := "quay.io/redhat-services-prod/insights-management-tenant/image-builder-bootc-foundry/rhel-10.1-installer:latest"
	validPayloadRef := "quay.io/redhat-services-prod/insights-management-tenant/image-builder-bootc-foundry/rhel-10.1-qcow2:latest"
	invalidPayloadRef := "quay.io/example/not-in-allowed-list:latest"
	awsBootcRef := "quay.io/redhat-services-prod/insights-management-tenant/image-builder-bootc-foundry/rhel-10.1-ec2:latest"

	tests := []struct {
		name             string
		bootc            *v1.BootcBody
		imageType        v1.ImageTypes
		uploadType       v1.UploadTypes
		uploadOpts       func(t *testing.T) v1.UploadRequest_Options
		wantStatus       int
		wantErrSubstring string
		checkComposer    func(t *testing.T, cr composer.ComposeRequest)
	}{
		{
			name: "bootable-container-iso with valid iso_payload_reference",
			bootc: &v1.BootcBody{
				Reference:           installerRef,
				IsoPayloadReference: &validPayloadRef,
			},
			imageType:  v1.ImageTypesBootableContainerIso,
			uploadType: v1.UploadTypesAwsS3,
			uploadOpts: func(t *testing.T) v1.UploadRequest_Options {
				var uo v1.UploadRequest_Options
				require.NoError(t, uo.FromAWSS3UploadRequestOptions(v1.AWSS3UploadRequestOptions{}))
				return uo
			},
			wantStatus: http.StatusCreated,
			checkComposer: func(t *testing.T, cr composer.ComposeRequest) {
				require.NotNil(t, cr.Bootc)
				require.Equal(t, installerRef, cr.Bootc.Reference)
				require.NotNil(t, cr.Bootc.IsoPayloadReference)
				require.Equal(t, validPayloadRef, *cr.Bootc.IsoPayloadReference)
			},
		},
		{
			name: "bootable-container-iso without iso_payload_reference",
			bootc: &v1.BootcBody{
				Reference: installerRef,
			},
			imageType:  v1.ImageTypesBootableContainerIso,
			uploadType: v1.UploadTypesAwsS3,
			uploadOpts: func(t *testing.T) v1.UploadRequest_Options {
				var uo v1.UploadRequest_Options
				require.NoError(t, uo.FromAWSS3UploadRequestOptions(v1.AWSS3UploadRequestOptions{}))
				return uo
			},
			wantStatus: http.StatusCreated,
			checkComposer: func(t *testing.T, cr composer.ComposeRequest) {
				require.NotNil(t, cr.Bootc)
				require.Equal(t, installerRef, cr.Bootc.Reference)
				require.Nil(t, cr.Bootc.IsoPayloadReference)
			},
		},
		{
			name: "bootable-container-iso with invalid iso_payload_reference",
			bootc: &v1.BootcBody{
				Reference:           installerRef,
				IsoPayloadReference: &invalidPayloadRef,
			},
			imageType:  v1.ImageTypesBootableContainerIso,
			uploadType: v1.UploadTypesAwsS3,
			uploadOpts: func(t *testing.T) v1.UploadRequest_Options {
				var uo v1.UploadRequest_Options
				require.NoError(t, uo.FromAWSS3UploadRequestOptions(v1.AWSS3UploadRequestOptions{}))
				return uo
			},
			wantStatus:       http.StatusBadRequest,
			wantErrSubstring: "iso payload reference",
		},
		{
			name: "iso_payload_reference rejected on non-ISO bootc type",
			bootc: &v1.BootcBody{
				Reference:           awsBootcRef,
				IsoPayloadReference: &validPayloadRef,
			},
			imageType:  v1.ImageTypesAws,
			uploadType: v1.UploadTypesAws,
			uploadOpts: func(t *testing.T) v1.UploadRequest_Options {
				var uo v1.UploadRequest_Options
				require.NoError(t, uo.FromAWSUploadRequestOptions(v1.AWSUploadRequestOptions{
					ShareWithAccounts: &[]string{"test-account"},
				}))
				return uo
			},
			wantStatus:       http.StatusBadRequest,
			wantErrSubstring: "iso_payload_reference must not be set for non-ISO bootc image types",
		},
		{
			name:       "bootable-container-iso requires bootc",
			bootc:      nil,
			imageType:  v1.ImageTypesBootableContainerIso,
			uploadType: v1.UploadTypesAwsS3,
			uploadOpts: func(t *testing.T) v1.UploadRequest_Options {
				var uo v1.UploadRequest_Options
				require.NoError(t, uo.FromAWSS3UploadRequestOptions(v1.AWSS3UploadRequestOptions{}))
				return uo
			},
			wantStatus:       http.StatusBadRequest,
			wantErrSubstring: "bootc is required for bootable-container-iso image type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantComposeID := uuid.New()
			var gotComposer composer.ComposeRequest

			apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "Bearer accesstoken", r.Header.Get("Authorization"))
				err := json.NewDecoder(r.Body).Decode(&gotComposer)
				require.NoError(t, err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				err = json.NewEncoder(w).Encode(composer.ComposeId{Id: wantComposeID})
				require.NoError(t, err)
			}))
			defer apiSrv.Close()

			srv := startServer(t, &testServerClientsConf{ComposerURL: apiSrv.URL}, &v1.ServerConfig{
				DistributionsDir: distsDir,
			})
			defer srv.Shutdown(t)

			payload := v1.ComposeRequest{
				Bootc: tt.bootc,
				ImageRequests: []v1.ImageRequest{
					{
						Architecture: "x86_64",
						ImageType:    tt.imageType,
						UploadRequest: v1.UploadRequest{
							Type:    tt.uploadType,
							Options: tt.uploadOpts(t),
						},
					},
				},
			}

			status, body := tutils.PostResponseBody(t, srv.URL+"/api/image-builder/v1/compose", payload)
			require.Equal(t, tt.wantStatus, status, body)

			if tt.wantErrSubstring != "" {
				require.Contains(t, body, tt.wantErrSubstring)
			}
			if tt.checkComposer != nil {
				tt.checkComposer(t, gotComposer)
			}
		})
	}
}
