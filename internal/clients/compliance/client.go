package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/BurntSushi/toml"
	"github.com/osbuild/blueprint/pkg/blueprint"
	"github.com/osbuild/logging/pkg/strc"
	"github.com/redhatinsights/identity"
)

var (
	ErrorAuth              = errors.New("user is not authorized")
	ErrorMajorVersion      = errors.New("major version of policy doesn't match requested major version")
	ErrorPolicyNotFound    = errors.New("compliance policy not found")
	ErrorTailoringNotFound = errors.New("tailorings for a policy not found")
	ErrorNotOk             = errors.New("unexpected http status")
)

type ComplianceClient struct {
	url    string
	client *http.Client
}

type ComplianceClientConfig struct {
	URL string
}

type PolicyData struct {
	PolicyID      string
	ProfileID     string
	TailoringData json.RawMessage
}

func NewClient(conf ComplianceClientConfig) *ComplianceClient {
	return &ComplianceClient{
		url:    conf.URL,
		client: &http.Client{},
	}
}

func (cc *ComplianceClient) request(ctx context.Context, method, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}

	id, ok := identity.GetIdentityHeader(ctx)
	if !ok {
		return nil, fmt.Errorf("unable to get identity from context")
	}
	req.Header.Add("x-rh-identity", id)
	req.Header.Add("content-type", "application/json")

	return strc.NewTracingDoer(cc.client).Do(req)
}

type v2PolicyResponse struct {
	Data v2PolicyData `json:"data"`
}

type v2PolicyData struct {
	ID             string `json:"id"`
	RefID          string `json:"ref_id"`
	OSMajorVersion int    `json:"os_major_version"`
}

func (cc *ComplianceClient) PolicyDataForMinorVersion(ctx context.Context, majorVersion, minorVersion int, policyID string) (*PolicyData, error) {
	policiesResp, err := cc.request(ctx, "GET", fmt.Sprintf("%s/policies/%s", cc.url, policyID))
	if err != nil {
		return nil, err
	}

	if policiesResp.StatusCode == http.StatusUnauthorized || policiesResp.StatusCode == http.StatusForbidden {
		return nil, ErrorAuth
	} else if policiesResp.StatusCode == http.StatusNotFound {
		return nil, ErrorPolicyNotFound
	} else if policiesResp.StatusCode != http.StatusOK {
		return nil, ErrorNotOk
	}

	defer policiesResp.Body.Close()
	var v2pr v2PolicyResponse
	err = json.NewDecoder(policiesResp.Body).Decode(&v2pr)
	if err != nil {
		return nil, err
	}

	if v2pr.Data.OSMajorVersion != majorVersion {
		return nil, ErrorMajorVersion
	}

	tailoringFileResp, err := cc.request(ctx, "GET", fmt.Sprintf("%s/policies/%s/tailorings/%d/tailoring_file.json", cc.url, policyID, minorVersion))
	if err != nil {
		return nil, err
	}
	defer tailoringFileResp.Body.Close()

	if tailoringFileResp.StatusCode == http.StatusUnauthorized || tailoringFileResp.StatusCode == http.StatusForbidden {
		return nil, ErrorAuth
	} else if tailoringFileResp.StatusCode == http.StatusNotFound {
		return nil, ErrorTailoringNotFound
	} else if tailoringFileResp.StatusCode != http.StatusOK && tailoringFileResp.StatusCode != http.StatusNoContent {
		return nil, ErrorNotOk
	}

	var tailoringData json.RawMessage
	// returns 204 if there's no tailoring attached to the policy
	if tailoringFileResp.StatusCode != http.StatusNoContent {
		tailoringData, err = io.ReadAll(tailoringFileResp.Body)
		if err != nil {
			return nil, err
		}
	}

	return &PolicyData{
		PolicyID:      v2pr.Data.ID,
		ProfileID:     v2pr.Data.RefID,
		TailoringData: tailoringData,
	}, nil
}

func (cc *ComplianceClient) PolicyCustomizations(ctx context.Context, majorVersion, minorVersion int, policyID string) (*blueprint.Blueprint, error) {
	blueprintResp, err := cc.request(ctx, "GET", fmt.Sprintf("%s/policies/%s/tailorings/%d/tailoring_file.toml", cc.url, policyID, minorVersion))
	if err != nil {
		return nil, err
	}
	defer blueprintResp.Body.Close()

	if blueprintResp.StatusCode == http.StatusUnauthorized || blueprintResp.StatusCode == http.StatusForbidden {
		return nil, ErrorAuth
	} else if blueprintResp.StatusCode == http.StatusNotFound {
		return nil, ErrorTailoringNotFound
	} else if blueprintResp.StatusCode != http.StatusOK && blueprintResp.StatusCode != http.StatusNoContent {
		return nil, ErrorNotOk
	}

	var bp blueprint.Blueprint
	dec := toml.NewDecoder(blueprintResp.Body)
	_, err = dec.Decode(&bp)
	if err != nil {
		return nil, fmt.Errorf("unable to parse blueprint for compliance policy: %w", err)
	}
	return &bp, nil
}
