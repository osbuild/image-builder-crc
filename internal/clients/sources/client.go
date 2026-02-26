package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"

	"github.com/osbuild/logging/pkg/strc"
	"github.com/redhatinsights/identity"
)

type SourcesClient struct {
	url    string
	client *http.Client

	awsResolver *AWSAccountIDResolver

	mu        sync.RWMutex
	appTypeID string
	// sourceTypeID -> provider name (e.g. "amazon" -> maps to "aws")
	sourceTypes map[string]string
}

type SourcesClientConfig struct {
	URL              string
	AWSAccessKeyID   string
	AWSSecretKey     string
	AWSDefaultRegion string
}

type Source struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	Provider string `json:"provider,omitempty"`
	Status   string `json:"status,omitempty"`
	UID      string `json:"uid,omitempty"`
}

func NewClient(conf SourcesClientConfig) (*SourcesClient, error) {
	sc := &SourcesClient{
		url:    conf.URL,
		client: &http.Client{},
	}

	if conf.AWSAccessKeyID != "" && conf.AWSSecretKey != "" {
		resolver, err := NewAWSAccountIDResolver(conf.AWSAccessKeyID, conf.AWSSecretKey, conf.AWSDefaultRegion)
		if err != nil {
			return nil, fmt.Errorf("unable to create AWS account ID resolver: %w", err)
		}
		sc.awsResolver = resolver
	}

	return sc, nil
}

func (sc *SourcesClient) request(ctx context.Context, method, requestURL string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, requestURL, body)
	if err != nil {
		return nil, err
	}

	id, ok := identity.GetIdentityHeader(ctx)
	if !ok {
		return nil, fmt.Errorf("unable to get identity from context")
	}
	req.Header.Add("x-rh-identity", id)

	return strc.NewTracingDoer(sc.client).Do(req)
}

const provisioningAppTypeName = "/insights/platform/provisioning"

// sourceTypeNameToProvider maps Sources API source type names to our provider names.
var sourceTypeNameToProvider = map[string]string{
	"amazon":          "aws",
	"azure":           "azure",
	"google":          "gcp",
	"oracle-cloud":    "oci",
	"ibm":             "ibm",
	"satellite":       "satellite",
	"openshift":       "openshift",
	"vsphere":         "vsphere",
	"ansible-tower":   "ansible",
	"terraform":       "terraform",
	"provisioning-ha": "provisioning-ha",
}

func providerForSourceType(sourceTypeName string) string {
	if p, ok := sourceTypeNameToProvider[sourceTypeName]; ok {
		return p
	}
	return sourceTypeName
}

// providerToSourceTypeName returns the Sources API source type name for a given provider.
var providerToSourceTypeName = map[string]string{
	"aws":   "amazon",
	"azure": "azure",
	"gcp":   "google",
}

type appTypeResponse struct {
	Data []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"data"`
}

type sourceTypeResponse struct {
	Data []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"data"`
}

type sourcesListResponse struct {
	Data []struct {
		ID                 *string `json:"id"`
		Name               *string `json:"name"`
		SourceTypeID       *string `json:"source_type_id"`
		UID                *string `json:"uid"`
		AvailabilityStatus *string `json:"availability_status"`
	} `json:"data"`
	Meta *struct {
		Count *int `json:"count"`
	} `json:"meta"`
}

type authenticationResponse struct {
	Data []struct {
		Authtype     *string `json:"authtype"`
		Username     *string `json:"username"`
		ResourceType *string `json:"resource_type"`
		ResourceID   *string `json:"resource_id"`
	} `json:"data"`
}

// ensureConstants lazily fetches and caches the provisioning app type ID and source type mapping.
func (sc *SourcesClient) ensureConstants(ctx context.Context) error {
	sc.mu.RLock()
	if sc.appTypeID != "" && sc.sourceTypes != nil {
		sc.mu.RUnlock()
		return nil
	}
	sc.mu.RUnlock()

	sc.mu.Lock()
	defer sc.mu.Unlock()

	// Double-check after acquiring write lock
	if sc.appTypeID != "" && sc.sourceTypes != nil {
		return nil
	}

	appTypeID, err := sc.loadAppTypeID(ctx)
	if err != nil {
		return err
	}
	sourceTypes, err := sc.loadSourceTypes(ctx)
	if err != nil {
		return err
	}

	sc.appTypeID = appTypeID
	sc.sourceTypes = sourceTypes
	return nil
}

func (sc *SourcesClient) loadAppTypeID(ctx context.Context) (string, error) {
	resp, err := sc.request(ctx, "GET", fmt.Sprintf("%s/application_types", sc.url), nil)
	if err != nil {
		return "", fmt.Errorf("failed to fetch application types: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("failed to fetch application types: status %d", resp.StatusCode)
	}

	var result appTypeResponse
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("could not unmarshal application type response: %w", err)
	}

	for _, t := range result.Data {
		if t.Name == provisioningAppTypeName {
			return t.ID, nil
		}
	}
	return "", fmt.Errorf("provisioning application type not found in Sources")
}

func (sc *SourcesClient) loadSourceTypes(ctx context.Context) (map[string]string, error) {
	resp, err := sc.request(ctx, "GET", fmt.Sprintf("%s/source_types", sc.url), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch source types: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("failed to fetch source types: status %d", resp.StatusCode)
	}

	var result sourceTypeResponse
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("could not unmarshal source types response: %w", err)
	}

	sourceTypes := make(map[string]string)
	for _, t := range result.Data {
		sourceTypes[t.ID] = t.Name
	}
	return sourceTypes, nil
}

// ListProvisioningSources lists sources associated with the provisioning application type,
// optionally filtered by provider (e.g. "aws", "azure", "gcp").
func (sc *SourcesClient) ListProvisioningSources(ctx context.Context, provider string) ([]Source, int, error) {
	if err := sc.ensureConstants(ctx); err != nil {
		return nil, 0, err
	}

	requestURL := fmt.Sprintf("%s/application_types/%s/sources", sc.url, sc.appTypeID)

	if provider != "" {
		sourceName, ok := providerToSourceTypeName[provider]
		if !ok {
			return nil, 0, fmt.Errorf("unknown provider: %s", provider)
		}
		requestURL += "?" + url.Values{
			"filter[source_type][name]": {sourceName},
		}.Encode()
	}

	resp, err := sc.request(ctx, "GET", requestURL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list sources: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, 0, fmt.Errorf("failed to list sources: status %d", resp.StatusCode)
	}

	var result sourcesListResponse
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, 0, fmt.Errorf("could not unmarshal sources response: %w", err)
	}

	sources := make([]Source, 0, len(result.Data))
	for _, src := range result.Data {
		s := Source{}
		if src.ID != nil {
			s.ID = *src.ID
		}
		if src.Name != nil {
			s.Name = *src.Name
		}
		if src.UID != nil {
			s.UID = *src.UID
		}
		if src.AvailabilityStatus != nil {
			s.Status = *src.AvailabilityStatus
		}
		if src.SourceTypeID != nil {
			if typeName, ok := sc.sourceTypes[*src.SourceTypeID]; ok {
				s.Provider = providerForSourceType(typeName)
			}
		}
		sources = append(sources, s)
	}

	total := len(sources)
	if result.Meta != nil && result.Meta.Count != nil {
		total = *result.Meta.Count
	}

	return sources, total, nil
}

// Authentication holds the result of resolving a source's provisioning credential.
type Authentication struct {
	ProviderType string
	Payload      string // ARN for AWS, Subscription ID for Azure, Project ID for GCP
}

// GetAuthentication retrieves the provisioning authentication for a given source.
// It filters for resource_type == "Application" and known provisioning auth types.
func (sc *SourcesClient) GetAuthentication(ctx context.Context, sourceID string) (*Authentication, error) {
	resp, err := sc.request(ctx, "GET", fmt.Sprintf("%s/sources/%s/authentications", sc.url, sourceID), nil)
	if err != nil {
		return nil, fmt.Errorf("cannot list source authentications: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("source %s not found", sourceID)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("failed to get authentications for source %s: status %d", sourceID, resp.StatusCode)
	}

	var result authenticationResponse
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("could not unmarshal authentications response: %w", err)
	}

	for _, auth := range result.Data {
		if auth.ResourceType == nil || *auth.ResourceType != "Application" {
			continue
		}
		if auth.Authtype == nil || auth.Username == nil {
			continue
		}
		switch *auth.Authtype {
		case "provisioning-arn":
			return &Authentication{ProviderType: "aws", Payload: *auth.Username}, nil
		case "provisioning_lighthouse_subscription_id":
			return &Authentication{ProviderType: "azure", Payload: *auth.Username}, nil
		case "provisioning_project_id":
			return &Authentication{ProviderType: "gcp", Payload: *auth.Username}, nil
		}
	}

	return nil, fmt.Errorf("no provisioning authentication found for source %s", sourceID)
}

// ResolveSourceToAWSAccountID resolves a source ID to a 12-digit AWS account ID
// by fetching the ARN from Sources and using STS AssumeRole + GetCallerIdentity.
func (sc *SourcesClient) ResolveSourceToAWSAccountID(ctx context.Context, sourceID string) (string, error) {
	auth, err := sc.GetAuthentication(ctx, sourceID)
	if err != nil {
		return "", fmt.Errorf("unable to get authentication for source %s: %w", sourceID, err)
	}

	if auth.ProviderType != "aws" {
		return "", fmt.Errorf("source %s is not an AWS source (provider: %s)", sourceID, auth.ProviderType)
	}

	if sc.awsResolver == nil {
		return "", fmt.Errorf("AWS account ID resolver is not configured")
	}

	accountID, err := sc.awsResolver.ResolveAccountID(ctx, auth.Payload)
	if err != nil {
		return "", fmt.Errorf("unable to resolve AWS account ID for source %s: %w", sourceID, err)
	}

	slog.InfoContext(ctx, "resolved source to AWS account ID", "source_id", sourceID, "account_id", accountID)
	return accountID, nil
}
