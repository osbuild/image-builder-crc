package unleash

import (
	"context"
	"fmt"
	"maps"
	"net/http"

	"github.com/Unleash/unleash-client-go/v4"
	ucontext "github.com/Unleash/unleash-client-go/v4/context"
	fedora_identity "github.com/osbuild/community-gateway/oidc-authorizer/pkg/identity"
	rh_identity "github.com/redhatinsights/identity"
)

type FeatureFlag string

const (
	unleashProjectName = "default"
	unleashAppName     = "image-builder"

	CompliancePolicies  FeatureFlag = "image-builder.compliance-policies.enabled"
	BootcDistroDisabled FeatureFlag = "image-builder.bootc-distro.disabled"
)

type Config struct {
	URL   string
	Token string
}

func Initialize(conf Config) error {
	err := unleash.Initialize(
		unleash.WithProjectName(unleashProjectName),
		unleash.WithAppName(unleashAppName),
		unleash.WithListener(LogListener{}),
		unleash.WithUrl(conf.URL),
		unleash.WithCustomHeaders(http.Header{"Authorization": {conf.Token}}),
	)
	if err != nil {
		return fmt.Errorf("unleash error: %w", err)
	}

	return nil
}

// Enabled evaluates a feature flag without Unleash context.
func Enabled(flag FeatureFlag) bool {
	return IsEnabled(ucontext.Context{}, string(flag))
}

// IsEnabled evaluates a feature flag with Unleash user context.
func IsEnabled(uc ucontext.Context, name string) bool {
	return IsEnabledWithFallback(uc, name, true)
}

// EnabledCtx evaluates a feature flag with Unleash context derived from the request context.
func EnabledCtx(ctx context.Context, flag FeatureFlag) bool {
	return IsEnabled(unleashContextFromRequest(ctx), string(flag))
}

// EnabledBootcCtx reports whether bootc is allowed for the distro / image-type combination.
// It matches osDistro unleash flag against distroName first, then distroName+"-"+imageType.
// For disable-style flags, evaluation uses fallback false so missing or unknown state does not hide bootc.
func EnabledBootcCtx(ctx context.Context, flag FeatureFlag, distroName, imageType string) bool {
	uc := unleashContextFromRequest(ctx)
	if distroName != "" {
		if !IsEnabledWithFallback(withOsDistro(uc, distroName), string(flag), false) {
			return true
		}
	}
	if imageType == "" {
		return false
	}
	return !IsEnabledWithFallback(withOsDistro(uc, distroName+"-"+imageType), string(flag), false)
}

func withOsDistro(base ucontext.Context, osDistro string) ucontext.Context {
	out := ucontext.Context{
		UserId:        base.UserId,
		SessionId:     base.SessionId,
		RemoteAddress: base.RemoteAddress,
		Environment:   base.Environment,
		AppName:       base.AppName,
		CurrentTime:   base.CurrentTime,
		Properties:    make(map[string]string, len(base.Properties)+1),
	}
	maps.Copy(out.Properties, base.Properties)
	if osDistro != "" {
		out.Properties["osDistro"] = osDistro
	}
	return out
}

// IsEnabledWithFallback evaluates a feature flag (name, Unleash user context, SDK fallback default).
// Defaults to the Unleash client; tests may temporarily replace this variable and restore it afterward.
var IsEnabledWithFallback = defaultIsEnabledWithFallback

func defaultIsEnabledWithFallback(uc ucontext.Context, name string, fallback bool) bool {
	opts := []unleash.FeatureOption{unleash.WithFallback(fallback)}
	if uc.UserId != "" || len(uc.Properties) > 0 {
		opts = append(opts, unleash.WithContext(uc))
	}
	return unleash.IsEnabled(name, opts...)
}

func unleashContextFromRequest(ctx context.Context) ucontext.Context {
	if xrhid, ok := rh_identity.Get(ctx); ok {
		return unleashContextFromXRHID(xrhid)
	}
	if val := ctx.Value(fedora_identity.IDHeaderKey); val != nil {
		if fid, ok := val.(*fedora_identity.Identity); ok {
			return unleashContextFromFedora(fid)
		}
	}
	return ucontext.Context{}
}

func unleashContextFromXRHID(xrhid rh_identity.XRHID) ucontext.Context {
	uc := ucontext.Context{
		Properties: map[string]string{},
	}
	if org := xrhid.Identity.OrgID; org != "" {
		uc.Properties["orgId"] = org
	}
	user := xrhid.Identity.User.UserID
	if user == "" {
		user = xrhid.Identity.User.Username
	}
	if user == "" {
		user = xrhid.Identity.AccountNumber
	}
	uc.UserId = user
	return uc
}

func unleashContextFromFedora(fid *fedora_identity.Identity) ucontext.Context {
	uc := ucontext.Context{
		Properties: map[string]string{},
	}
	if fid.User != "" {
		uc.UserId = fid.User
		uc.Properties["orgId"] = fid.User
	}
	return uc
}
