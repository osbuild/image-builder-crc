package unleash

import (
	"context"
	"testing"

	ucontext "github.com/Unleash/unleash-client-go/v4/context"
	fedora_identity "github.com/osbuild/community-gateway/oidc-authorizer/pkg/identity"
	"github.com/stretchr/testify/require"

	rh_identity "github.com/redhatinsights/identity"
)

func TestEnabled_and_EnabledCtx_swapped(t *testing.T) {
	rhCtx := context.WithValue(t.Context(), rh_identity.Key, rh_identity.XRHID{
		Identity: rh_identity.Identity{
			OrgID: "org-42",
			User:  rh_identity.User{Username: "bob"},
		},
	})
	fdCtx := context.WithValue(t.Context(), fedora_identity.IDHeaderKey, &fedora_identity.Identity{
		User: "fedora-user",
	})

	tests := []struct {
		name string
		stub func(t *testing.T, uc ucontext.Context, n string, fb bool) bool
		call func() bool
		want bool
	}{
		{
			name: "Enabled empty uc fallback true",
			stub: func(t *testing.T, uc ucontext.Context, n string, fb bool) bool {
				require.Empty(t, uc.UserId)
				require.True(t, fb)
				require.Equal(t, string(CompliancePolicies), n)
				return false
			},
			call: func() bool { return Enabled(CompliancePolicies) },
			want: false,
		},
		{
			name: "EnabledCtx RH identity",
			stub: func(t *testing.T, uc ucontext.Context, n string, fb bool) bool {
				require.Equal(t, string(CompliancePolicies), n)
				require.Equal(t, "bob", uc.UserId)
				require.Equal(t, "org-42", uc.Properties["orgId"])
				require.True(t, fb)
				return true
			},
			call: func() bool { return EnabledCtx(rhCtx, CompliancePolicies) },
			want: true,
		},
		{
			name: "EnabledCtx Fedora identity",
			stub: func(t *testing.T, uc ucontext.Context, n string, fb bool) bool {
				require.Equal(t, "fedora-user", uc.UserId)
				require.Equal(t, "fedora-user", uc.Properties["orgId"])
				return true
			},
			call: func() bool { return EnabledCtx(fdCtx, CompliancePolicies) },
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := IsEnabledWithFallback
			t.Cleanup(func() { IsEnabledWithFallback = orig })
			IsEnabledWithFallback = func(uc ucontext.Context, n string, fb bool) bool {
				return tt.stub(t, uc, n, fb)
			}
			require.Equal(t, tt.want, tt.call())
		})
	}
}

func TestEnabledBootcCtx_swapped(t *testing.T) {
	rhCtx := context.WithValue(t.Context(), rh_identity.Key, rh_identity.XRHID{
		Identity: rh_identity.Identity{
			OrgID: "1",
			User:  rh_identity.User{Username: "u"},
		},
	})

	tests := []struct {
		name      string
		stub      func(t *testing.T, calls *int) func(uc ucontext.Context, n string, fb bool) bool
		call      func() bool
		want      bool
		wantCalls int
	}{
		{
			name: "distro disabled then distro-type allowed",
			stub: func(t *testing.T, calls *int) func(uc ucontext.Context, n string, fb bool) bool {
				return func(uc ucontext.Context, n string, fb bool) bool {
					*calls++
					require.Equal(t, string(BootcDistroDisabled), n)
					require.False(t, fb)
					switch uc.Properties["osDistro"] {
					case "rhel-9":
						return true
					case "rhel-9-aws":
						return false
					default:
						t.Fatalf("unexpected osDistro %q", uc.Properties["osDistro"])
						return false
					}
				}
			},
			call:      func() bool { return EnabledBootcCtx(rhCtx, BootcDistroDisabled, "rhel-9", "aws") },
			want:      true,
			wantCalls: 2,
		},
		{
			name: "distro only blocked no imageType",
			stub: func(t *testing.T, calls *int) func(uc ucontext.Context, n string, fb bool) bool {
				return func(uc ucontext.Context, n string, fb bool) bool {
					*calls++
					require.Equal(t, "solo", uc.Properties["osDistro"])
					return true
				}
			},
			call:      func() bool { return EnabledBootcCtx(t.Context(), BootcDistroDisabled, "solo", "") },
			want:      false,
			wantCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := IsEnabledWithFallback
			t.Cleanup(func() { IsEnabledWithFallback = orig })
			var calls int
			IsEnabledWithFallback = tt.stub(t, &calls)
			require.Equal(t, tt.want, tt.call())
			require.Equal(t, tt.wantCalls, calls)
		})
	}
}

func TestIsEnabledWithFallback_defaultDoesNotPanic(t *testing.T) {
	orig := IsEnabledWithFallback
	t.Cleanup(func() { IsEnabledWithFallback = orig })
	IsEnabledWithFallback = defaultIsEnabledWithFallback
	require.NotPanics(t, func() { _ = Enabled(CompliancePolicies) })
}
