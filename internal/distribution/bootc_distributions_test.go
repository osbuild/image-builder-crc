package distribution

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestArchitectureValidateBootcReference(t *testing.T) {
	t.Parallel()
	archBoth := Architecture{
		Bootc: []BootcImage{
			{Type: "ec2", Reference: "ref-ec2"},
			{Type: "gcp", Reference: "ref-gcp"},
		},
	}
	archEC2Only := Architecture{
		Bootc: []BootcImage{{Type: "ec2", Reference: "r"}},
	}
	archEmpty := Architecture{Bootc: []BootcImage{}}

	tests := []struct {
		name         string
		arch         Architecture
		reference    string
		wantErr      bool
		errSubstring string
	}{
		{
			name:      "reference matches first bootc entry",
			arch:      archBoth,
			reference: "ref-ec2",
		},
		{
			name:      "reference matches second bootc entry",
			arch:      archBoth,
			reference: "ref-gcp",
		},
		{
			name:         "reference not in bootc list",
			arch:         archEC2Only,
			reference:    "other-ref",
			wantErr:      true,
			errSubstring: "bootc reference 'other-ref' not found",
		},
		{
			name:         "empty bootc list",
			arch:         archEmpty,
			reference:    "any-ref",
			wantErr:      true,
			errSubstring: "bootc reference 'any-ref' not found",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.arch.ValidateBootcReference(tt.reference)
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errSubstring)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCollectBootcFromRegistry(t *testing.T) {
	t.Parallel()
	loaded, err := LoadDistroRegistry("testdata/distributions")
	require.NoError(t, err)

	tests := []struct {
		name      string
		registry  *AllDistroRegistry
		want      []BootcDistributionEntry
		wantEmpty bool
	}{
		{
			name:     "collects bootc from distro architectures",
			registry: loaded,
			want: []BootcDistributionEntry{
				{
					Distro:    "with-bootc",
					Name:      "Test distro with bootc entries",
					Type:      "ec2",
					Arch:      "x86_64",
					Reference: "quay.io/redhat-services-prod/insights-management-tenant/image-builder-bootc-foundry/rhel-10.1-ec2:latest",
				},
			},
		},
		{
			name:      "empty registry returns empty list",
			registry:  &AllDistroRegistry{distros: map[string]*DistributionFile{}},
			wantEmpty: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			list := tt.registry.CollectBootcFromRegistry()
			if tt.wantEmpty {
				require.Empty(t, list)
				return
			}
			require.Equal(t, tt.want, list)
		})
	}
}
