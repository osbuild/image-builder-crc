package distribution

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/osbuild/image-builder-crc/internal/common"
)

func TestDistroRegistry_List(t *testing.T) {
	allDistros := []string{
		"needs-entitlement",
		"no-packages",
		"restricted-access",
		"rhel-1.2",
		"rhel-34",
		"standard",
		"with-bootc",
	}
	notEntitledDistros := []string{
		"no-packages",
		"restricted-access",
		"rhel-1.2",
		"rhel-34",
		"standard",
		"with-bootc",
	}

	dr, err := LoadDistroRegistry("./testdata/distributions")
	require.NoError(t, err)

	result := dr.Available(true).List()
	require.Len(t, result, len(allDistros))
	for _, distro := range result {
		require.Contains(t, allDistros, distro.Distribution.Name)
	}

	result = dr.Available(false).List()
	require.Len(t, result, len(notEntitledDistros))
	for _, distro := range result {
		require.Contains(t, notEntitledDistros, distro.Distribution.Name)
	}
}

func TestDistroRegistry_Get(t *testing.T) {
	dr, err := LoadDistroRegistry("./testdata/distributions")
	require.NoError(t, err)

	result, err := dr.Available(true).Get("standard")
	require.NoError(t, err)
	require.Equal(t, "standard", result.Distribution.Name)
	require.Nil(t, err)

	pkgs := map[string][]Package{
		"base": []Package{
			{
				Name:    "pkg-base-1",
				Summary: "pkg-base-1",
			},
			{
				Name:    "pkg-base-2",
				Summary: "pkg-base-2",
			},
		},
		"other": []Package{
			{
				Name:    "pkg-other-1",
				Summary: "pkg-other-1",
			},
			{
				Name:    "pkg-other-2",
				Summary: "pkg-other-2",
			},
		},
	}

	require.Equal(t, &DistributionFile{
		ModulePlatformID: "platform:std",
		OscapName:        "standard",
		Distribution: DistributionItem{
			Description:      "A distribution with no frills",
			Name:             "standard",
			ComposerName:     common.ToPtr("composer-standard"),
			RestrictedAccess: false,
			NoPackageList:    false,
		},
		ArchX86: &Architecture{
			ImageTypes: []string{"std", "std2"},
			Repositories: []Repository{
				{
					Id:            "base",
					Baseurl:       common.ToPtr("https://std.example.com/base/x86_64"),
					Rhsm:          false,
					CheckGpg:      common.ToPtr(true),
					GpgKey:        common.ToPtr("standard-gpgkey"),
					ImageTypeTags: nil,
				},
				{
					Id:            "other",
					Baseurl:       common.ToPtr("https://std.example.com/other/x86_64"),
					Rhsm:          false,
					CheckGpg:      common.ToPtr(true),
					GpgKey:        common.ToPtr("standard-gpgkey"),
					ImageTypeTags: []string{"std2"},
				},
			},
			Packages: pkgs,
		},
		Aarch64: &Architecture{
			ImageTypes: []string{"std", "std2"},
			Repositories: []Repository{
				{
					Id:            "base",
					Baseurl:       common.ToPtr("https://std.example.com/base/aarch64"),
					Rhsm:          false,
					CheckGpg:      common.ToPtr(true),
					GpgKey:        common.ToPtr("standard-gpgkey"),
					ImageTypeTags: nil,
				},
				{
					Id:            "other",
					Baseurl:       common.ToPtr("https://std.example.com/other/aarch64"),
					Rhsm:          false,
					CheckGpg:      common.ToPtr(true),
					GpgKey:        common.ToPtr("standard-gpgkey"),
					ImageTypeTags: []string{"std2"},
				},
			},
			Packages: pkgs,
		},
	}, result)

	result, err = dr.Available(false).Get("toucan-42")
	require.Nil(t, result)
	require.Equal(t, ErrDistributionNotFound, err)
}

func TestDistroRegistry_FindByMajorMinorStr(t *testing.T) {
	dr, err := LoadDistroRegistry("./testdata/distributions")
	require.NoError(t, err)
	registry := dr.Available(true)

	cases := []struct {
		input    string
		expected string
		desc     string
	}{
		// rhel-1.2 has no composer_name → returns distribution name
		{"1.2", "rhel-1.2", "returns distribution name when no composer_name is set"},
		// rhel-3.4 has composer_name "rhel-3.4" → returns composer_name
		{"3.4", "rhel-3.4", "returns composer_name when set"},
		// no distribution matches this version
		{"9.99", "", "returns empty string for unknown version"},
		// malformed inputs
		{"notanumber", "", "returns empty string for non-numeric input"},
		{"1", "", "returns empty string when minor version is missing"},
		{"1.2.3", "", "returns empty string when minor part is not a plain integer"},
		{"", "", "returns empty string for empty input"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			require.Equal(t, tc.expected, registry.FindByMajorMinorStr(tc.input))
		})
	}
}

func TestDistroRegistry_ValidateBootcReference(t *testing.T) {
	dr, err := LoadDistroRegistry("./testdata/distributions")
	require.NoError(t, err)
	registry := dr.Available(true)

	cases := []struct {
		ref  string
		err  error
		desc string
	}{
		{"quay.io/redhat-services-prod/insights-management-tenant/image-builder-bootc-foundry/rhel-10.1-ec2:latest", nil, "returns nil error on valid reference"},
		{"duck", fmt.Errorf("bootc reference 'duck' not found"), "returns error on invalid reference"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			require.Equal(t, tc.err, registry.ValidateBootcReference(tc.ref))
		})
	}
}

func TestDistroRegistry_CollectBootcFromRegistry(t *testing.T) {
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
		t.Run(tt.name, func(t *testing.T) {
			list := tt.registry.CollectBootcFromRegistry()
			if tt.wantEmpty {
				require.Empty(t, list)
				return
			}
			require.Equal(t, tt.want, list)
		})
	}
}
