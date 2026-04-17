package distribution

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/osbuild/image-builder-crc/internal/common"
)

// distroReg is shared by tests that use internal/distribution/testdata/distributions.
var distroReg = MustLoadDistroRegistry("testdata/distributions")

func TestDistroRegistry_List(t *testing.T) {
	t.Parallel()
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

	dr := distroReg

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
	t.Parallel()
	dr := distroReg

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
	t.Parallel()
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
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.expected, registry.FindByMajorMinorStr(tc.input))
		})
	}
}
