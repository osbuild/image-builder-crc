package distribution

import (
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
		"standard",
	}
	notEntitledDistros := []string{
		"no-packages",
		"restricted-access",
		"rhel-1.2",
		"standard",
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
