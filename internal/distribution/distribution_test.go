package distribution

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/osbuild/image-builder-crc/internal/common"
)

func TestDistributionFile_Architecture(t *testing.T) {
	t.Parallel()
	d, err := distroReg.Available(false).Get("standard")
	require.NoError(t, err)

	arch, err := d.Architecture("x86_64")
	require.NoError(t, err)

	// don't test packages, they are huge — copy so we don't mutate the shared test registry
	archForCompare := *arch
	archForCompare.Packages = nil

	require.Equal(t, &Architecture{
		ImageTypes: []string{"std", "std2"},
		Repositories: []Repository{
			{
				Id:       "base",
				Baseurl:  common.ToPtr("https://std.example.com/base/x86_64"),
				Rhsm:     false,
				CheckGpg: common.ToPtr(true),
				GpgKey:   common.ToPtr("standard-gpgkey"),
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
	}, &archForCompare,
	)

	arch, err = d.Architecture("unsupported")
	require.Nil(t, arch)
	require.Error(t, err, "Architecture not supported")
}

func TestRHELMajorMinor(t *testing.T) {
	t.Parallel()
	d, err := distroReg.Available(true).Get("rhel-1.2")
	require.NoError(t, err)
	major, minor, err := d.RHELMajorMinor()
	require.NoError(t, err)
	require.Equal(t, 1, major)
	require.Equal(t, 2, minor)

	d, err = distroReg.Available(true).Get("standard")
	require.NoError(t, err)
	_, _, err = d.RHELMajorMinor()
	require.Error(t, err, ErrMajorMinor)
}

func TestArchitecture_FindPackages(t *testing.T) {
	t.Parallel()
	d, err := distroReg.Available(false).Get("standard")
	require.NoError(t, err)

	arch, err := d.Architecture("x86_64")
	require.NoError(t, err)

	pkgs := arch.FindPackages("pkg-base")
	require.ElementsMatch(t, []Package{
		{
			Name:    "pkg-base-1",
			Summary: "pkg-base-1",
		},
		{
			Name:    "pkg-base-2",
			Summary: "pkg-base-2",
		},
	}, pkgs)

	arch, err = d.Architecture("aarch64")
	require.NoError(t, err)

	// repos with image type tags are ignored
	pkgs = arch.FindPackages("other")
	require.Empty(t, pkgs)

	// check that a distro with no_package_list == true works
	d, err = distroReg.Available(true).Get("no-packages")
	require.NoError(t, err)

	arch, err = d.Architecture("x86_64")
	require.NoError(t, err)

	pkgs = arch.FindPackages("pkg")
	require.Nil(t, pkgs)
}

func TestInvalidDistribution(t *testing.T) {
	t.Parallel()
	_, err := readDistribution("./testdata/distributions", "none")
	require.Error(t, err, ErrDistributionNotFound)
}

func TestDistributionFileIsRestricted(t *testing.T) {
	t.Parallel()
	distsDir := "testdata/distributions"

	t.Run("distro is not restricted, has no restricted_access field", func(t *testing.T) {
		t.Parallel()
		d, err := readDistribution(distsDir, "standard")
		require.NoError(t, err)
		actual := d.IsRestricted()
		expected := false
		require.Equal(t, expected, actual)
	})

	t.Run("distro is not restricted, restricted_access field is false", func(t *testing.T) {
		t.Parallel()
		d, err := readDistribution(distsDir, "needs-entitlement")
		require.NoError(t, err)
		actual := d.IsRestricted()
		expected := false
		require.Equal(t, expected, actual)
	})

	t.Run("distro is restricted, restricted_access field is true", func(t *testing.T) {
		t.Parallel()
		d, err := readDistribution(distsDir, "restricted-access")
		require.NoError(t, err)
		actual := d.IsRestricted()
		expected := true
		require.Equal(t, expected, actual)
	})
}

func TestArchitecture_validate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		arch Architecture
		err  error
	}{
		{
			"good",
			Architecture{
				ImageTypes: nil,
				Repositories: []Repository{
					{Baseurl: common.ToPtr("http://example.com/repo1")},
					{Metalink: common.ToPtr("http://example.com/repo2")},
				},
				Packages: nil,
			},
			nil,
		},
		{
			"multiple-sources",
			Architecture{
				ImageTypes: nil,
				Repositories: []Repository{
					{
						Baseurl:  common.ToPtr("http://example.com/repo1"),
						Metalink: common.ToPtr("http://example.com/repo2"),
					},
				},
				Packages: nil,
			},
			ErrRepoSource,
		},
		{
			"no-source",
			Architecture{
				ImageTypes: nil,
				Repositories: []Repository{
					{},
				},
				Packages: nil,
			},
			ErrRepoSource,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.arch.validate()
			require.Equal(t, tt.err, err)
		})
	}
}
