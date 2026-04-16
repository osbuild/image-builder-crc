package distribution

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestArchitectureValidateBootcReference(t *testing.T) {
	t.Run("returns nil when reference matches a bootc entry", func(t *testing.T) {
		arch := Architecture{
			Bootc: []BootcImage{
				{Type: "ec2", Reference: "ref-ec2"},
				{Type: "gcp", Reference: "ref-gcp"},
			},
		}
		require.NoError(t, arch.ValidateBootcReference("ref-ec2"))
		require.NoError(t, arch.ValidateBootcReference("ref-gcp"))
	})

	t.Run("returns error when reference is not in bootc list", func(t *testing.T) {
		arch := Architecture{
			Bootc: []BootcImage{{Type: "ec2", Reference: "r"}},
		}
		err := arch.ValidateBootcReference("other-ref")
		require.Error(t, err)
		require.Contains(t, err.Error(), "bootc reference 'other-ref' not found")
	})

	t.Run("returns error when bootc list is empty", func(t *testing.T) {
		arch := Architecture{Bootc: []BootcImage{}}
		err := arch.ValidateBootcReference("any-ref")
		require.Error(t, err)
		require.Contains(t, err.Error(), "bootc reference 'any-ref' not found")
	})
}

func TestCollectBootcFromRegistry(t *testing.T) {
	t.Run("collects bootc from distro architectures", func(t *testing.T) {
		adr, err := LoadDistroRegistry("testdata/distributions")
		require.NoError(t, err)
		list := adr.CollectBootcFromRegistry()
		require.Len(t, list, 1)
		require.Equal(t, "with-bootc", list[0].Distro)
		require.Equal(t, "Test distro with bootc entries", list[0].Name)
		require.Equal(t, "ec2", list[0].Type)
		require.Equal(t, "x86_64", list[0].Arch)
		require.Equal(t, "quay.io/redhat-services-prod/insights-management-tenant/image-builder-bootc-foundry/rhel-10.1-ec2:latest", list[0].Reference)
	})

	t.Run("empty registry returns empty list", func(t *testing.T) {
		adr := &AllDistroRegistry{distros: map[string]*DistributionFile{}}
		list := adr.CollectBootcFromRegistry()
		require.Empty(t, list)
	})
}
