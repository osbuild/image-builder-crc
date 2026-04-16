package distribution

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
		require.Equal(t, "test/ec2", list[0].Reference)
	})

	t.Run("empty registry returns empty list", func(t *testing.T) {
		adr := &AllDistroRegistry{distros: map[string]*DistributionFile{}}
		list := adr.CollectBootcFromRegistry()
		require.Empty(t, list)
	})
}
