package distribution

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadBootcDistributions(t *testing.T) {
	t.Run("empty path returns empty list", func(t *testing.T) {
		list, err := LoadBootcDistributions("")
		require.NoError(t, err)
		require.Empty(t, list)
	})

	t.Run("missing file returns empty list", func(t *testing.T) {
		list, err := LoadBootcDistributions("testdata/nonexistent.json")
		require.NoError(t, err)
		require.Empty(t, list)
	})

	t.Run("invalid JSON returns error", func(t *testing.T) {
		f := t.TempDir() + "/bad.json"
		require.NoError(t, os.WriteFile(f, []byte("{not json}"), 0o600))
		list, err := LoadBootcDistributions(f)
		require.Error(t, err)
		require.Nil(t, list)
	})

	t.Run("valid file returns distributions", func(t *testing.T) {
		list, err := LoadBootcDistributions("testdata/bootc_distributions.json")
		require.NoError(t, err)
		require.Len(t, list, 1)
		require.Equal(t, "rhel-10.0-ec2", list[0].ID)
		require.Equal(t, "Red Hat Enterprise Linux 10.0", list[0].Name)
		require.Equal(t, "ec2", list[0].Type)
		require.Equal(t, "rhel/10.0-ec2", list[0].Image)
	})
}

func TestFindBootcDistributionByID(t *testing.T) {
	list := []BootcDistributionEntry{
		{ID: "rhel-10.0-ec2", Name: "RHEL 10.0", Type: "ec2", Image: "rhel/10.0-ec2"},
	}

	t.Run("finds existing id", func(t *testing.T) {
		entry, ok := FindBootcDistributionByID(list, "rhel-10.0-ec2")
		require.True(t, ok)
		require.Equal(t, "rhel-10.0-ec2", entry.ID)
		require.Equal(t, "rhel/10.0-ec2", entry.Image)
	})

	t.Run("missing id returns false", func(t *testing.T) {
		entry, ok := FindBootcDistributionByID(list, "nonexistent")
		require.False(t, ok)
		require.Zero(t, entry)
	})

	t.Run("empty list returns false", func(t *testing.T) {
		_, ok := FindBootcDistributionByID(nil, "rhel-10.0-ec2")
		require.False(t, ok)
	})
}
