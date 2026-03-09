package distribution

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// BootcDistributionEntry represents one OS-version-type combination
// from the bootc distributions config file.
type BootcDistributionEntry struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	Image string `json:"image"`
}

// BootcDistributionsConfig is the root structure of the JSON config file.
type BootcDistributionsConfig struct {
	Distributions []BootcDistributionEntry `json:"distributions"`
}

// LoadBootcDistributions loads the list of bootc distributions from a JSON file.
// If path is empty, returns an empty list and nil error.
// If the file does not exist, returns an empty list and nil error (optional config).
func LoadBootcDistributions(path string) ([]BootcDistributionEntry, error) {
	if path == "" {
		return []BootcDistributionEntry{}, nil
	}

	cleaned := filepath.Clean(path)
	data, err := os.ReadFile(cleaned)
	if err != nil {
		if os.IsNotExist(err) {
			return []BootcDistributionEntry{}, nil
		}
		return nil, fmt.Errorf("reading bootc distributions file %q: %w", path, err)
	}

	var cfg BootcDistributionsConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing bootc distributions file %q: %w", path, err)
	}

	if cfg.Distributions == nil {
		return []BootcDistributionEntry{}, nil
	}
	return cfg.Distributions, nil
}

// FindBootcDistributionByID returns the entry with the given id and true,
// or false if not found.
func FindBootcDistributionByID(list []BootcDistributionEntry, id string) (BootcDistributionEntry, bool) {
	for _, e := range list {
		if e.ID == id {
			return e, true
		}
	}
	return BootcDistributionEntry{}, false
}
