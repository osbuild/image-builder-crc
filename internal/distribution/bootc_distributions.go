package distribution

import "fmt"

type BootcDistributionEntry struct {
	Distro    string `json:"distro"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Arch      string `json:"arch"`
	Reference string `json:"reference"`
}

func (arch *Architecture) ValidateBootcReference(reference string) error {
	if arch == nil {
		return fmt.Errorf("bootc reference '%s' not found", reference)
	}
	for _, image := range arch.Bootc {
		if image.Reference == reference {
			return nil
		}
	}

	return fmt.Errorf("bootc reference '%s' not found", reference)
}
