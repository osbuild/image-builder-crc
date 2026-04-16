package distribution

type BootcDistributionEntry struct {
	Distro    string `json:"distro"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Arch      string `json:"arch"`
	Reference string `json:"reference"`
}
