package distribution

type BootcDistributionEntry struct {
	ID        string `json:"id"`
	Distro    string `json:"distro"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Arch      string `json:"arch"`
	ImageName string `json:"image_name"`
}
