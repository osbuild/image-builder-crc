package mocks

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/BurntSushi/toml"
	"github.com/osbuild/blueprint/pkg/blueprint"

	"github.com/osbuild/image-builder-crc/internal/tutils"
)

const (
	PolicyID        = "2531793b-c607-4e1c-80b2-fbbaf9d12790"
	PolicyID2       = "6b9bed55-153e-4315-b6c9-3e5d3985ef96"
	MinimalPolicyID = "eb2bf3d1-9308-45d0-84f6-d638f3928a63"
)

func policies(w http.ResponseWriter, r *http.Request) {
	if tutils.AuthString0 != r.Header.Get("x-rh-identity") {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	if !slices.Contains([]string{PolicyID, PolicyID2, MinimalPolicyID}, r.PathValue("id")) {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	policyData := struct {
		Data struct {
			ID             string `json:"id"`
			RefID          string `json:"ref_id"`
			OSMajorVersion int    `json:"os_major_version"`
		} `json:"data"`
	}{
		Data: struct {
			ID             string `json:"id"`
			RefID          string `json:"ref_id"`
			OSMajorVersion int    `json:"os_major_version"`
		}{
			ID:             r.PathValue("id"),
			RefID:          "openscap-ref-id",
			OSMajorVersion: 8,
		},
	}
	err := json.NewEncoder(w).Encode(policyData)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func tailorings(w http.ResponseWriter, r *http.Request) {
	if tutils.AuthString0 != r.Header.Get("x-rh-identity") {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	if !slices.Contains([]string{PolicyID, PolicyID2, MinimalPolicyID}, r.PathValue("id")) {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if r.PathValue("minv") != "10" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	tailoringData := "{ \"data\": \"some-tailoring-data\"}"
	_, err := w.Write([]byte(tailoringData))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func tailoredBlueprint(w http.ResponseWriter, r *http.Request) {
	if tutils.AuthString0 != r.Header.Get("x-rh-identity") {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/toml")

	if r.PathValue("minv") != "10" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var bp blueprint.Blueprint
	switch r.PathValue("id") {
	case PolicyID:
		bp = blueprint.Blueprint{
			Packages: []blueprint.Package{
				{
					Name:    "required-by-compliance",
					Version: "*",
				},
			},
			Customizations: &blueprint.Customizations{
				Services: &blueprint.ServicesCustomization{
					Enabled: []string{"enabled-required-by-compliance"},
					Masked:  []string{"masked-required-by-compliance"},
				},
			},
		}
	case PolicyID2:
		bp = blueprint.Blueprint{
			Customizations: &blueprint.Customizations{
				Kernel: &blueprint.KernelCustomization{
					Append: "-compliance",
				},
				Filesystem: []blueprint.FilesystemCustomization{
					{
						Mountpoint: "/tmp",
						MinSize:    20,
					},
					{
						Mountpoint: "/var",
						MinSize:    400,
					},
				},
			},
		}
	case MinimalPolicyID:
		bp = blueprint.Blueprint{
			Packages: []blueprint.Package{
				{
					Name:    "required-by-compliance",
					Version: "*",
				},
			},
		}
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}

	enc := toml.NewEncoder(w)
	err := enc.Encode(bp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func Compliance() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /policies/{id}", policies)
	mux.HandleFunc("GET /policies/{id}/tailorings/{minv}/tailoring_file.json", tailorings)
	mux.HandleFunc("GET /policies/{id}/tailorings/{minv}/tailoring_file.toml", tailoredBlueprint)
	return mux
}
