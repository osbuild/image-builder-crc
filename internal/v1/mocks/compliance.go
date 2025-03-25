package mocks

import (
	"encoding/json"
	"net/http"

	"github.com/osbuild/image-builder-crc/internal/tutils"
)

const (
	PolicyID = "2531793b-c607-4e1c-80b2-fbbaf9d12790"
)

func policies(w http.ResponseWriter, r *http.Request) {
	if tutils.AuthString0 != r.Header.Get("x-rh-identity") {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	if r.PathValue("id") == PolicyID {
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
				ID:             PolicyID,
				RefID:          "openscap-ref-id",
				OSMajorVersion: 8,
			},
		}
		err := json.NewEncoder(w).Encode(policyData)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}

func tailorings(w http.ResponseWriter, r *http.Request) {
	if tutils.AuthString0 != r.Header.Get("x-rh-identity") {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	if r.PathValue("id") != PolicyID {
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

func Compliance() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /policies/{id}", policies)
	mux.HandleFunc("GET /policies/{id}/tailorings/{minv}/tailoring_file.json", tailorings)
	return mux
}
