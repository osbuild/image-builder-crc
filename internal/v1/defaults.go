package v1

import (
	"encoding/json"
	"errors"
)

var ErrMultipleUploadRequests = errors.New("multiple upload requests are not allowed")

func imageRequestsDefaults(obj *[]ImageRequest) {
	for i := range *obj {
		if (*obj)[i].Architecture == "" {
			(*obj)[i].Architecture = "x86_64"
		}

		if (*obj)[i].UploadRequest == nil {
			(*obj)[i].UploadRequest = &UploadRequest{
				Type: UploadTypesAwsS3,
				Options: UploadRequest_Options{
					union: json.RawMessage(`{"type": "aws.s3", "options": {}}`),
				},
			}
		}
	}
}

// BuildDefaults sets default values for the given field and checks for basic constraints.
func (obj *ComposeRequest) BuildDefaults() {
	imageRequestsDefaults(&obj.ImageRequests)
}

// BuildDefaults sets default values for the given field and checks for basic constraints.
func (obj *CreateBlueprintRequest) BuildDefaults() {
	imageRequestsDefaults(&obj.ImageRequests)
}
