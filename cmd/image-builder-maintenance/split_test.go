package main

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

func TestBodyWithSingleImageRequestPreservesOtherFields(t *testing.T) {
	original := json.RawMessage(`{
		"customizations": {"packages": ["vim"]},
		"distribution": "rhel-9",
		"image_requests": [
			{"image_type": "aws", "architecture": "x86_64"},
			{"image_type": "gcp", "architecture": "x86_64"}
		],
		"bootc": {"ref": "quay.io/example"}
	}`)
	requests, err := extractImageRequests(original)
	require.NoError(t, err)
	require.Len(t, requests, 2)

	body, err := bodyWithSingleImageRequest(original, requests[1])
	require.NoError(t, err)

	var parsed struct {
		Customizations json.RawMessage   `json:"customizations"`
		Distribution   string            `json:"distribution"`
		ImageRequests  []json.RawMessage `json:"image_requests"`
		Bootc          json.RawMessage   `json:"bootc"`
	}
	require.NoError(t, json.Unmarshal(body, &parsed))
	require.JSONEq(t, `{"packages": ["vim"]}`, string(parsed.Customizations))
	require.Equal(t, "rhel-9", parsed.Distribution)
	require.JSONEq(t, `{"ref": "quay.io/example"}`, string(parsed.Bootc))
	require.Len(t, parsed.ImageRequests, 1)
	require.JSONEq(t, string(requests[1]), string(parsed.ImageRequests[0]))
}

func TestIsMatchingSingleTarget(t *testing.T) {
	body := json.RawMessage(`{"image_requests":[{"image_type":"aws","architecture":"x86_64"}]}`)
	require.True(t, isMatchingSingleTarget(body, imageRequestMeta{ImageType: "aws", Architecture: "x86_64"}))
	require.False(t, isMatchingSingleTarget(body, imageRequestMeta{ImageType: "aws", Architecture: "aarch64"}))
	require.False(t, isMatchingSingleTarget(body, imageRequestMeta{ImageType: "gcp", Architecture: "x86_64"}))

	multi := json.RawMessage(`{"image_requests":[{"image_type":"aws"},{"image_type":"gcp"}]}`)
	require.False(t, isMatchingSingleTarget(multi, imageRequestMeta{ImageType: "aws"}))
}

func TestPreferredSplitNames(t *testing.T) {
	primary, secondary := preferredSplitNames("multi", imageRequestMeta{ImageType: "aws", Architecture: "x86_64"})
	require.Equal(t, "multi - aws", primary)
	require.Equal(t, "multi - aws-x86_64", secondary)

	long := strings.Repeat("a", blueprintNameMaxLen)
	primary, secondary = preferredSplitNames(long, imageRequestMeta{ImageType: "aws", Architecture: "x86_64"})
	require.Equal(t, strings.Repeat("a", blueprintNameMaxLen-len(" - aws"))+" - aws", primary)
	require.Equal(t, strings.Repeat("a", blueprintNameMaxLen-len(" - aws-x86_64"))+" - aws-x86_64", secondary)
	require.LessOrEqual(t, utf8.RuneCountInString(primary), blueprintNameMaxLen)
	require.LessOrEqual(t, utf8.RuneCountInString(secondary), blueprintNameMaxLen)
}
