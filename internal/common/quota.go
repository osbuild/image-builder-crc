package common

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/osbuild/image-builder-crc/internal/db"
)

const (
	day                  time.Duration = 24 * time.Hour
	week                 time.Duration = 7 * day
	DefaultSlidingWindow time.Duration = 2 * week
	DefaultQuota         int           = 100
)

// the QUOTA_FILE needs to contain data arranged as such:
//
//	{
//	    "000000":{
//	        "quota":2,
//	        "slidingWindow":1209600000000000
//	    },
//	    "000001":{
//	        "quota":0,
//	        "slidingWindow":1209600000000000
//	    },
//	    "default":{
//	        "quota":100,
//	        "slidingWindow":1209600000000000
//	    }
//	}
//
// The unit for the sliding window is the nanosecond.
type Quota struct {
	Quota         int           `json:"quota"`
	SlidingWindow time.Duration `json:"slidingWindow"`
}

// QuotaResult contains the result of a quota check along with quota details.
type QuotaResult struct {
	Ok            bool
	Limit         int
	Used          int
	SlidingWindow time.Duration
}

// Returns a QuotaResult indicating if the number of requests made by OrgID during a sliding window is below a threshold.
// The duration of the sliding window and the value of the threshold must be set in a file pointed by the QUOTA_FILE
// environment variable.
// If the variable is unset (or an empty string), the check is disabled and always returns Ok=true.
func CheckQuota(ctx context.Context, orgID string, dB db.DB, quotaFile string) (QuotaResult, error) {
	if quotaFile == "" {
		return QuotaResult{Ok: true}, nil
	}
	var authorizedRequests int
	var slidingWindow time.Duration

	// read proper values from quotas' file
	var quotas map[string]Quota
	jsonFile, err := os.Open(filepath.Clean(quotaFile))
	if _, ok := err.(*os.PathError); ok {
		return QuotaResult{}, fmt.Errorf("no config file for quotas found at %s", quotaFile)
	} else {
		rawJsonFile, err := io.ReadAll(jsonFile)
		if err != nil {
			return QuotaResult{}, fmt.Errorf("failed to read quota file %q: %s", quotaFile, err.Error())
		}
		err = json.Unmarshal(rawJsonFile, &quotas)
		if err != nil {
			return QuotaResult{}, fmt.Errorf("failed to unmarshal quota file %q: %s", quotaFile, err.Error())
		}
		if quota, ok := quotas[orgID]; ok {
			authorizedRequests = quota.Quota
			slidingWindow = quota.SlidingWindow
		} else if quota, ok := quotas["default"]; ok {
			authorizedRequests = quota.Quota
			slidingWindow = quota.SlidingWindow
		} else {
			return QuotaResult{}, fmt.Errorf("no default values in the quotas file %s", quotaFile)
		}
	}

	// read user created requests
	count, err := dB.CountComposesSince(ctx, orgID, slidingWindow)
	if err != nil {
		return QuotaResult{}, err
	}
	return QuotaResult{
		Ok:            count < authorizedRequests,
		Limit:         authorizedRequests,
		Used:          count,
		SlidingWindow: slidingWindow,
	}, nil
}
