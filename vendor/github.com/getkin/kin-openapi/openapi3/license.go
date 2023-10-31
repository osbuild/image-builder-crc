package openapi3

import (
	"context"
	"encoding/json"
	"errors"
)

// License is specified by OpenAPI/Swagger standard version 3.
// See https://github.com/OAI/OpenAPI-Specification/blob/main/versions/3.0.3.md#license-object
type License struct {
	Extensions map[string]interface{} `json:"-" yaml:"-"`

	Name string `json:"name" yaml:"name"` // Required
	URL  string `json:"url,omitempty" yaml:"url,omitempty"`
}

// MarshalJSON returns the JSON encoding of License.
func (license License) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{}, 2+len(license.Extensions))
	for k, v := range license.Extensions {
		m[k] = v
	}
	m["name"] = license.Name
	if x := license.URL; x != "" {
		m["url"] = x
	}
	return json.Marshal(m)
}

// UnmarshalJSON sets License to a copy of data.
func (license *License) UnmarshalJSON(data []byte) error {
	type LicenseBis License
	var x LicenseBis
	if err := json.Unmarshal(data, &x); err != nil {
		return err
	}
	_ = json.Unmarshal(data, &x.Extensions)
	delete(x.Extensions, "name")
	delete(x.Extensions, "url")
	*license = License(x)
	return nil
}

// Validate returns an error if License does not comply with the OpenAPI spec.
func (license *License) Validate(ctx context.Context, opts ...ValidationOption) error {
	ctx = WithValidationOptions(ctx, opts...)

	if license.Name == "" {
		return errors.New("value of license name must be a non-empty string")
	}

	return validateExtensions(ctx, license.Extensions)
}
