package v1

import (
	"errors"
	"reflect"
	"testing"
)

func TestToHTTPErrorList(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected HTTPErrorList
	}{
		{
			name: "single blueprintRuleError",
			err:  blueprintRuleError{title: "t1", detail: "d1"},
			expected: HTTPErrorList{
				Errors: []HTTPError{
					{Title: "t1", Detail: "d1"},
				},
			},
		},
		{
			name: "joined blueprintRuleErrors",
			err: errors.Join(
				blueprintRuleError{title: "t1", detail: "d1"},
				blueprintRuleError{title: "t2", detail: "d2"},
			),
			expected: HTTPErrorList{
				Errors: []HTTPError{
					{Title: "t1", Detail: "d1"},
					{Title: "t2", Detail: "d2"},
				},
			},
		},
		{
			name: "joined blueprintRuleError and other error",
			err: errors.Join(
				blueprintRuleError{title: "t1", detail: "d1"},
				errors.New("some other error"),
			),
			expected: HTTPErrorList{
				Errors: []HTTPError{
					{Title: "t1", Detail: "d1"},
					{Title: "blueprint rule error", Detail: "some other error"},
				},
			},
		},
		{
			name: "single other error",
			err:  errors.New("some other error"),
			expected: HTTPErrorList{
				Errors: []HTTPError{
					{Title: "blueprint rule error", Detail: "some other error"},
				},
			},
		},
		{
			name: "nil error",
			err:  nil,
			expected: HTTPErrorList{
				Errors: nil,
			},
		},
		{
			name: "nested joined errors",
			err: errors.Join(
				blueprintRuleError{title: "t1", detail: "d1"},
				errors.Join(
					blueprintRuleError{title: "t2", detail: "d2"},
					errors.New("some other error"),
				),
			),
			expected: HTTPErrorList{
				Errors: []HTTPError{
					{Title: "t1", Detail: "d1"},
					{Title: "t2", Detail: "d2"},
					{Title: "blueprint rule error", Detail: "some other error"},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := toHTTPErrorList(tc.err)
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Errorf("expected %+v, got %+v", tc.expected, actual)
			}
		})
	}
}
