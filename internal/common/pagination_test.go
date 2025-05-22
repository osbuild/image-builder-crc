package common_test

import (
	"fmt"
	"testing"

	"github.com/osbuild/image-builder-crc/internal/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPaginatorBasic tests the basic functionality of the paginator.
// It checks the creation of the paginator with various limit and offset values.
// It also checks the getters for the paginator base properties.
func TestPaginatorBasic(t *testing.T) {
	testCases := []struct {
		name   string
		items  []int
		limit  int
		offset int
		err    error
	}{
		{
			name:   "valid case #1",
			items:  []int{1, 2, 3, 4, 5},
			limit:  10,
			offset: 0,
			err:    nil,
		},
		{
			name:   "valid case #2",
			items:  []int{1, 2, 3, 4, 5},
			limit:  2,
			offset: 1,
			err:    nil,
		},
		{
			name:   "valid case #3",
			items:  []int{},
			limit:  2,
			offset: 1,
			err:    nil,
		},
		{
			name:   "valid case #4",
			items:  []int{1, 2, 3},
			limit:  3,
			offset: 0,
			err:    nil,
		},
		{
			name:   "zero limit",
			items:  []int{1, 2, 3, 4, 5},
			limit:  0,
			offset: 0,
			err:    fmt.Errorf("limit cannot be less than or equal to zero: %d", 0),
		},
		{
			name:   "negative limit",
			items:  []int{1, 2, 3, 4, 5},
			limit:  -1,
			offset: 0,
			err:    fmt.Errorf("limit cannot be less than or equal to zero: %d", -1),
		},
		{
			name:   "negative offset",
			items:  []int{1, 2, 3, 4, 5},
			limit:  2,
			offset: -1,
			err:    fmt.Errorf("offset cannot be negative: %d", -1),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			paginator, err := common.NewPaginator(tc.items, tc.limit, tc.offset)
			if tc.err != nil {
				require.Error(t, err)
				assert.Equal(t, tc.err.Error(), err.Error())
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, paginator)
			assert.Equal(t, tc.limit, paginator.Limit())
			assert.Equal(t, tc.offset, paginator.Offset())
			assert.Equal(t, len(tc.items), paginator.Count())
		})
	}
}

func TestGetPage(t *testing.T) {
	testCases := []struct {
		name   string
		items  []int
		limit  int
		offset int
		page   []int
	}{
		{
			name:   "first page",
			items:  []int{1, 2, 3, 4, 5},
			limit:  2,
			offset: 0,
			page:   []int{1, 2},
		},
		{
			name:   "second page",
			items:  []int{1, 2, 3, 4, 5},
			limit:  2,
			offset: 2,
			page:   []int{3, 4},
		},
		{
			name:   "overflow page",
			items:  []int{1, 2, 3, 4, 5},
			limit:  2,
			offset: 5,
			page:   []int{},
		},
		{
			name:   "empty items",
			items:  []int{},
			limit:  2,
			offset: 0,
			page:   []int{},
		},
		{
			name:   "limit greater than items",
			items:  []int{1, 2, 3},
			limit:  5,
			offset: 0,
			page:   []int{1, 2, 3},
		},
		{
			name:   "limit equal to items",
			items:  []int{1, 2, 3},
			limit:  3,
			offset: 0,
			page:   []int{1, 2, 3},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			paginator, err := common.NewPaginator(tc.items, tc.limit, tc.offset)
			require.NoError(t, err)
			page := paginator.GetPage()
			assert.Equal(t, tc.page, page)
		})
	}
}

func TestLastPageOffset(t *testing.T) {
	testCases := []struct {
		name           string
		items          []int
		limit          int
		offset         int
		lastPageOffset int
	}{
		{
			name:           "case #1",
			items:          []int{1, 2, 3, 4, 5},
			limit:          2,
			offset:         0,
			lastPageOffset: 4,
		},
		{
			name:           "case #2",
			items:          []int{1, 2, 3, 4, 5},
			limit:          3,
			offset:         0,
			lastPageOffset: 3,
		},
		{
			name:           "case #3",
			items:          []int{1, 2, 3, 4, 5},
			limit:          5,
			offset:         0,
			lastPageOffset: 0,
		},
		{
			name:           "case #4",
			items:          []int{1, 2, 3, 4, 5},
			limit:          6,
			offset:         0,
			lastPageOffset: 0,
		},
		{
			name:           "case #5",
			items:          []int{1, 2, 3, 4, 5},
			limit:          1,
			offset:         0,
			lastPageOffset: 4,
		},
		{
			name:           "case #6",
			items:          []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
			limit:          5,
			offset:         2,
			lastPageOffset: 10,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			paginator, err := common.NewPaginator(tc.items, tc.limit, tc.offset)
			require.NoError(t, err)
			lastPageOffset := paginator.LastPageOffset()
			assert.Equal(t, tc.lastPageOffset, lastPageOffset)

			// Test the CalculateLastPageOffset function directly
			calculatedLastPageOffset := common.CalculateLastPageOffset(len(tc.items), tc.limit)
			assert.Equal(t, tc.lastPageOffset, calculatedLastPageOffset)
		})
	}
}
