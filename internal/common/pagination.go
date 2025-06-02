package common

import "fmt"

// Paginator is a generic type that provides pagination functionality.
// It allows you to paginate through a slice of items of any type T.
type Paginator[T any] struct {
	items  []T
	limit  int
	offset int
}

// NewPaginator creates a new Paginator instance with the provided items, limit, and offset.
func NewPaginator[T any](items []T, limit, offset int) (*Paginator[T], error) {
	if limit <= 0 {
		return nil, fmt.Errorf("limit cannot be less than or equal to zero: %d", limit)
	}
	if offset < 0 {
		return nil, fmt.Errorf("offset cannot be negative: %d", offset)
	}

	return &Paginator[T]{
		items:  items,
		limit:  limit,
		offset: offset,
	}, nil
}

// Limit returns the limit of items per page.
func (p *Paginator[T]) Limit() int {
	return p.limit
}

// Offset returns the current offset for pagination.
func (p *Paginator[T]) Offset() int {
	return p.offset
}

// Count returns the total number of items in the paginator.
func (p *Paginator[T]) Count() int {
	return len(p.items)
}

// Page returns the items for the current page based on the limit and offset.
// It returns an empty slice if the offset is greater than or equal to the total count.
func (p *Paginator[T]) Page() []T {
	start := p.offset
	end := start + p.limit
	if start >= p.Count() {
		return []T{}
	}
	if end > p.Count() {
		end = p.Count()
	}
	return p.items[start:end]
}

// LasetPageOffset returns the last page offset based on the total count and page size defined by the limit.
func (p *Paginator[T]) LastPageOffset() int {
	return CalculateLastPageOffset(p.Count(), p.limit)
}

// CalculateLastPageOffset calculates the offset for the last page based on the total count and limit.
func CalculateLastPageOffset(count, limit int) int {
	if limit >= count {
		return 0
	}
	return (count - 1) / limit * limit
}
