package common

import "fmt"

type Paginator[T any] struct {
	items  []T
	count  int
	limit  int
	offset int
}

func NewPaginator[T any](items []T, limit, offset int) (*Paginator[T], error) {
	if limit <= 0 {
		return nil, fmt.Errorf("limit cannot be less than or equal to zero: %d", limit)
	}
	if offset < 0 {
		return nil, fmt.Errorf("offset cannot be negative: %d", offset)
	}

	return &Paginator[T]{
		items:  items,
		count:  len(items),
		limit:  limit,
		offset: offset,
	}, nil
}

func (p *Paginator[T]) Limit() int {
	return p.limit
}

func (p *Paginator[T]) Offset() int {
	return p.offset
}

func (p *Paginator[T]) Count() int {
	return p.count
}

// GetPage returns the items for the current page based on the limit and offset.
// It returns an empty slice if the offset is greater than or equal to the total count.
func (p *Paginator[T]) GetPage() []T {
	start := p.offset
	end := start + p.limit
	if start >= p.count {
		return []T{}
	}
	if end > p.count {
		end = p.count
	}
	return p.items[start:end]
}

// LasetPageOffset returns the last page offset based on the total count and page size defined by the limit.
func (p *Paginator[T]) LastPageOffset() int {
	return CalculateLastPageOffset(p.count, p.limit)
}

func CalculateLastPageOffset(count, limit int) int {
	if limit >= count {
		return 0
	}
	return (count - 1) / limit * limit
}
