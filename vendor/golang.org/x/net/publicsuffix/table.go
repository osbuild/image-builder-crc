// generated by go run gen.go; DO NOT EDIT

package publicsuffix

import _ "embed"

const version = "publicsuffix.org's public_suffix_list.dat, git revision 63cbc63d470d7b52c35266aa96c4c98c96ec499c (2023-08-03T10:01:25Z)"

const (
	nodesBits           = 40
	nodesBitsChildren   = 10
	nodesBitsICANN      = 1
	nodesBitsTextOffset = 16
	nodesBitsTextLength = 6

	childrenBitsWildcard = 1
	childrenBitsNodeType = 2
	childrenBitsHi       = 14
	childrenBitsLo       = 14
)

const (
	nodeTypeNormal     = 0
	nodeTypeException  = 1
	nodeTypeParentOnly = 2
)

// numTLD is the number of top level domains.
const numTLD = 1474

// text is the combined text of all labels.
//
//go:embed data/text
var text string

// nodes is the list of nodes. Each node is represented as a 40-bit integer,
// which encodes the node's children, wildcard bit and node type (as an index
// into the children array), ICANN bit and text.
//
// The layout within the node, from MSB to LSB, is:
//
//	[ 7 bits] unused
//	[10 bits] children index
//	[ 1 bits] ICANN bit
//	[16 bits] text index
//	[ 6 bits] text length
//
//go:embed data/nodes
var nodes uint40String

// children is the list of nodes' children, the parent's wildcard bit and the
// parent's node type. If a node has no children then their children index
// will be in the range [0, 6), depending on the wildcard bit and node type.
//
// The layout within the uint32, from MSB to LSB, is:
//
//	[ 1 bits] unused
//	[ 1 bits] wildcard bit
//	[ 2 bits] node type
//	[14 bits] high nodes index (exclusive) of children
//	[14 bits] low nodes index (inclusive) of children
//
//go:embed data/children
var children uint32String

// max children 743 (capacity 1023)
// max text offset 30876 (capacity 65535)
// max text length 31 (capacity 63)
// max hi 9322 (capacity 16383)
// max lo 9317 (capacity 16383)
