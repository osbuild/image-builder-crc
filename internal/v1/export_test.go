package v1

import (
	"github.com/osbuild/image-builder-crc/internal/db"
)

var (
	BuildOSTreeOptions      = buildOSTreeOptions
	ValidateComposeRequest  = validateComposeRequest
	ParseComposeStatusError = parseComposeStatusError
)

func (s *Server) GetDB() db.DB {
	return s.db
}
