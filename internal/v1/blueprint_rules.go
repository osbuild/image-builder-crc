package v1

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/osbuild/images/pkg/customizations/fsnode"
)

var (
	blueprintNameRegex         = regexp.MustCompile(`\S+`)
	blueprintInvalidNameDetail = "The blueprint name must contain at least two characters."
)

// ValidationError represents a validation error that should be returned as HTTP 422
type ValidationError struct {
	HTTPErrorList HTTPErrorList
}

func (e ValidationError) Error() string {
	if len(e.HTTPErrorList.Errors) > 0 {
		return e.HTTPErrorList.Errors[0].Detail
	}
	return "validation error"
}

// newValidationError creates a ValidationError with the given title and detail
func newValidationError(title, detail string) ValidationError {
	return ValidationError{
		HTTPErrorList: HTTPErrorList{
			Errors: []HTTPError{{
				Title:  title,
				Detail: detail,
			}},
		},
	}
}

// parseOctalMode parses an octal mode string to os.FileMode
func parseOctalMode(modeStr *string) *os.FileMode {
	if modeStr == nil {
		return nil
	}

	if modeVal, err := strconv.ParseUint(*modeStr, 8, 32); err == nil {
		m := os.FileMode(modeVal)
		return &m
	}
	return nil
}

// parseFileUser extracts user from File union type
func parseFileUser(fileUser *File_User) interface{} {
	if fileUser == nil {
		return nil
	}

	if userStr, err := fileUser.AsFileUser0(); err == nil {
		return userStr
	} else if userInt, err := fileUser.AsFileUser1(); err == nil {
		return userInt
	}
	return nil
}

// parseFileGroup extracts group from File union type
func parseFileGroup(fileGroup *File_Group) interface{} {
	if fileGroup == nil {
		return nil
	}

	if groupStr, err := fileGroup.AsFileGroup0(); err == nil {
		return groupStr
	} else if groupInt, err := fileGroup.AsFileGroup1(); err == nil {
		return groupInt
	}
	return nil
}

// parseDirectoryUser extracts user from Directory union type
func parseDirectoryUser(dirUser *Directory_User) interface{} {
	if dirUser == nil {
		return nil
	}

	if userStr, err := dirUser.AsDirectoryUser0(); err == nil {
		return userStr
	} else if userInt, err := dirUser.AsDirectoryUser1(); err == nil {
		return userInt
	}
	return nil
}

// parseDirectoryGroup extracts group from Directory union type
func parseDirectoryGroup(dirGroup *Directory_Group) interface{} {
	if dirGroup == nil {
		return nil
	}

	if groupStr, err := dirGroup.AsDirectoryGroup0(); err == nil {
		return groupStr
	} else if groupInt, err := dirGroup.AsDirectoryGroup1(); err == nil {
		return groupInt
	}
	return nil
}

// BlueprintValidator interface for the Chain of Responsibility pattern
type BlueprintValidator interface {
	Validate(ctx echo.Context, request *CreateBlueprintRequest, existingUsers []User) error
}

// ValidationChain manages a chain of blueprint validators
type ValidationChain struct {
	validators []BlueprintValidator
}

// Validate executes all validators in the chain and collects all errors
func (vc *ValidationChain) Validate(ctx echo.Context, request *CreateBlueprintRequest, existingUsers []User) error {
	var allErrors []HTTPError

	for _, validator := range vc.validators {
		if err := validator.Validate(ctx, request, existingUsers); err != nil {
			if validationErr, ok := err.(ValidationError); ok {
				// Collect all errors from this validator
				allErrors = append(allErrors, validationErr.HTTPErrorList.Errors...)
			} else {
				// Handle unexpected error types
				allErrors = append(allErrors, HTTPError{
					Title:  "Validation Error",
					Detail: err.Error(),
				})
			}
		}
	}

	if len(allErrors) > 0 {
		return ValidationError{
			HTTPErrorList: HTTPErrorList{
				Errors: allErrors,
			},
		}
	}

	return nil
}

// NameValidator validates blueprint names
type NameValidator struct{}

func (nv *NameValidator) Validate(ctx echo.Context, request *CreateBlueprintRequest, existingUsers []User) error {
	if !blueprintNameRegex.MatchString(request.Name) {
		return newValidationError("Invalid blueprint name", blueprintInvalidNameDetail)
	}
	return nil
}

// UserValidator validates blueprint users
type UserValidator struct{}

func (uv *UserValidator) Validate(ctx echo.Context, request *CreateBlueprintRequest, existingUsers []User) error {
	users := request.Customizations.Users
	if users == nil {
		return nil
	}

	for i, user := range *users {
		var err error
		if existingUsers != nil {
			err = (*users)[i].MergeForUpdate(existingUsers)
		} else {
			err = user.Valid()
		}

		if err != nil {
			return newValidationError("Invalid user", err.Error())
		}
	}
	return nil
}

// FileValidator validates blueprint file customizations
type FileValidator struct{}

func (fv *FileValidator) Validate(ctx echo.Context, request *CreateBlueprintRequest, existingUsers []User) error {
	files := request.Customizations.Files
	if files == nil {
		return nil
	}

	for _, file := range *files {
		// Convert API types to fsnode types for validation
		mode := parseOctalMode(file.Mode)
		user := parseFileUser(file.User)
		group := parseFileGroup(file.Group)

		var data []byte
		if file.Data != nil {
			data = []byte(*file.Data)
		}

		// Use fsnode.NewFile for validation - this handles all path, mode, user, group validation
		_, err := fsnode.NewFile(file.Path, mode, user, group, data)
		if err != nil {
			return newValidationError("Invalid file customization", fmt.Sprintf("file %q: %s", file.Path, err.Error()))
		}
	}
	return nil
}

// DirectoryValidator validates blueprint directory customizations
type DirectoryValidator struct{}

func (dv *DirectoryValidator) Validate(ctx echo.Context, request *CreateBlueprintRequest, existingUsers []User) error {
	directories := request.Customizations.Directories
	if directories == nil {
		return nil
	}

	for _, dir := range *directories {
		// Convert API types to fsnode types for validation
		mode := parseOctalMode(dir.Mode)
		user := parseDirectoryUser(dir.User)
		group := parseDirectoryGroup(dir.Group)

		ensureParents := false
		if dir.EnsureParents != nil {
			ensureParents = *dir.EnsureParents
		}

		// Use fsnode.NewDirectory for validation - this handles all path, mode, user, group validation
		_, err := fsnode.NewDirectory(dir.Path, mode, user, group, ensureParents)
		if err != nil {
			return newValidationError("Invalid directory customization", fmt.Sprintf("directory %q: %s", dir.Path, err.Error()))
		}
	}
	return nil
}

// FilesystemValidator validates blueprint filesystem customizations
type FilesystemValidator struct{}

func (fsv *FilesystemValidator) Validate(ctx echo.Context, request *CreateBlueprintRequest, existingUsers []User) error {
	filesystem := request.Customizations.Filesystem
	if filesystem == nil {
		return nil
	}

	for _, fs := range *filesystem {
		// Use the same path validation logic as fsnode (following library patterns)
		if fs.Mountpoint == "" {
			return newValidationError("Invalid filesystem customization", "mountpoint must not be empty")
		}
		if fs.Mountpoint[0] != '/' {
			return newValidationError("Invalid filesystem customization", fmt.Sprintf("mountpoint %q must be absolute", fs.Mountpoint))
		}
		if fs.Mountpoint != filepath.Clean(fs.Mountpoint) {
			return newValidationError("Invalid filesystem customization", fmt.Sprintf("mountpoint %q must be canonical", fs.Mountpoint))
		}

		// Validate minimum size is reasonable
		if fs.MinSize > 0 && fs.MinSize < 1024*1024 { // 1MB minimum
			return newValidationError("Invalid filesystem customization", fmt.Sprintf("mountpoint %q minimum size must be at least 1MB", fs.Mountpoint))
		}
	}
	return nil
}

// NewBlueprintValidationChain creates a new validation chain with all validators
func NewBlueprintValidationChain() *ValidationChain {
	return &ValidationChain{
		validators: []BlueprintValidator{
			&NameValidator{},
			&UserValidator{},
			&FileValidator{},
			&DirectoryValidator{},
			&FilesystemValidator{},
		},
	}
}

// ValidateBlueprintRequest performs common validation for blueprint requests
// using the Chain of Responsibility pattern
func ValidateBlueprintRequest(ctx echo.Context, blueprintRequest *CreateBlueprintRequest, existingUsers []User) error {
	chain := NewBlueprintValidationChain()
	return chain.Validate(ctx, blueprintRequest, existingUsers)
}
