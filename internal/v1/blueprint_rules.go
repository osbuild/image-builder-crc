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

// RuleViolationError represents a rule violation that should be returned as HTTP 422
type RuleViolationError struct {
	HTTPErrorList HTTPErrorList
}

func (e RuleViolationError) Error() string {
	if len(e.HTTPErrorList.Errors) > 0 {
		return e.HTTPErrorList.Errors[0].Detail
	}
	return "rule violation"
}

// newRuleViolation creates a RuleViolationError with the given title and detail
func newRuleViolation(title, detail string) RuleViolationError {
	return RuleViolationError{
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

// BlueprintRuleChecker interface for the Chain of Responsibility pattern
type BlueprintRuleChecker interface {
	CheckRules(ctx echo.Context, request *CreateBlueprintRequest, existingUsers []User) error
}

// RuleCheckingChain manages a chain of blueprint rule checkers
type RuleCheckingChain struct {
	checkers []BlueprintRuleChecker
}

// CheckRules executes all rule checkers in the chain and collects all violations
func (rc *RuleCheckingChain) CheckRules(ctx echo.Context, request *CreateBlueprintRequest, existingUsers []User) error {
	var allViolations []HTTPError
	
	for _, checker := range rc.checkers {
		if err := checker.CheckRules(ctx, request, existingUsers); err != nil {
			if ruleViolationErr, ok := err.(RuleViolationError); ok {
				// Collect all violations from this checker
				allViolations = append(allViolations, ruleViolationErr.HTTPErrorList.Errors...)
			} else {
				// Handle unexpected error types
				allViolations = append(allViolations, HTTPError{
					Title:  "Rule Violation",
					Detail: err.Error(),
				})
			}
		}
	}
	
	if len(allViolations) > 0 {
		return RuleViolationError{
			HTTPErrorList: HTTPErrorList{
				Errors: allViolations,
			},
		}
	}
	
	return nil
}

// NameRuleChecker checks blueprint name rules
type NameRuleChecker struct{}

func (nrc *NameRuleChecker) CheckRules(ctx echo.Context, request *CreateBlueprintRequest, existingUsers []User) error {
	if !blueprintNameRegex.MatchString(request.Name) {
		return newRuleViolation("Blueprint name rule violation", blueprintInvalidNameDetail)
	}
	return nil
}

// UserRuleChecker checks blueprint user rules
type UserRuleChecker struct{}

func (urc *UserRuleChecker) CheckRules(ctx echo.Context, request *CreateBlueprintRequest, existingUsers []User) error {
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
			return newRuleViolation("User rule violation", err.Error())
		}
	}
	return nil
}

// FileRuleChecker checks blueprint file customization rules
type FileRuleChecker struct{}

func (frc *FileRuleChecker) CheckRules(ctx echo.Context, request *CreateBlueprintRequest, existingUsers []User) error {
	files := request.Customizations.Files
	if files == nil {
		return nil
	}

	for _, file := range *files {
		// Convert API types to fsnode types for rule checking
		mode := parseOctalMode(file.Mode)
		user := parseFileUser(file.User)
		group := parseFileGroup(file.Group)

		var data []byte
		if file.Data != nil {
			data = []byte(*file.Data)
		}

		// Use fsnode.NewFile for rule checking - this handles all path, mode, user, group rules
		_, err := fsnode.NewFile(file.Path, mode, user, group, data)
		if err != nil {
			return newRuleViolation("File rule violation", fmt.Sprintf("file %q: %s", file.Path, err.Error()))
		}
	}
	return nil
}

// DirectoryRuleChecker checks blueprint directory customization rules
type DirectoryRuleChecker struct{}

func (drc *DirectoryRuleChecker) CheckRules(ctx echo.Context, request *CreateBlueprintRequest, existingUsers []User) error {
	directories := request.Customizations.Directories
	if directories == nil {
		return nil
	}

	for _, dir := range *directories {
		// Convert API types to fsnode types for rule checking
		mode := parseOctalMode(dir.Mode)
		user := parseDirectoryUser(dir.User)
		group := parseDirectoryGroup(dir.Group)

		ensureParents := false
		if dir.EnsureParents != nil {
			ensureParents = *dir.EnsureParents
		}

		// Use fsnode.NewDirectory for rule checking - this handles all path, mode, user, group rules
		_, err := fsnode.NewDirectory(dir.Path, mode, user, group, ensureParents)
		if err != nil {
			return newRuleViolation("Directory rule violation", fmt.Sprintf("directory %q: %s", dir.Path, err.Error()))
		}
	}
	return nil
}

// FilesystemRuleChecker checks blueprint filesystem customization rules
type FilesystemRuleChecker struct{}

func (fsrc *FilesystemRuleChecker) CheckRules(ctx echo.Context, request *CreateBlueprintRequest, existingUsers []User) error {
	filesystem := request.Customizations.Filesystem
	if filesystem == nil {
		return nil
	}

	for _, fs := range *filesystem {
		// Use the same path rule checking logic as fsnode (following library patterns)
		if fs.Mountpoint == "" {
			return newRuleViolation("Filesystem rule violation", "mountpoint must not be empty")
		}
		if fs.Mountpoint[0] != '/' {
			return newRuleViolation("Filesystem rule violation", fmt.Sprintf("mountpoint %q must be absolute", fs.Mountpoint))
		}
		if fs.Mountpoint != filepath.Clean(fs.Mountpoint) {
			return newRuleViolation("Filesystem rule violation", fmt.Sprintf("mountpoint %q must be canonical", fs.Mountpoint))
		}

		// Check minimum size is reasonable
		if fs.MinSize > 0 && fs.MinSize < 1024*1024 { // 1MB minimum
			return newRuleViolation("Filesystem rule violation", fmt.Sprintf("mountpoint %q minimum size must be at least 1MB", fs.Mountpoint))
		}
	}
	return nil
}

// NewBlueprintRuleChecker creates a new rule checking chain with all checkers
func NewBlueprintRuleChecker() *RuleCheckingChain {
	return &RuleCheckingChain{
		checkers: []BlueprintRuleChecker{
			&NameRuleChecker{},
			&UserRuleChecker{},
			&FileRuleChecker{},
			&DirectoryRuleChecker{},
			&FilesystemRuleChecker{},
		},
	}
}

// CheckBlueprintRules performs common rule checking for blueprint requests
// using the Chain of Responsibility pattern
func CheckBlueprintRules(ctx echo.Context, blueprintRequest *CreateBlueprintRequest, existingUsers []User) error {
	chain := NewBlueprintRuleChecker()
	return chain.CheckRules(ctx, blueprintRequest, existingUsers)
}
