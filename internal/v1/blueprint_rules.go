package v1

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/osbuild/images/pkg/customizations/fsnode"
	"github.com/osbuild/images/pkg/policies"
)

var (
	blueprintNameRegex         = regexp.MustCompile(`\S+`)
	blueprintInvalidNameDetail = "the blueprint name must contain at least two characters"
)

// blueprintRuleError wraps an error with HTTP response details
type blueprintRuleError struct {
	title  string
	detail string
}

func (ve blueprintRuleError) Error() string {
	return ve.detail
}

func newBlueprintRuleError(title, detail string) error {
	return blueprintRuleError{
		title:  title,
		detail: detail,
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
func parseFileUser(fileUser *File_User) any {
	if fileUser == nil {
		return nil
	}

	if userStr, err := fileUser.AsFileUser0(); err == nil {
		return userStr
	}
	if userInt, err := fileUser.AsFileUser1(); err == nil {
		return userInt
	}
	return nil
}

// parseFileGroup extracts group from File union type
func parseFileGroup(fileGroup *File_Group) any {
	if fileGroup == nil {
		return nil
	}

	if groupStr, err := fileGroup.AsFileGroup0(); err == nil {
		return groupStr
	}
	if groupInt, err := fileGroup.AsFileGroup1(); err == nil {
		return groupInt
	}
	return nil
}

// parseDirectoryUser extracts user from Directory union type
func parseDirectoryUser(dirUser *Directory_User) any {
	if dirUser == nil {
		return nil
	}

	if userStr, err := dirUser.AsDirectoryUser0(); err == nil {
		return userStr
	}
	if userInt, err := dirUser.AsDirectoryUser1(); err == nil {
		return userInt
	}
	return nil
}

// parseDirectoryGroup extracts group from Directory union type
func parseDirectoryGroup(dirGroup *Directory_Group) any {
	if dirGroup == nil {
		return nil
	}

	if groupStr, err := dirGroup.AsDirectoryGroup0(); err == nil {
		return groupStr
	}
	if groupInt, err := dirGroup.AsDirectoryGroup1(); err == nil {
		return groupInt
	}
	return nil
}

func checkNameRule(request *CreateBlueprintRequest) error {
	if !blueprintNameRegex.MatchString(request.Name) {
		return newBlueprintRuleError("blueprint name rule violation", blueprintInvalidNameDetail)
	}
	return nil
}

func checkUserRule(request *CreateBlueprintRequest, existingUsers []User) error {
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
			return newBlueprintRuleError("user rule violation", err.Error())
		}
	}
	return nil
}

func checkFileRule(request *CreateBlueprintRequest) error {
	files := request.Customizations.Files
	if files == nil {
		return nil
	}

	var errs []error
	for _, file := range *files {
		// Check path policy first
		if err := policies.CustomFilesPolicies.Check(file.Path); err != nil {
			errs = append(errs, newBlueprintRuleError(
				"file rule violation",
				fmt.Sprintf("file %q: %s", file.Path, err.Error()),
			))
			continue
		}

		mode := parseOctalMode(file.Mode)
		user := parseFileUser(file.User)
		group := parseFileGroup(file.Group)

		var data []byte
		if file.Data != nil {
			data = []byte(*file.Data)
		}

		_, err := fsnode.NewFile(file.Path, mode, user, group, data)
		if err != nil {
			errs = append(errs, newBlueprintRuleError(
				"file rule violation",
				fmt.Sprintf("file %q: %s", file.Path, err.Error()),
			))
		}
	}

	return errors.Join(errs...)
}

func checkDirectoryRule(request *CreateBlueprintRequest) error {
	directories := request.Customizations.Directories
	if directories == nil {
		return nil
	}

	var errs []error
	for _, dir := range *directories {
		// Check path policy first
		if err := policies.CustomDirectoriesPolicies.Check(dir.Path); err != nil {
			errs = append(errs, newBlueprintRuleError(
				"directory rule violation",
				fmt.Sprintf("directory %q: %s", dir.Path, err.Error()),
			))
			continue
		}

		mode := parseOctalMode(dir.Mode)
		user := parseDirectoryUser(dir.User)
		group := parseDirectoryGroup(dir.Group)

		ensureParents := false
		if dir.EnsureParents != nil {
			ensureParents = *dir.EnsureParents
		}

		_, err := fsnode.NewDirectory(dir.Path, mode, user, group, ensureParents)
		if err != nil {
			errs = append(errs, newBlueprintRuleError(
				"directory rule violation",
				fmt.Sprintf("directory %q: %s", dir.Path, err.Error()),
			))
		}
	}

	return errors.Join(errs...)
}

func checkFilesystemRule(request *CreateBlueprintRequest) error {
	filesystem := request.Customizations.Filesystem
	if filesystem == nil {
		return nil
	}

	var errs []error
	for _, fs := range *filesystem {
		if fs.Mountpoint == "" {
			errs = append(errs, newBlueprintRuleError(
				"filesystem rule violation",
				"mountpoint must not be empty",
			))
		} else if fs.Mountpoint[0] != '/' {
			errs = append(errs, newBlueprintRuleError(
				"filesystem rule violation",
				fmt.Sprintf("mountpoint %q must be absolute", fs.Mountpoint),
			))
		} else if fs.Mountpoint != filepath.Clean(fs.Mountpoint) {
			errs = append(errs, newBlueprintRuleError(
				"filesystem rule violation",
				fmt.Sprintf("mountpoint %q must be canonical", fs.Mountpoint),
			))
		}

		if fs.MinSize > 0 && fs.MinSize < 1024*1024 {
			errs = append(errs, newBlueprintRuleError(
				"filesystem rule violation",
				fmt.Sprintf("mountpoint %q minimum size must be at least 1MB", fs.Mountpoint),
			))
		}
	}

	return errors.Join(errs...)
}

// CheckBlueprintRules performs common rule checking for blueprint requests
func CheckBlueprintRules(ctx echo.Context, request *CreateBlueprintRequest, existingUsers []User) error {
	return errors.Join(
		checkNameRule(request),
		checkUserRule(request, existingUsers),
		checkFileRule(request),
		checkDirectoryRule(request),
		checkFilesystemRule(request),
	)
}
