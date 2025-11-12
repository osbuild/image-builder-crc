package v1

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/osbuild/blueprint/pkg/blueprint"
	"github.com/osbuild/image-builder-crc/internal/clients/compliance"
	"github.com/osbuild/image-builder-crc/internal/common"
	"github.com/osbuild/image-builder-crc/internal/distribution"
)

// LinterOption specifies the behavior of OpenSCAP linting operations
type LinterOption int

const (
	// LinterOptionFixup performs linting and applies fixes to the input (mutates bpBody)
	LinterOptionFixup LinterOption = iota
	// LinterOptionNoFixup performs linting without modifying the input
	LinterOptionNoFixup
)

func OscapProfiles(distribution Distributions) (DistributionProfileResponse, error) {
	switch distribution {
	case Rhel8:
		fallthrough
	case Rhel84:
		fallthrough
	case Rhel85:
		fallthrough
	case Rhel86:
		fallthrough
	case Rhel87:
		fallthrough
	case Rhel88:
		fallthrough
	case Rhel89:
		fallthrough
	case Rhel8Nightly:
		return DistributionProfileResponse{
			XccdfOrgSsgprojectContentProfileAnssiBp28Enhanced,
			XccdfOrgSsgprojectContentProfileAnssiBp28High,
			XccdfOrgSsgprojectContentProfileAnssiBp28Intermediary,
			XccdfOrgSsgprojectContentProfileAnssiBp28Minimal,
			XccdfOrgSsgprojectContentProfileCis,
			XccdfOrgSsgprojectContentProfileCisServerL1,
			XccdfOrgSsgprojectContentProfileCisWorkstationL1,
			XccdfOrgSsgprojectContentProfileCisWorkstationL2,
			XccdfOrgSsgprojectContentProfileCui,
			XccdfOrgSsgprojectContentProfileE8,
			XccdfOrgSsgprojectContentProfileHipaa,
			XccdfOrgSsgprojectContentProfileIsmO,
			XccdfOrgSsgprojectContentProfileOspp,
			XccdfOrgSsgprojectContentProfilePciDss,
			XccdfOrgSsgprojectContentProfileStig,
			XccdfOrgSsgprojectContentProfileStigGui,
		}, nil
	case Centos9:
		fallthrough
	case Rhel9:
		fallthrough
	case Rhel91:
		fallthrough
	case Rhel92:
		fallthrough
	case Rhel93:
		fallthrough
	case Rhel94:
		fallthrough
	case Rhel95:
		fallthrough
	case Rhel96:
		fallthrough
	case Rhel97:
		fallthrough
	case Rhel96Nightly:
		fallthrough
	case Rhel97Nightly:
		fallthrough
	case Rhel98Nightly:
		fallthrough
	case Rhel99Nightly:
		fallthrough
	case Rhel9Nightly:
		return DistributionProfileResponse{
			XccdfOrgSsgprojectContentProfileAnssiBp28Enhanced,
			XccdfOrgSsgprojectContentProfileAnssiBp28High,
			XccdfOrgSsgprojectContentProfileAnssiBp28Intermediary,
			XccdfOrgSsgprojectContentProfileAnssiBp28Minimal,
			XccdfOrgSsgprojectContentProfileCcnAdvanced,
			XccdfOrgSsgprojectContentProfileCcnBasic,
			XccdfOrgSsgprojectContentProfileCcnIntermediate,
			XccdfOrgSsgprojectContentProfileCis,
			XccdfOrgSsgprojectContentProfileCisServerL1,
			XccdfOrgSsgprojectContentProfileCisWorkstationL1,
			XccdfOrgSsgprojectContentProfileCisWorkstationL2,
			XccdfOrgSsgprojectContentProfileCui,
			XccdfOrgSsgprojectContentProfileE8,
			XccdfOrgSsgprojectContentProfileHipaa,
			XccdfOrgSsgprojectContentProfileIsmO,
			XccdfOrgSsgprojectContentProfileOspp,
			XccdfOrgSsgprojectContentProfilePciDss,
			XccdfOrgSsgprojectContentProfileStig,
			XccdfOrgSsgprojectContentProfileStigGui,
		}, nil
	case Rhel100:
		fallthrough
	case Rhel101:
		fallthrough
	case Rhel10Nightly:
		fallthrough
	case Rhel100Nightly:
		fallthrough
	case Rhel101Nightly:
		fallthrough
	case Rhel102Nightly:
		fallthrough
	case Rhel103Nightly:
		fallthrough
	case Rhel10:
		return DistributionProfileResponse{
			XccdfOrgSsgprojectContentProfileAnssiBp28Enhanced,
			XccdfOrgSsgprojectContentProfileAnssiBp28High,
			XccdfOrgSsgprojectContentProfileAnssiBp28Intermediary,
			XccdfOrgSsgprojectContentProfileAnssiBp28Minimal,
			XccdfOrgSsgprojectContentProfileCis,
			XccdfOrgSsgprojectContentProfileCisServerL1,
			XccdfOrgSsgprojectContentProfileCisWorkstationL1,
			XccdfOrgSsgprojectContentProfileCisWorkstationL2,
			XccdfOrgSsgprojectContentProfileE8,
			XccdfOrgSsgprojectContentProfileHipaa,
			XccdfOrgSsgprojectContentProfileIsmO,
			XccdfOrgSsgprojectContentProfilePciDss,
			XccdfOrgSsgprojectContentProfileStig,
			XccdfOrgSsgprojectContentProfileStigGui,
		}, nil

	case Rhel90:
		fallthrough
	default:
		return nil, errors.New("no profile for the specified distribution")
	}
}

func loadOscapCustomizations(distributionDir string, distribution Distributions, profile DistributionProfileItem) (*Customizations, error) {
	//Load the json file with the customizations
	//Ignore the warning from gosec, as this function is only used internally. oscapDir comes from the server
	//configuration and Base path is gotten from the other params, so everything is fine security wise.
	jsonFile, err := os.Open(path.Join(
		distributionDir,
		string(distribution),
		"oscap",
		filepath.Base(string(profile)),
		"customizations.json")) // #nosec G304
	if err != nil {
		return nil, err
	}
	defer jsonFile.Close()
	bytes, err := io.ReadAll(jsonFile)
	if err != nil {
		return nil, err
	}
	// The customizations json file already contains a valid Customizations object to be returned as is.
	var customizations Customizations
	err = json.Unmarshal(bytes, &customizations)
	if err != nil {
		return nil, err
	}

	if customizations.Openscap == nil {
		// set the profile id in the customizations object
		return nil, errors.New("customizations file is missing OpenSCAP section")
	}

	return &customizations, nil
}

func (h *Handlers) GetOscapProfiles(ctx echo.Context, distribution Distributions) error {
	profiles, err := OscapProfiles(distribution)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}
	return ctx.JSON(http.StatusOK, profiles)
}

func (h *Handlers) GetOscapCustomizations(ctx echo.Context, distribution Distributions, profile DistributionProfileItem) error {
	customizations, err := loadOscapCustomizations(h.server.distributionsDir, distribution, profile)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}
	return ctx.JSON(http.StatusOK, customizations)
}

func (h *Handlers) GetOscapCustomizationsForPolicy(ctx echo.Context, policy uuid.UUID, distro Distributions) error {
	// lintOpenscap expects a Customizations object with Openscap field to extract policy information.
	// Since we only have a policy ID from the URL parameter, we create a temporary OpenSCAP object
	// to satisfy this API contract. The OpenSCAP object is removed from the response later.
	var openscap OpenSCAP
	err := openscap.FromOpenSCAPCompliance(OpenSCAPCompliance{
		PolicyId: policy,
	})
	if err != nil {
		return err
	}

	// create empty customizations with only openscap because
	// we need to store only that in the db.ServiceSnapshot that
	// we return (and that gets mutated by fixup=true)
	cust := Customizations{
		Openscap: &openscap,
	}
	_, _, err = h.lintAndFixupOpenscap(ctx, &cust, LinterOptionFixup, distro, nil)
	if err == distribution.ErrMajorMinor {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	} else if err == compliance.ErrorTailoringNotFound {
		return echo.NewHTTPError(http.StatusNotFound, err)
	} else if err != nil {
		return err
	}

	// Clear OpenSCAP from response - we only want the customizations, not the policy reference
	cust.Openscap = nil
	return ctx.JSON(http.StatusOK, cust)
}

// lintAndFixupOpenscap validates compliance policy requirements against blueprint customizations.
// bpBody should contain the current blueprint customizations including Openscap field with compliance policy
// information (policy ID). When option=LinterOptionFixup, missing customizations are automatically added to bpBody.
// snapshotCust contains previously saved policy customizations for comparison to detect removed requirements.
// Returns lint errors, warnings, and the original error for callers to handle appropriately.
func (h *Handlers) lintAndFixupOpenscap(ctx echo.Context, bpBody *Customizations, option LinterOption, distro Distributions, snapshotCust *Customizations) ([]BlueprintLintItem, []BlueprintLintItem, error) {
	var err error
	fixup := option == LinterOptionFixup

	if fixup && bpBody == nil {
		return nil, nil, fmt.Errorf("internal error: unable to fix blueprint compliance issues")
	}

	if bpBody.Openscap == nil {
		return []BlueprintLintItem{}, []BlueprintLintItem{}, nil
	}

	compl, err := bpBody.Openscap.AsOpenSCAPCompliance()
	if err != nil || compl.PolicyId == uuid.Nil {
		return []BlueprintLintItem{}, []BlueprintLintItem{}, nil
	}

	d, err := h.server.getDistro(ctx, distro)
	if err != nil {
		return nil, nil, err
	}
	major, minor, err := d.RHELMajorMinor()
	if err != nil {
		return nil, nil, err
	}

	var allErrors []BlueprintLintItem
	var allWarnings []BlueprintLintItem

	policyBP, err := h.server.complianceClient.PolicyCustomizations(ctx.Request().Context(), major, minor, compl.PolicyId.String())
	if err == compliance.ErrorTailoringNotFound {
		allErrors = append(allErrors, BlueprintLintItem{
			Name:        "Compliance",
			Description: "Compliance policy does not have a definition for the latest minor version",
		})
		return allErrors, allWarnings, err
	} else if err != nil {
		return nil, nil, echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	if policyBP == nil && fixup {
		return nil, nil, echo.NewHTTPError(http.StatusInternalServerError, fmt.Errorf("unexpected nil policyBP during fixup"))
	}

	// Collect errors and warnings from all lint functions (they now return instead of mutating)
	allErrors = append(allErrors, lintPackagesE(policyBP, bpBody, fixup)...)
	allWarnings = append(allWarnings, lintPackagesW(policyBP, snapshotCust)...)
	allErrors = append(allErrors, lintFilesystemsE(policyBP, bpBody, fixup)...)
	allWarnings = append(allWarnings, lintFilesystemsW(policyBP, snapshotCust)...)
	allErrors = append(allErrors, lintServicesE(policyBP, bpBody, fixup)...)
	allWarnings = append(allWarnings, lintServicesW(policyBP, snapshotCust)...)
	allErrors = append(allErrors, lintKernelE(policyBP, bpBody, fixup)...)
	allWarnings = append(allWarnings, lintKernelW(policyBP, snapshotCust)...)
	allErrors = append(allErrors, lintFIPSE(policyBP, bpBody, fixup)...)
	allWarnings = append(allWarnings, lintFIPSW(policyBP, snapshotCust)...)

	return allErrors, allWarnings, nil
}

// lintPackagesE validates packages required by current policy but missing from current blueprint
func lintPackagesE(policyBP *blueprint.Blueprint, currentCust *Customizations, fixup bool) []BlueprintLintItem {
	var errs []BlueprintLintItem

	if policyBP == nil {
		return errs
	}

	for _, pkg := range policyBP.GetPackagesEx(false) {
		if currentCust == nil || currentCust.Packages == nil || !slices.Contains(*currentCust.Packages, pkg) {
			errs = append(errs, BlueprintLintItem{
				Name:        "Compliance",
				Description: fmt.Sprintf("package %s required by policy is not present", pkg),
			})
			if fixup {
				currentCust.Packages = common.ToPtr(append(common.FromPtr(currentCust.Packages), pkg))
			}
		}
	}
	return errs
}

// lintPackagesW validates packages that were required by policy in snapshot but no longer required
func lintPackagesW(policyBP *blueprint.Blueprint, snapshotCust *Customizations) []BlueprintLintItem {
	var warns []BlueprintLintItem

	// Check for obsolete packages from snapshot - even if policyBP is nil,
	// as the policy might have changed to one without package requirements
	if snapshotCust == nil {
		return warns
	}

	for _, pkg := range common.FromPtr(snapshotCust.Packages) {
		if policyBP == nil || !slices.Contains(policyBP.GetPackagesEx(false), pkg) {
			warns = append(warns, BlueprintLintItem{
				Name:        "Compliance",
				Description: fmt.Sprintf("package %s is no longer required by policy", pkg),
			})
		}
	}
	return warns
}

// lintFilesystemsE validates filesystems required by current policy but missing from current blueprint
func lintFilesystemsE(policyBP *blueprint.Blueprint, currentCust *Customizations, fixup bool) []BlueprintLintItem {
	var errs []BlueprintLintItem

	if policyBP == nil || policyBP.Customizations == nil {
		return errs
	}

	for _, fsc := range policyBP.Customizations.GetFilesystems() {
		if currentCust == nil || currentCust.Filesystem == nil || !slices.ContainsFunc(*currentCust.Filesystem, func(fs Filesystem) bool { return fs.Mountpoint == fsc.Mountpoint }) {
			errs = append(errs, BlueprintLintItem{
				Name:        "Compliance",
				Description: fmt.Sprintf("mountpoint %s required by policy is not present", fsc.Mountpoint),
			})
			if fixup {
				currentCust.Filesystem = common.ToPtr(append(common.FromPtr(currentCust.Filesystem), Filesystem{
					Mountpoint: fsc.Mountpoint,
					MinSize:    fsc.MinSize,
				}))
			}
		}
	}
	return errs
}

// lintFilesystemsW validates filesystems in saved policy no longer required
func lintFilesystemsW(policyBP *blueprint.Blueprint, snapshotCust *Customizations) []BlueprintLintItem {
	var warns []BlueprintLintItem

	// Check for obsolete filesystems from snapshot - even if policyBP is nil,
	// as the policy might have changed to one without filesystem requirements
	if snapshotCust == nil {
		return warns
	}

	policyFilesystems := policyBP.Customizations.GetFilesystems()
	for _, fs := range common.FromPtr(snapshotCust.Filesystem) {
		if !slices.ContainsFunc(policyFilesystems, func(fsc blueprint.FilesystemCustomization) bool { return fsc.Mountpoint == fs.Mountpoint }) {
			warns = append(warns, BlueprintLintItem{
				Name:        "Compliance",
				Description: fmt.Sprintf("mountpoint %s is no longer required by policy", fs.Mountpoint),
			})
		}
	}
	return warns
}

// lintServicesE validates services required by current policy but missing from current blueprint
func lintServicesE(policyBP *blueprint.Blueprint, currentCust *Customizations, fixup bool) []BlueprintLintItem {
	var errs []BlueprintLintItem

	if policyBP == nil || policyBP.Customizations == nil {
		return errs
	}

	services := policyBP.Customizations.GetServices()
	if services == nil {
		return errs
	}

	for _, e := range services.Enabled {
		if currentCust == nil || currentCust.Services == nil || currentCust.Services.Enabled == nil || !slices.Contains(*currentCust.Services.Enabled, e) {
			errs = append(errs, BlueprintLintItem{
				Name:        "Compliance",
				Description: fmt.Sprintf("service %s required as enabled by policy is not present", e),
			})
			if fixup {
				currentCust.Services = common.ToPtr(common.FromPtr(currentCust.Services))
				currentCust.Services.Enabled = common.ToPtr(append(common.FromPtr(currentCust.Services.Enabled), e))
			}
		}
	}
	for _, m := range services.Masked {
		if currentCust == nil || currentCust.Services == nil || currentCust.Services.Masked == nil || !slices.Contains(*currentCust.Services.Masked, m) {
			errs = append(errs, BlueprintLintItem{
				Name:        "Compliance",
				Description: fmt.Sprintf("service %s required as masked by policy is not present", m),
			})
			if fixup {
				currentCust.Services = common.ToPtr(common.FromPtr(currentCust.Services))
				currentCust.Services.Masked = common.ToPtr(append(common.FromPtr(currentCust.Services.Masked), m))
			}
		}
	}
	for _, d := range services.Disabled {
		if currentCust == nil || currentCust.Services == nil || currentCust.Services.Disabled == nil || !slices.Contains(*currentCust.Services.Disabled, d) {
			errs = append(errs, BlueprintLintItem{
				Name:        "Compliance",
				Description: fmt.Sprintf("service %s required as disabled by policy is not present", d),
			})
			if fixup {
				currentCust.Services = common.ToPtr(common.FromPtr(currentCust.Services))
				currentCust.Services.Disabled = common.ToPtr(append(common.FromPtr(currentCust.Services.Disabled), d))
			}
		}
	}
	return errs
}

// lintServicesW validates services from saved policy no longer required by current policy
func lintServicesW(policyBP *blueprint.Blueprint, snapshotCust *Customizations) []BlueprintLintItem {
	var warns []BlueprintLintItem

	// Check for obsolete services from snapshot - even if policyBP is nil,
	// as the policy might have changed to one without service requirements
	if snapshotCust == nil || snapshotCust.Services == nil {
		return warns
	}

	policyServices := policyBP.Customizations.GetServices()

	checkObsoleteServices := func(services *[]string, serviceType string, isStillRequired func(string) bool) []BlueprintLintItem {
		var serviceWarns []BlueprintLintItem
		if services == nil {
			return serviceWarns
		}
		for _, service := range *services {
			if !isStillRequired(service) {
				serviceWarns = append(serviceWarns, BlueprintLintItem{
					Name:        "Compliance",
					Description: fmt.Sprintf("service %s is no longer required as %s by policy", service, serviceType),
				})
			}
		}
		return serviceWarns
	}

	warns = append(warns, checkObsoleteServices(snapshotCust.Services.Enabled, "enabled", func(service string) bool {
		return policyServices != nil && slices.Contains(policyServices.Enabled, service)
	})...)

	warns = append(warns, checkObsoleteServices(snapshotCust.Services.Masked, "masked", func(service string) bool {
		return policyServices != nil && slices.Contains(policyServices.Masked, service)
	})...)

	warns = append(warns, checkObsoleteServices(snapshotCust.Services.Disabled, "disabled", func(service string) bool {
		return policyServices != nil && slices.Contains(policyServices.Disabled, service)
	})...)

	return warns
}

// lintKernelE validates kernel settings required by current policy but missing from current blueprint
func lintKernelE(policyBP *blueprint.Blueprint, currentCust *Customizations, fixup bool) []BlueprintLintItem {
	var errs []BlueprintLintItem

	if policyBP == nil || policyBP.Customizations == nil || policyBP.Customizations.Kernel == nil {
		return errs
	}

	policyKernel := policyBP.Customizations.Kernel
	currentName := common.FromPtr(common.FromPtr(currentCust.Kernel).Name)
	currentAppend := common.FromPtr(common.FromPtr(currentCust.Kernel).Append)

	if policyKernel.Name != "" && currentName != policyKernel.Name {
		errs = append(errs, BlueprintLintItem{
			Name:        "Compliance",
			Description: fmt.Sprintf("kernel name %s required by policy not set", policyKernel.Name),
		})
		if fixup {
			currentCust.Kernel = common.ToPtr(common.FromPtr(currentCust.Kernel))
			currentCust.Kernel.Name = &policyKernel.Name
		}
	}

	for _, param := range strings.Split(policyKernel.Append, " ") {
		if param != "" && !strings.Contains(currentAppend, param) {
			errs = append(errs, BlueprintLintItem{
				Name:        "Compliance",
				Description: fmt.Sprintf("kernel command line parameter '%s' required by policy not set", param),
			})
			if fixup {
				currentCust.Kernel = common.ToPtr(common.FromPtr(currentCust.Kernel))
				currentCust.Kernel.Append = common.ToPtr(currentAppend + " " + param)
			}
		}
	}
	return errs
}

// lintKernelW validates kernel settings from saved policy no longer required
func lintKernelW(policyBP *blueprint.Blueprint, snapshotCust *Customizations) []BlueprintLintItem {
	var warns []BlueprintLintItem

	// Check for obsolete settings from snapshot - even if policyBP is nil,
	// as the policy might have changed to one without kernel customizations
	if snapshotCust == nil || snapshotCust.Kernel == nil {
		return warns
	}

	snapshotName := common.FromPtr(snapshotCust.Kernel.Name)
	snapshotAppend := common.FromPtr(snapshotCust.Kernel.Append)

	var policyKernel *blueprint.KernelCustomization
	if policyBP != nil && policyBP.Customizations != nil {
		policyKernel = policyBP.Customizations.Kernel
	}

	// Warn about obsolete kernel name
	if snapshotName != "" && (policyKernel == nil || policyKernel.Name != snapshotName) {
		warns = append(warns, BlueprintLintItem{
			Name:        "Compliance",
			Description: fmt.Sprintf("kernel name %s is no longer required by policy", snapshotName),
		})
	}

	// Warn about obsolete kernel parameters
	for _, param := range strings.Split(snapshotAppend, " ") {
		if param != "" && (policyKernel == nil || !strings.Contains(policyKernel.Append, param)) {
			warns = append(warns, BlueprintLintItem{
				Name:        "Compliance",
				Description: fmt.Sprintf("kernel command line parameter '%s' is no longer required by policy", param),
			})
		}
	}
	return warns
}

// lintFIPSE validates FIPS settings required by current policy but missing from current blueprint
func lintFIPSE(policyBP *blueprint.Blueprint, currentCust *Customizations, fixup bool) []BlueprintLintItem {
	var errs []BlueprintLintItem
	if policyBP == nil || policyBP.Customizations == nil {
		return errs
	}

	// Determine policy FIPS requirement if present
	policyFIPS := policyBP.Customizations.FIPS

	// If policy explicitly requires FIPS
	if policyFIPS != nil && *policyFIPS {
		fipsNotSet := currentCust == nil || currentCust.Fips == nil || currentCust.Fips.Enabled == nil || !*currentCust.Fips.Enabled
		if fipsNotSet {
			errs = append(errs, BlueprintLintItem{
				Name:        "Compliance",
				Description: fmt.Sprintf("FIPS required '%t' by policy but not set", *policyFIPS),
			})
			if fixup {
				currentCust.Fips = &FIPS{Enabled: policyFIPS}
			}
		}
	}
	return errs
}

// lintFIPSW validates FIPS settings from saved policy no longer required
func lintFIPSW(policyBP *blueprint.Blueprint, snapshotCust *Customizations) []BlueprintLintItem {
	var warns []BlueprintLintItem

	// Check for obsolete FIPS from snapshot - even if policyBP is nil,
	// as the policy might have changed to one without FIPS requirements
	if snapshotCust == nil || snapshotCust.Fips == nil || snapshotCust.Fips.Enabled == nil || !*snapshotCust.Fips.Enabled {
		return warns
	}

	// Determine policy FIPS requirement if present
	var policyFIPS *bool
	if policyBP != nil && policyBP.Customizations != nil {
		policyFIPS = policyBP.Customizations.FIPS
	}

	// Warnings: saved policy had FIPS enabled previously but not now
	if policyFIPS == nil || !*policyFIPS {
		warns = append(warns, BlueprintLintItem{
			Name:        "Compliance",
			Description: "FIPS is no longer required by policy",
		})
	}
	return warns
}
