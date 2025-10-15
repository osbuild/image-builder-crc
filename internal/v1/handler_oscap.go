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
	case Rhel96Nightly:
		fallthrough
	case Rhel97Nightly:
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
	case Rhel10Nightly:
		fallthrough
	case Rhel100Nightly:
		fallthrough
	case Rhel101Nightly:
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
	var cust Customizations
	_, _, err := h.lintOpenscap(ctx, &cust, true, distro, policy.String(), nil)
	if err == distribution.ErrMajorMinor {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	} else if err == compliance.ErrorTailoringNotFound {
		return echo.NewHTTPError(http.StatusNotFound, err)
	} else if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, cust)
}

func (h *Handlers) lintOpenscap(ctx echo.Context, cust *Customizations, fixup bool, distro Distributions, policy string, savedPolicy *Customizations) ([]BlueprintLintItem, []BlueprintLintItem, error) {
	var err error

	d, err := h.server.getDistro(ctx, distro)
	if err != nil {
		return nil, nil, err
	}
	major, minor, err := d.RHELMajorMinor()
	if err != nil {
		return nil, nil, err
	}
	bp, err := h.server.complianceClient.PolicyCustomizations(ctx.Request().Context(), major, minor, policy)
	if err == compliance.ErrorTailoringNotFound {
		return nil, nil, err
	} else if err != nil {
		return nil, nil, echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	var lintErrors []BlueprintLintItem
	var lintWarnings []BlueprintLintItem

	// Collect errors and warnings from all lint functions
	h.lintPackages(bp, savedPolicy, cust, fixup, &lintErrors, &lintWarnings)
	h.lintFilesystems(bp, savedPolicy, cust, fixup, &lintErrors, &lintWarnings)
	h.lintServices(bp, savedPolicy, cust, fixup, &lintErrors, &lintWarnings)
	h.lintKernel(bp, savedPolicy, cust, fixup, &lintErrors, &lintWarnings)
	h.lintFIPS(bp, savedPolicy, cust, fixup, &lintErrors, &lintWarnings)

	return lintErrors, lintWarnings, nil
}

// lintPackages validates package compliance by performing two comparisons:
// 1. ERRORS: Packages required by current policy but missing from current blueprint
// 2. WARNINGS: Packages that were required by policy in snapshot but no longer required
func (h *Handlers) lintPackages(bp *blueprint.Blueprint, savedPolicy, cust *Customizations, fixup bool, lintErrors *[]BlueprintLintItem, lintWarnings *[]BlueprintLintItem) {
	// Check for packages required by current policy but missing from current blueprint (ERRORS)
	for _, pkg := range bp.GetPackagesEx(false) {
		if cust.Packages == nil || !slices.Contains(*cust.Packages, pkg) {
			*lintErrors = append(*lintErrors, BlueprintLintItem{
				Name:        "Compliance",
				Description: fmt.Sprintf("package %s required by policy is not present", pkg),
			})
			if fixup {
				cust.Packages = common.ToPtr(append(common.FromPtr(cust.Packages), pkg))
			}
		}
	}
	// Check for packages in saved policy that are no longer required by current policy (WARNINGS)
	if savedPolicy != nil && savedPolicy.Packages != nil {
		for _, pkg := range *savedPolicy.Packages {
			if !slices.Contains(bp.GetPackagesEx(false), pkg) {
				*lintWarnings = append(*lintWarnings, BlueprintLintItem{
					Name:        "Compliance",
					Description: fmt.Sprintf("package %s is no longer required by policy", pkg),
				})
			}
		}
	}
}

// lintFilesystems validates filesystem/mountpoint compliance using the same diffing logic:
// 1. ERRORS: Mountpoints required by current policy but missing from current blueprint
// 2. WARNINGS: Mountpoints that were required in snapshot but no longer needed by current policy
func (h *Handlers) lintFilesystems(bp *blueprint.Blueprint, savedPolicy, cust *Customizations, fixup bool, lintErrors *[]BlueprintLintItem, lintWarnings *[]BlueprintLintItem) {
	// Check for filesystems required by current policy but missing from current blueprint (ERRORS)
	// Only check if policy actually defines filesystem requirements
	if bp.Customizations != nil {
		for _, fsc := range bp.Customizations.GetFilesystems() {
			if cust.Filesystem == nil || !slices.ContainsFunc(*cust.Filesystem, func(fs Filesystem) bool { return fs.Mountpoint == fsc.Mountpoint }) {
				*lintErrors = append(*lintErrors, BlueprintLintItem{
					Name:        "Compliance",
					Description: fmt.Sprintf("mountpoint %s required by policy is not present", fsc.Mountpoint),
				})
				if fixup {
					cust.Filesystem = common.ToPtr(append(common.FromPtr(cust.Filesystem), Filesystem{
						Mountpoint: fsc.Mountpoint,
						MinSize:    fsc.MinSize,
					}))
				}
			}
		}
	}
	// Check for filesystems in saved policy that are no longer required by current policy (WARNINGS)
	if savedPolicy != nil && savedPolicy.Filesystem != nil {
		var currentPolicyFilesystems []blueprint.FilesystemCustomization
		if bp.Customizations != nil {
			currentPolicyFilesystems = bp.Customizations.GetFilesystems()
		}

		for _, fs := range *savedPolicy.Filesystem {
			if !slices.ContainsFunc(currentPolicyFilesystems, func(fsc blueprint.FilesystemCustomization) bool { return fsc.Mountpoint == fs.Mountpoint }) {
				*lintWarnings = append(*lintWarnings, BlueprintLintItem{
					Name:        "Compliance",
					Description: fmt.Sprintf("mountpoint %s is no longer required by policy", fs.Mountpoint),
				})
			}
		}
	}
}

// lintServices validates service compliance for enabled/disabled/masked states:
// 1. ERRORS: Services required by current policy but missing from current blueprint
// 2. WARNINGS: Services that were required in snapshot but no longer needed by current policy
func (h *Handlers) lintServices(bp *blueprint.Blueprint, savedPolicy, cust *Customizations, fixup bool, lintErrors *[]BlueprintLintItem, lintWarnings *[]BlueprintLintItem) {
	// Check for services required by current policy but missing from current blueprint (ERRORS)
	// Only check if policy actually defines service requirements
	if bp.Customizations != nil {
		if services := bp.Customizations.GetServices(); services != nil {
			for _, e := range services.Enabled {
				if cust.Services == nil || cust.Services.Enabled == nil || !slices.Contains(*cust.Services.Enabled, e) {
					*lintErrors = append(*lintErrors, BlueprintLintItem{
						Name:        "Compliance",
						Description: fmt.Sprintf("service %s required as enabled by policy is not present", e),
					})
					if fixup {
						cust.Services = common.ToPtr(common.FromPtr(cust.Services))
						cust.Services.Enabled = common.ToPtr(append(common.FromPtr(cust.Services.Enabled), e))
					}
				}
			}
			for _, m := range services.Masked {
				if cust.Services == nil || cust.Services.Masked == nil || !slices.Contains(*cust.Services.Masked, m) {
					*lintErrors = append(*lintErrors, BlueprintLintItem{
						Name:        "Compliance",
						Description: fmt.Sprintf("service %s required as masked by policy is not present", m),
					})
					if fixup {
						cust.Services = common.ToPtr(common.FromPtr(cust.Services))
						cust.Services.Masked = common.ToPtr(append(common.FromPtr(cust.Services.Masked), m))
					}
				}
			}
			for _, d := range services.Disabled {
				if cust.Services == nil || cust.Services.Disabled == nil || !slices.Contains(*cust.Services.Disabled, d) {
					*lintErrors = append(*lintErrors, BlueprintLintItem{
						Name:        "Compliance",
						Description: fmt.Sprintf("service %s required as disabled by policy is not present", d),
					})
					if fixup {
						cust.Services = common.ToPtr(common.FromPtr(cust.Services))
						cust.Services.Disabled = common.ToPtr(append(common.FromPtr(cust.Services.Disabled), d))
					}
				}
			}
		}
	}
	// Check for services in saved policy that are no longer required by current policy (WARNINGS)
	if savedPolicy != nil && savedPolicy.Services != nil {
		if savedPolicy.Services.Enabled != nil {
			for _, e := range *savedPolicy.Services.Enabled {
				// Check if current policy requires this enabled service
				stillRequired := false
				if bp.Customizations != nil {
					if policyServices := bp.Customizations.GetServices(); policyServices != nil {
						stillRequired = slices.Contains(policyServices.Enabled, e)
					}
				}
				if !stillRequired {
					*lintWarnings = append(*lintWarnings, BlueprintLintItem{
						Name:        "Compliance",
						Description: fmt.Sprintf("service %s is no longer required as enabled by policy", e),
					})
				}
			}
		}
		if savedPolicy.Services.Disabled != nil {
			for _, d := range *savedPolicy.Services.Disabled {
				// Check if current policy requires this disabled service
				stillRequired := false
				if bp.Customizations != nil {
					if policyServices := bp.Customizations.GetServices(); policyServices != nil {
						stillRequired = slices.Contains(policyServices.Disabled, d)
					}
				}
				if !stillRequired {
					*lintWarnings = append(*lintWarnings, BlueprintLintItem{
						Name:        "Compliance",
						Description: fmt.Sprintf("service %s is no longer required as disabled by policy", d),
					})
				}
			}
		}
		if savedPolicy.Services.Masked != nil {
			for _, m := range *savedPolicy.Services.Masked {
				// Check if current policy requires this masked service
				stillRequired := false
				if bp.Customizations != nil {
					if policyServices := bp.Customizations.GetServices(); policyServices != nil {
						stillRequired = slices.Contains(policyServices.Masked, m)
					}
				}
				if !stillRequired {
					*lintWarnings = append(*lintWarnings, BlueprintLintItem{
						Name:        "Compliance",
						Description: fmt.Sprintf("service %s is no longer required as masked by policy", m),
					})
				}
			}
		}
	}
}

// lintKernel validates kernel settings (name and command line parameters):
// 1. ERRORS: Kernel settings required by current policy but missing from current blueprint
// 2. WARNINGS: Kernel settings that were required in snapshot but no longer needed by current policy
func (h *Handlers) lintKernel(bp *blueprint.Blueprint, savedPolicy, cust *Customizations, fixup bool, lintErrors *[]BlueprintLintItem, lintWarnings *[]BlueprintLintItem) {
	// Check for kernel settings required by current policy but missing from current blueprint (ERRORS)
	// Only check if policy actually defines kernel requirements
	if bp.Customizations != nil {
		if kernel := bp.Customizations.Kernel; kernel != nil {
			if kernel.Name != "" {
				if cust.Kernel == nil || cust.Kernel.Name == nil || *cust.Kernel.Name != kernel.Name {
					*lintErrors = append(*lintErrors, BlueprintLintItem{
						Name:        "Compliance",
						Description: fmt.Sprintf("kernel name %s required by policy not set", kernel.Name),
					})
					if fixup {
						cust.Kernel = common.ToPtr(common.FromPtr(cust.Kernel))
						cust.Kernel.Name = common.ToPtr(kernel.Name)
					}
				}
			}
			for _, kcmd := range strings.Fields(kernel.Append) {
				if kcmd == "" {
					continue
				}
				if cust.Kernel == nil || cust.Kernel.Append == nil || !strings.Contains(*cust.Kernel.Append, kcmd) {
					*lintErrors = append(*lintErrors, BlueprintLintItem{
						Name:        "Compliance",
						Description: fmt.Sprintf("kernel command line parameter '%s' required by policy not set", kcmd),
					})
					if fixup {
						cust.Kernel = common.ToPtr(common.FromPtr(cust.Kernel))
						cust.Kernel.Append = common.ToPtr(fmt.Sprintf("%s %s", common.FromPtr(cust.Kernel.Append), kcmd))
					}
				}
			}
		}
	}
	// Check for kernel settings in saved policy that are no longer required by current policy (WARNINGS)
	if savedPolicy != nil && savedPolicy.Kernel != nil {
		var policyKernel *blueprint.KernelCustomization
		if bp.Customizations != nil {
			policyKernel = bp.Customizations.Kernel
		}
		if savedPolicy.Kernel.Name != nil {
			if policyKernel == nil || policyKernel.Name != *savedPolicy.Kernel.Name {
				*lintWarnings = append(*lintWarnings, BlueprintLintItem{
					Name:        "Compliance",
					Description: fmt.Sprintf("kernel name %s is no longer required by policy", *savedPolicy.Kernel.Name),
				})
			}
		}
		if savedPolicy.Kernel.Append != nil {
			for _, kcmd := range strings.Fields(*savedPolicy.Kernel.Append) {
				if kcmd == "" {
					continue
				}
				if policyKernel == nil || !strings.Contains(policyKernel.Append, kcmd) {
					*lintWarnings = append(*lintWarnings, BlueprintLintItem{
						Name:        "Compliance",
						Description: fmt.Sprintf("kernel command line parameter '%s' is no longer required by policy", kcmd),
					})
				}
			}
		}
	}
}

// lintFIPS validates FIPS compliance settings:
// 1. ERRORS: FIPS required by current policy but not enabled in current blueprint
// 2. WARNINGS: FIPS was required in snapshot but no longer needed by current policy
func (h *Handlers) lintFIPS(bp *blueprint.Blueprint, savedPolicy, cust *Customizations, fixup bool, lintErrors *[]BlueprintLintItem, lintWarnings *[]BlueprintLintItem) {
	// Check for FIPS required by current policy but not set in current blueprint (ERRORS)
	// Only check if policy actually defines FIPS requirements
	if bp.Customizations != nil {
		if fips := bp.Customizations.FIPS; fips != nil {
			if cust.Fips == nil || cust.Fips.Enabled == nil || !*cust.Fips.Enabled {
				if fixup {
					cust.Fips = &FIPS{Enabled: fips}
				} else {
					*lintErrors = append(*lintErrors, BlueprintLintItem{
						Name:        "Compliance",
						Description: fmt.Sprintf("FIPS required '%t' by policy but not set", *fips),
					})
				}
			}
		}
	}
	// Check for FIPS in saved policy that is no longer required by current policy (WARNINGS)
	if savedPolicy != nil && savedPolicy.Fips != nil && savedPolicy.Fips.Enabled != nil && *savedPolicy.Fips.Enabled {
		var policyFips *bool
		if bp.Customizations != nil {
			policyFips = bp.Customizations.FIPS
		}
		if policyFips == nil || !*policyFips {
			*lintWarnings = append(*lintWarnings, BlueprintLintItem{
				Name:        "Compliance",
				Description: "FIPS is no longer required by policy",
			})
		}
	}
}
