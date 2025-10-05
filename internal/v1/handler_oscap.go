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
	// Create OpenSCAP object with the policy ID from URL parameter
	var openscap OpenSCAP
	err := openscap.FromOpenSCAPCompliance(OpenSCAPCompliance{
		PolicyId: policy,
	})
	if err != nil {
		return err
	}
	cust.Openscap = &openscap
	_, _, err = h.lintOpenscap(ctx, &cust, true, distro, nil)
	if err != nil {
		switch err {
		case distribution.ErrMajorMinor:
			return echo.NewHTTPError(http.StatusBadRequest, err)
		case compliance.ErrorTailoringNotFound, compliance.ErrorMajorVersion:
			return echo.NewHTTPError(http.StatusNotFound, err)
		default:
			return err
		}
	}

	// Clear OpenSCAP from response - we only want the customizations, not the policy reference
	cust.Openscap = nil
	return ctx.JSON(http.StatusOK, cust)
}

func (h *Handlers) lintOpenscap(ctx echo.Context, bpBody *Customizations, fixup bool, distro Distributions, snapshotCust *Customizations) ([]BlueprintLintItem, []BlueprintLintItem, error) {
	var err error

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

	// Validate policy major version matches distribution before fetching TOML customizations.
	// This makes failures deterministic regardless of which minor "rhel-9" symlinks to.
	if _, err := h.server.complianceClient.PolicyDataForMinorVersion(ctx.Request().Context(), major, minor, compl.PolicyId.String()); err != nil {
		if err == compliance.ErrorMajorVersion {
			return nil, nil, err
		}
	}

	policyBP, err := h.server.complianceClient.PolicyCustomizations(ctx.Request().Context(), major, minor, compl.PolicyId.String())
	if err == compliance.ErrorTailoringNotFound {
		if fixup {
			//typically 500 or endpoint-specific handling
			return nil, nil, err
		}
		return []BlueprintLintItem{{
			Name:        "Compliance",
			Description: "Compliance policy does not have a definition for the latest minor version",
		}}, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}

	var allErrors []BlueprintLintItem
	var allWarnings []BlueprintLintItem

	// Collect errors and warnings from all lint functions (they now return instead of mutating)
	errs, warns := lintPackages(policyBP, snapshotCust, bpBody, fixup)
	allErrors = append(allErrors, errs...)
	allWarnings = append(allWarnings, warns...)
	errs, warns = lintFilesystems(policyBP, snapshotCust, bpBody, fixup)
	allErrors = append(allErrors, errs...)
	allWarnings = append(allWarnings, warns...)
	errs, warns = lintServices(policyBP, snapshotCust, bpBody, fixup)
	allErrors = append(allErrors, errs...)
	allWarnings = append(allWarnings, warns...)
	errs, warns = lintKernel(policyBP, snapshotCust, bpBody, fixup)
	allErrors = append(allErrors, errs...)
	allWarnings = append(allWarnings, warns...)
	errs, warns = lintFIPS(policyBP, snapshotCust, bpBody, fixup)
	allErrors = append(allErrors, errs...)
	allWarnings = append(allWarnings, warns...)

	return allErrors, allWarnings, nil
}

// lintPackages validates package compliance by performing two comparisons:
// 1. ERRORS: Packages required by current policy but missing from current blueprint
// 2. WARNINGS: Packages that were required by policy in snapshot but no longer required
func lintPackages(policyBP *blueprint.Blueprint, snapshotCust, currentCust *Customizations, fixup bool) ([]BlueprintLintItem, []BlueprintLintItem) {
	var errs []BlueprintLintItem
	var warns []BlueprintLintItem

	for _, pkg := range policyBP.GetPackagesEx(false) {
		if currentCust.Packages == nil || !slices.Contains(*currentCust.Packages, pkg) {
			errs = append(errs, BlueprintLintItem{
				Name:        "Compliance",
				Description: fmt.Sprintf("package %s required by policy is not present", pkg),
			})
			if fixup {
				currentCust.Packages = common.ToPtr(append(common.FromPtr(currentCust.Packages), pkg))
			}
		}
	}

	// Warnings: packages from saved policy no longer required
	if snapshotCust != nil {
		for _, pkg := range common.FromPtr(snapshotCust.Packages) {
			if !slices.Contains(policyBP.GetPackagesEx(false), pkg) {
				warns = append(warns, BlueprintLintItem{
					Name:        "Compliance",
					Description: fmt.Sprintf("package %s is no longer required by policy", pkg),
				})
			}
		}
	}

	return errs, warns
}

func lintFilesystems(policyBP *blueprint.Blueprint, snapshotCust, currentCust *Customizations, fixup bool) ([]BlueprintLintItem, []BlueprintLintItem) {
	var errs []BlueprintLintItem
	var warns []BlueprintLintItem

	// Only check if policy actually defines filesystem requirements
	if policyBP.Customizations != nil {
		for _, fsc := range policyBP.Customizations.GetFilesystems() {
			if currentCust.Filesystem == nil || !slices.ContainsFunc(*currentCust.Filesystem, func(fs Filesystem) bool { return fs.Mountpoint == fsc.Mountpoint }) {
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
	}

	// Warnings: filesystems in saved policy no longer required
	if snapshotCust != nil {
		var policyFilesystems []blueprint.FilesystemCustomization
		if policyBP.Customizations != nil {
			policyFilesystems = policyBP.Customizations.GetFilesystems()
		}
		for _, fs := range common.FromPtr(snapshotCust.Filesystem) {
			if !slices.ContainsFunc(policyFilesystems, func(fsc blueprint.FilesystemCustomization) bool { return fsc.Mountpoint == fs.Mountpoint }) {
				warns = append(warns, BlueprintLintItem{
					Name:        "Compliance",
					Description: fmt.Sprintf("mountpoint %s is no longer required by policy", fs.Mountpoint),
				})
			}
		}
	}

	return errs, warns
}

func lintServices(policyBP *blueprint.Blueprint, snapshotCust, currentCust *Customizations, fixup bool) ([]BlueprintLintItem, []BlueprintLintItem) {
	var errs []BlueprintLintItem
	var warns []BlueprintLintItem

	if policyBP.Customizations != nil && policyBP.Customizations.GetServices() != nil {
		services := policyBP.Customizations.GetServices()
		for _, e := range services.Enabled {
			if currentCust.Services == nil || currentCust.Services.Enabled == nil || !slices.Contains(*currentCust.Services.Enabled, e) {
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
			if currentCust.Services == nil || currentCust.Services.Masked == nil || !slices.Contains(*currentCust.Services.Masked, m) {
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
			if currentCust.Services == nil || currentCust.Services.Disabled == nil || !slices.Contains(*currentCust.Services.Disabled, d) {
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
	}

	// Warnings: services from saved policy no longer required by current policy
	if snapshotCust == nil || snapshotCust.Services == nil {
		return errs, warns
	}

	var policyServices *blueprint.ServicesCustomization
	if policyBP.Customizations != nil {
		policyServices = policyBP.Customizations.GetServices()
	}

	checkErrs, checkWarns := checkObsoleteServices(snapshotCust.Services.Enabled, "enabled", func(service string) bool {
		return policyServices != nil && slices.Contains(policyServices.Enabled, service)
	})
	errs = append(errs, checkErrs...)
	warns = append(warns, checkWarns...)

	checkErrs, checkWarns = checkObsoleteServices(snapshotCust.Services.Disabled, "disabled", func(service string) bool {
		return policyServices != nil && slices.Contains(policyServices.Disabled, service)
	})
	errs = append(errs, checkErrs...)
	warns = append(warns, checkWarns...)

	checkErrs, checkWarns = checkObsoleteServices(snapshotCust.Services.Masked, "masked", func(service string) bool {
		return policyServices != nil && slices.Contains(policyServices.Masked, service)
	})
	errs = append(errs, checkErrs...)
	warns = append(warns, checkWarns...)

	return errs, warns
}

func checkObsoleteServices(services *[]string, serviceType string, isStillRequired func(string) bool) ([]BlueprintLintItem, []BlueprintLintItem) {
	var warns []BlueprintLintItem
	if services == nil {
		return nil, nil
	}
	for _, service := range *services {
		if !isStillRequired(service) {
			warns = append(warns, BlueprintLintItem{
				Name:        "Compliance",
				Description: fmt.Sprintf("service %s is no longer required as %s by policy", service, serviceType),
			})
		}
	}
	return nil, warns
}

func lintKernel(policyBP *blueprint.Blueprint, snapshotCust, currentCust *Customizations, fixup bool) ([]BlueprintLintItem, []BlueprintLintItem) {
	var errs []BlueprintLintItem
	var warns []BlueprintLintItem

	if policyBP.Customizations != nil {
		if kernel := policyBP.Customizations.Kernel; kernel != nil {
			if kernel.Name != "" {
				if currentCust.Kernel == nil || currentCust.Kernel.Name == nil || *currentCust.Kernel.Name != kernel.Name {
					errs = append(errs, BlueprintLintItem{
						Name:        "Compliance",
						Description: fmt.Sprintf("kernel name %s required by policy not set", kernel.Name),
					})
					if fixup {
						currentCust.Kernel = common.ToPtr(common.FromPtr(currentCust.Kernel))
						currentCust.Kernel.Name = common.ToPtr(kernel.Name)
					}
				}
			}
			for _, kcmd := range strings.Fields(kernel.Append) {
				if kcmd == "" {
					continue
				}
				if currentCust.Kernel == nil || currentCust.Kernel.Append == nil || !strings.Contains(*currentCust.Kernel.Append, kcmd) {
					errs = append(errs, BlueprintLintItem{
						Name:        "Compliance",
						Description: fmt.Sprintf("kernel command line parameter '%s' required by policy not set", kcmd),
					})
					if fixup {
						currentCust.Kernel = common.ToPtr(common.FromPtr(currentCust.Kernel))
						currentCust.Kernel.Append = common.ToPtr(fmt.Sprintf("%s %s", common.FromPtr(currentCust.Kernel.Append), kcmd))
					}
				}
			}
		}
	}

	// Warnings from saved policy
	if snapshotCust != nil && snapshotCust.Kernel != nil {
		var policyKernel *blueprint.KernelCustomization
		if policyBP.Customizations != nil {
			policyKernel = policyBP.Customizations.Kernel
		}
		if snapshotCust.Kernel.Name != nil {
			if policyKernel == nil || policyKernel.Name != *snapshotCust.Kernel.Name {
				warns = append(warns, BlueprintLintItem{
					Name:        "Compliance",
					Description: fmt.Sprintf("kernel name %s is no longer required by policy", *snapshotCust.Kernel.Name),
				})
			}
		}
		if snapshotCust.Kernel.Append != nil {
			for _, kcmd := range strings.Fields(*snapshotCust.Kernel.Append) {
				if kcmd == "" {
					continue
				}
				if policyKernel == nil || !strings.Contains(policyKernel.Append, kcmd) {
					warns = append(warns, BlueprintLintItem{
						Name:        "Compliance",
						Description: fmt.Sprintf("kernel command line parameter '%s' is no longer required by policy", kcmd),
					})
				}
			}
		}
	}

	return errs, warns
}

func lintFIPS(policyBP *blueprint.Blueprint, snapshotCust, currentCust *Customizations, fixup bool) ([]BlueprintLintItem, []BlueprintLintItem) {
	var errs []BlueprintLintItem
	var warns []BlueprintLintItem

	if policyBP.Customizations == nil || policyBP.Customizations.FIPS == nil {
		return nil, nil
	}

	fips := policyBP.Customizations.FIPS
	fipsNotSet := currentCust.Fips == nil || currentCust.Fips.Enabled == nil || !*currentCust.Fips.Enabled

	if fipsNotSet {
		if fixup {
			currentCust.Fips = &FIPS{Enabled: fips}
		} else {
			errs = append(errs, BlueprintLintItem{
				Name:        "Compliance",
				Description: fmt.Sprintf("FIPS required '%t' by policy but not set", *fips),
			})
		}
	}

	// Warnings: saved policy had FIPS enabled previously but not now
	if snapshotCust != nil && snapshotCust.Fips != nil && snapshotCust.Fips.Enabled != nil && *snapshotCust.Fips.Enabled {
		if fips == nil || !*fips {
			warns = append(warns, BlueprintLintItem{
				Name:        "Compliance",
				Description: "FIPS is no longer required by policy",
			})
		}
	}

	return errs, warns
}
