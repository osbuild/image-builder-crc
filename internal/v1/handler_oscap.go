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
	_, err = h.lintOpenscap(ctx, &cust, true, distro)
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

func (h *Handlers) lintOpenscap(ctx echo.Context, cust *Customizations, fixup bool, distro Distributions) ([]BlueprintLintItem, error) {
	var lintErrors []BlueprintLintItem
	var err error

	if cust.Openscap == nil {
		return []BlueprintLintItem{}, nil
	}

	compl, err := cust.Openscap.AsOpenSCAPCompliance()
	if err != nil || compl.PolicyId == uuid.Nil {
		return []BlueprintLintItem{}, nil
	}

	d, err := h.server.getDistro(ctx, distro)
	if err != nil {
		return nil, err
	}
	major, minor, err := d.RHELMajorMinor()
	if err != nil {
		return nil, err
	}

	// Validate policy major version matches distribution before fetching TOML customizations.
	// This makes failures deterministic regardless of which minor "rhel-9" symlinks to.
	if _, err := h.server.complianceClient.PolicyDataForMinorVersion(ctx.Request().Context(), major, minor, compl.PolicyId.String()); err != nil {
		if err == compliance.ErrorMajorVersion {
			return nil, err
		}
	}

	bp, err := h.server.complianceClient.PolicyCustomizations(ctx.Request().Context(), major, minor, compl.PolicyId.String())
	if err == compliance.ErrorTailoringNotFound {
		if fixup {
			//typically 500 or endpoint-specific handling
			return nil, err
		}
		return []BlueprintLintItem{{
			Name:        "Compliance",
			Description: "Compliance policy does not have a definition for the latest minor version",
		}}, nil
	}
	if err != nil {
		return nil, err
	}

	// make sure all packages are present, all partitions, all enabled/disabled services, all kernel args
	for _, pkg := range bp.GetPackagesEx(false) {
		if cust.Packages == nil || !slices.Contains(*cust.Packages, pkg) {
			lintErrors = append(lintErrors, BlueprintLintItem{
				Name:        "Compliance",
				Description: fmt.Sprintf("package %s required by policy is not present", pkg),
			})
			if fixup {
				cust.Packages = common.ToPtr(append(common.FromPtr(cust.Packages), pkg))
			}
		}
	}

	// some policies (ansi minimal) only require some extra packages
	if bp.Customizations == nil {
		return lintErrors, nil
	}

	for _, fsc := range bp.Customizations.GetFilesystems() {
		if cust.Filesystem == nil || !slices.ContainsFunc(*cust.Filesystem, func(fs Filesystem) bool {
			return fs.Mountpoint == fsc.Mountpoint
		}) {
			lintErrors = append(lintErrors, BlueprintLintItem{
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

	if services := bp.Customizations.GetServices(); services != nil {
		for _, e := range services.Enabled {
			if cust.Services == nil || cust.Services.Enabled == nil || !slices.Contains(*cust.Services.Enabled, e) {
				lintErrors = append(lintErrors, BlueprintLintItem{
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
				lintErrors = append(lintErrors, BlueprintLintItem{
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
				lintErrors = append(lintErrors, BlueprintLintItem{
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

	if kernel := bp.Customizations.Kernel; kernel != nil {
		if kernel.Name != "" && (cust.Kernel == nil || *cust.Kernel.Name != kernel.Name) {
			lintErrors = append(lintErrors, BlueprintLintItem{
				Name:        "Compliance",
				Description: fmt.Sprintf("kernel name %s required by policy not set", kernel.Name),
			})
			if fixup {
				cust.Kernel = common.ToPtr(common.FromPtr(cust.Kernel))
				cust.Kernel.Name = common.ToPtr(kernel.Name)
			}
		}
		kernelcmd := strings.Split(kernel.Append, " ")
		for _, kcmd := range kernelcmd {
			if cust.Kernel == nil || !strings.Contains(*cust.Kernel.Append, kcmd) {
				lintErrors = append(lintErrors, BlueprintLintItem{
					Name:        "Compliance",
					Description: fmt.Sprintf("kernel command line parameter '%s' required by policy not set", kcmd),
				})
			}
			if fixup {
				cust.Kernel = common.ToPtr(common.FromPtr(cust.Kernel))
				cust.Kernel.Append = common.ToPtr(fmt.Sprintf("%s %s", common.FromPtr(cust.Kernel.Append), kcmd))
			}
		}
	}

	if fips := bp.Customizations.FIPS; fips != nil {
		if *fips && (cust.Fips == nil || cust.Fips.Enabled == nil) {
			lintErrors = append(lintErrors, BlueprintLintItem{
				Name:        "Compliance",
				Description: fmt.Sprintf("FIPS required '%t' by policy but not set", *fips),
			})
			if fixup {
				cust.Fips = &FIPS{
					Enabled: fips,
				}
			}
		}
	}

	return lintErrors, nil
}
