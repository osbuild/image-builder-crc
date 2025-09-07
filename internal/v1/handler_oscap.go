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
	"github.com/osbuild/image-builder-crc/internal/db"
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
	_, err := h.lintOpenscap(ctx, &cust, true, distro, policy.String(), nil)
	if err == distribution.ErrMajorMinor {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	} else if err == compliance.ErrorTailoringNotFound {
		return echo.NewHTTPError(http.StatusNotFound, err)
	} else if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, cust)
}

func (h *Handlers) lintOpenscap(ctx echo.Context, cust *Customizations, fixup bool, distro Distributions, policy string, blueprintId *uuid.UUID) ([]BlueprintLintItem, error) {
	var lintErrors []BlueprintLintItem
	var err error

	d, err := h.server.getDistro(ctx, distro)
	if err != nil {
		return nil, err
	}
	major, minor, err := d.RHELMajorMinor()
	if err != nil {
		return nil, err
	}
	currentBp, err := h.server.complianceClient.PolicyCustomizations(ctx.Request().Context(), major, minor, policy)
	if err == compliance.ErrorTailoringNotFound {
		return nil, err
	} else if err != nil {
		return nil, echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	// Check for missing items (items added to current policy that aren't in blueprint)
	lintErrors = append(lintErrors, h.CheckMissingItems(currentBp, cust, fixup)...)

	if blueprintId != nil {
		savedPolicyBp, err := h.getSavedPolicyBlueprint(ctx, *blueprintId)
		if err != nil {
			return nil, err
		}
		if savedPolicyBp != nil {
			lintErrors = append(lintErrors, h.CheckRemovedItems(savedPolicyBp, currentBp, cust, fixup)...)
		}
	}
	return lintErrors, nil
}

func (h *Handlers) getSavedPolicyBlueprint(ctx echo.Context, blueprintId uuid.UUID) (*blueprint.Blueprint, error) {
	userID, err := h.server.getIdentity(ctx)
	if err != nil {
		return nil, err
	}

	blueprintEntry, err := h.server.db.GetBlueprint(ctx.Request().Context(), blueprintId, userID.OrgID(), nil)
	if err != nil {
		return nil, err
	}

	if len(blueprintEntry.ServiceSnapshots) == 0 {
		return nil, nil
	}

	var serviceSnapshots db.ServiceSnapshots
	err = json.Unmarshal(blueprintEntry.ServiceSnapshots, &serviceSnapshots)
	if err != nil {
		return nil, err
	}

	if serviceSnapshots.Compliance == nil || len(serviceSnapshots.Compliance.PolicyCustomizations) == 0 {
		return nil, nil
	}

	// Since we now store v1.Customizations instead of blueprint.Blueprint,
	// we need to get the original blueprint from the compliance service
	d, err := h.server.getDistro(ctx, "rhel-8") // Default fallback
	if err != nil {
		return nil, err
	}
	major, minor, err := d.RHELMajorMinor()
	if err != nil {
		return nil, err
	}

	// Get the original blueprint from compliance service using the stored policy ID
	return h.server.complianceClient.PolicyCustomizations(ctx.Request().Context(), major, minor, serviceSnapshots.Compliance.PolicyId.String())
}

func (h *Handlers) CheckMissingItems(bp *blueprint.Blueprint, cust *Customizations, fixup bool) []BlueprintLintItem {
	var lintErrors []BlueprintLintItem

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
		return lintErrors
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
		if kernel.Name != "" && (cust.Kernel == nil || cust.Kernel.Name == nil || *cust.Kernel.Name != kernel.Name) {
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
			if cust.Kernel == nil || cust.Kernel.Append == nil || !strings.Contains(*cust.Kernel.Append, kcmd) {
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

	return lintErrors
}

func (h *Handlers) CheckRemovedItems(savedBp, currentBp *blueprint.Blueprint, cust *Customizations, fixup bool) []BlueprintLintItem {
	var lintErrors []BlueprintLintItem

	// If no saved blueprint is provided, no items can be considered "removed"
	if savedBp == nil {
		return lintErrors
	}

	// Check for packages that were removed from policy
	for _, pkg := range savedBp.GetPackagesEx(false) {
		if !slices.Contains(currentBp.GetPackagesEx(false), pkg) {
			// Package was removed from policy
			if cust.Packages != nil && slices.Contains(*cust.Packages, pkg) {
				lintErrors = append(lintErrors, BlueprintLintItem{
					Name:        "Compliance",
					Description: fmt.Sprintf("package %s is no longer required by policy and should be removed", pkg),
				})
				if fixup {
					// Remove the package from blueprint
					*cust.Packages = slices.DeleteFunc(*cust.Packages, func(p string) bool {
						return p == pkg
					})
					if len(*cust.Packages) == 0 {
						cust.Packages = nil
					}
				}
			}
		}
	}

	// Check for filesystems that were removed from policy
	if savedBp.Customizations != nil && currentBp.Customizations != nil {
		for _, savedFs := range savedBp.Customizations.GetFilesystems() {
			found := false
			for _, currentFs := range currentBp.Customizations.GetFilesystems() {
				if savedFs.Mountpoint == currentFs.Mountpoint {
					found = true
					break
				}
			}
			if !found {
				// Filesystem was removed from policy
				if cust.Filesystem != nil {
					idx := slices.IndexFunc(*cust.Filesystem, func(fs Filesystem) bool {
						return fs.Mountpoint == savedFs.Mountpoint
					})
					if idx != -1 {
						lintErrors = append(lintErrors, BlueprintLintItem{
							Name:        "Compliance",
							Description: fmt.Sprintf("mountpoint %s is no longer required by policy and should be removed", savedFs.Mountpoint),
						})
						if fixup {
							// Remove the filesystem from blueprint
							*cust.Filesystem = slices.Delete(*cust.Filesystem, idx, idx+1)
							if len(*cust.Filesystem) == 0 {
								cust.Filesystem = nil
							}
						}
					}
				}
			}
		}
	}

	// Check for services that were removed from policy
	if savedBp.Customizations != nil && currentBp.Customizations != nil {
		savedServices := savedBp.Customizations.GetServices()
		currentServices := currentBp.Customizations.GetServices()

		if savedServices != nil {
			// Check enabled services
			if currentServices == nil || currentServices.Enabled == nil {
				for _, service := range savedServices.Enabled {
					if cust.Services != nil && cust.Services.Enabled != nil && slices.Contains(*cust.Services.Enabled, service) {
						lintErrors = append(lintErrors, BlueprintLintItem{
							Name:        "Compliance",
							Description: fmt.Sprintf("service %s is no longer required as enabled by policy and should be removed", service),
						})
						if fixup {
							*cust.Services.Enabled = slices.DeleteFunc(*cust.Services.Enabled, func(s string) bool {
								return s == service
							})
							if len(*cust.Services.Enabled) == 0 {
								cust.Services.Enabled = nil
							}
						}
					}
				}
			} else {
				for _, service := range savedServices.Enabled {
					if !slices.Contains(currentServices.Enabled, service) {
						if cust.Services != nil && cust.Services.Enabled != nil && slices.Contains(*cust.Services.Enabled, service) {
							lintErrors = append(lintErrors, BlueprintLintItem{
								Name:        "Compliance",
								Description: fmt.Sprintf("service %s is no longer required as enabled by policy and should be removed", service),
							})
							if fixup {
								*cust.Services.Enabled = slices.DeleteFunc(*cust.Services.Enabled, func(s string) bool {
									return s == service
								})
								if len(*cust.Services.Enabled) == 0 {
									cust.Services.Enabled = nil
								}
							}
						}
					}
				}
			}

			// Check masked services
			if currentServices == nil || currentServices.Masked == nil {
				for _, service := range savedServices.Masked {
					if cust.Services != nil && cust.Services.Masked != nil && slices.Contains(*cust.Services.Masked, service) {
						lintErrors = append(lintErrors, BlueprintLintItem{
							Name:        "Compliance",
							Description: fmt.Sprintf("service %s is no longer required as masked by policy and should be removed", service),
						})
						if fixup {
							*cust.Services.Masked = slices.DeleteFunc(*cust.Services.Masked, func(s string) bool {
								return s == service
							})
							if len(*cust.Services.Masked) == 0 {
								cust.Services.Masked = nil
							}
						}
					}
				}
			} else {
				for _, service := range savedServices.Masked {
					if !slices.Contains(currentServices.Masked, service) {
						if cust.Services != nil && cust.Services.Masked != nil && slices.Contains(*cust.Services.Masked, service) {
							lintErrors = append(lintErrors, BlueprintLintItem{
								Name:        "Compliance",
								Description: fmt.Sprintf("service %s is no longer required as masked by policy and should be removed", service),
							})
							if fixup {
								*cust.Services.Masked = slices.DeleteFunc(*cust.Services.Masked, func(s string) bool {
									return s == service
								})
								if len(*cust.Services.Masked) == 0 {
									cust.Services.Masked = nil
								}
							}
						}
					}
				}
			}

			// Check disabled services
			if currentServices == nil || currentServices.Disabled == nil {
				for _, service := range savedServices.Disabled {
					if cust.Services != nil && cust.Services.Disabled != nil && slices.Contains(*cust.Services.Disabled, service) {
						lintErrors = append(lintErrors, BlueprintLintItem{
							Name:        "Compliance",
							Description: fmt.Sprintf("service %s is no longer required as disabled by policy and should be removed", service),
						})
						if fixup {
							*cust.Services.Disabled = slices.DeleteFunc(*cust.Services.Disabled, func(s string) bool {
								return s == service
							})
							if len(*cust.Services.Disabled) == 0 {
								cust.Services.Disabled = nil
							}
						}
					}
				}
			} else {
				for _, service := range savedServices.Disabled {
					if !slices.Contains(currentServices.Disabled, service) {
						if cust.Services != nil && cust.Services.Disabled != nil && slices.Contains(*cust.Services.Disabled, service) {
							lintErrors = append(lintErrors, BlueprintLintItem{
								Name:        "Compliance",
								Description: fmt.Sprintf("service %s is no longer required as disabled by policy and should be removed", service),
							})
							if fixup {
								*cust.Services.Disabled = slices.DeleteFunc(*cust.Services.Disabled, func(s string) bool {
									return s == service
								})
								if len(*cust.Services.Disabled) == 0 {
									cust.Services.Disabled = nil
								}
							}
						}
					}
				}
			}
		}
	}

	// Check for kernel settings that were removed from policy
	if savedBp.Customizations != nil && savedBp.Customizations.Kernel != nil {
		savedKernel := savedBp.Customizations.Kernel
		currentKernel := currentBp.Customizations.Kernel

		// Check kernel name
		if savedKernel.Name != "" && (currentKernel == nil || currentKernel.Name != savedKernel.Name) {
			if cust.Kernel != nil && cust.Kernel.Name != nil && *cust.Kernel.Name == savedKernel.Name {
				lintErrors = append(lintErrors, BlueprintLintItem{
					Name:        "Compliance",
					Description: fmt.Sprintf("kernel name %s is no longer required by policy and should be removed", savedKernel.Name),
				})
				if fixup {
					cust.Kernel.Name = nil
				}
			}
		}

		// Check kernel command line parameters
		if savedKernel.Append != "" {
			savedKernelCmds := strings.Split(savedKernel.Append, " ")
			var currentKernelCmds []string
			if currentKernel != nil && currentKernel.Append != "" {
				currentKernelCmds = strings.Split(currentKernel.Append, " ")
			}

			for _, savedCmd := range savedKernelCmds {
				if savedCmd != "" && !slices.Contains(currentKernelCmds, savedCmd) {
					if cust.Kernel != nil && cust.Kernel.Append != nil && strings.Contains(*cust.Kernel.Append, savedCmd) {
						lintErrors = append(lintErrors, BlueprintLintItem{
							Name:        "Compliance",
							Description: fmt.Sprintf("kernel command line parameter '%s' is no longer required by policy and should be removed", savedCmd),
						})
						if fixup {
							// Remove the command from kernel append
							newAppend := strings.ReplaceAll(*cust.Kernel.Append, savedCmd, "")
							newAppend = strings.TrimSpace(strings.ReplaceAll(newAppend, "  ", " "))
							if newAppend == "" {
								cust.Kernel.Append = nil
							} else {
								cust.Kernel.Append = &newAppend
							}
						}
					}
				}
			}
		}
	}

	// Check for FIPS setting that was removed from policy
	if savedBp.Customizations != nil && savedBp.Customizations.FIPS != nil {
		savedFips := savedBp.Customizations.FIPS
		currentFips := currentBp.Customizations.FIPS

		if *savedFips && (currentFips == nil || !*currentFips) {
			if cust.Fips != nil && cust.Fips.Enabled != nil && *cust.Fips.Enabled {
				lintErrors = append(lintErrors, BlueprintLintItem{
					Name:        "Compliance",
					Description: "FIPS is no longer required by policy and should be disabled",
				})
				if fixup {
					cust.Fips = nil
				}
			}
		}
	}

	return lintErrors
}
