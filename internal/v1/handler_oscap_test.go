package v1_test

import (
	"testing"

	"github.com/osbuild/blueprint/pkg/blueprint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osbuild/image-builder-crc/internal/common"
	v1 "github.com/osbuild/image-builder-crc/internal/v1"
)

// Test lintPackages function for both adding missing packages and removing obsolete packages
func TestLintPackages(t *testing.T) {
	tests := []struct {
		name           string
		policyBP       *blueprint.Blueprint
		snapshotCust   *v1.Customizations
		currentCust    *v1.Customizations
		fixup          bool
		expectedErrors []v1.BlueprintLintItem
		expectedWarns  []v1.BlueprintLintItem
		expectedCust   *v1.Customizations // Expected customizations after fixup
	}{
		{
			name: "missing packages - errors only",
			policyBP: &blueprint.Blueprint{
				Packages: []blueprint.Package{
					{Name: "required-pkg1"},
					{Name: "required-pkg2"},
				},
			},
			snapshotCust: nil,
			currentCust: &v1.Customizations{
				Packages: common.ToPtr([]string{"existing-pkg"}),
			},
			fixup: false,
			expectedErrors: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "package required-pkg1 required by policy is not present"},
				{Name: "Compliance", Description: "package required-pkg2 required by policy is not present"},
			},
			expectedWarns: []v1.BlueprintLintItem{},
		},
		{
			name: "missing packages with fixup",
			policyBP: &blueprint.Blueprint{
				Packages: []blueprint.Package{
					{Name: "required-pkg1"},
					{Name: "required-pkg2"},
				},
			},
			snapshotCust: nil,
			currentCust: &v1.Customizations{
				Packages: common.ToPtr([]string{"existing-pkg"}),
			},
			fixup:          true,
			expectedErrors: []v1.BlueprintLintItem{},
			expectedWarns:  []v1.BlueprintLintItem{},
			expectedCust: &v1.Customizations{
				Packages: common.ToPtr([]string{"existing-pkg", "required-pkg1", "required-pkg2"}),
			},
		},
		{
			name: "obsolete packages - warnings only",
			policyBP: &blueprint.Blueprint{
				Packages: []blueprint.Package{
					{Name: "current-pkg"},
				},
			},
			snapshotCust: &v1.Customizations{
				Packages: common.ToPtr([]string{"current-pkg", "obsolete-pkg1", "obsolete-pkg2"}),
			},
			currentCust: &v1.Customizations{
				Packages: common.ToPtr([]string{"current-pkg"}),
			},
			fixup:          false,
			expectedErrors: []v1.BlueprintLintItem{},
			expectedWarns: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "package obsolete-pkg1 is no longer required by policy"},
				{Name: "Compliance", Description: "package obsolete-pkg2 is no longer required by policy"},
			},
		},
		{
			name: "both missing and obsolete packages",
			policyBP: &blueprint.Blueprint{
				Packages: []blueprint.Package{
					{Name: "current-pkg"},
					{Name: "new-required-pkg"},
				},
			},
			snapshotCust: &v1.Customizations{
				Packages: common.ToPtr([]string{"current-pkg", "obsolete-pkg"}),
			},
			currentCust: &v1.Customizations{
				Packages: common.ToPtr([]string{"current-pkg"}),
			},
			fixup: false,
			expectedErrors: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "package new-required-pkg required by policy is not present"},
			},
			expectedWarns: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "package obsolete-pkg is no longer required by policy"},
			},
		},
		{
			name: "no packages in policy",
			policyBP: &blueprint.Blueprint{
				Packages: []blueprint.Package{},
			},
			snapshotCust: &v1.Customizations{
				Packages: common.ToPtr([]string{"obsolete-pkg"}),
			},
			currentCust: &v1.Customizations{
				Packages: common.ToPtr([]string{"some-pkg"}),
			},
			fixup:          false,
			expectedErrors: []v1.BlueprintLintItem{},
			expectedWarns: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "package obsolete-pkg is no longer required by policy"},
			},
		},
		{
			name: "nil packages in current customizations",
			policyBP: &blueprint.Blueprint{
				Packages: []blueprint.Package{
					{Name: "required-pkg"},
				},
			},
			snapshotCust: nil,
			currentCust: &v1.Customizations{
				Packages: nil,
			},
			fixup: false,
			expectedErrors: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "package required-pkg required by policy is not present"},
			},
			expectedWarns: []v1.BlueprintLintItem{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a copy of currentCust to avoid modifying the original
			currentCustCopy := *tt.currentCust
			if tt.currentCust.Packages != nil {
				packagesCopy := make([]string, len(*tt.currentCust.Packages))
				copy(packagesCopy, *tt.currentCust.Packages)
				currentCustCopy.Packages = common.ToPtr(packagesCopy)
			}

			errors, warnings := v1.LintPackages(tt.policyBP, tt.snapshotCust, &currentCustCopy, tt.fixup)

			assert.Equal(t, tt.expectedErrors, errors)
			assert.Equal(t, tt.expectedWarns, warnings)

			if tt.fixup && tt.expectedCust != nil {
				assert.Equal(t, tt.expectedCust.Packages, currentCustCopy.Packages)
			}
		})
	}
}

// Test lintFilesystems function for both adding missing filesystems and removing obsolete filesystems
func TestLintFilesystems(t *testing.T) {
	tests := []struct {
		name           string
		policyBP       *blueprint.Blueprint
		snapshotCust   *v1.Customizations
		currentCust    *v1.Customizations
		fixup          bool
		expectedErrors []v1.BlueprintLintItem
		expectedWarns  []v1.BlueprintLintItem
		expectedCust   *v1.Customizations
	}{
		{
			name: "missing filesystems - errors only",
			policyBP: &blueprint.Blueprint{
				Customizations: &blueprint.Customizations{
					Filesystem: []blueprint.FilesystemCustomization{
						{Mountpoint: "/var", MinSize: 1024},
						{Mountpoint: "/tmp", MinSize: 512},
					},
				},
			},
			snapshotCust: nil,
			currentCust: &v1.Customizations{
				Filesystem: common.ToPtr([]v1.Filesystem{
					{Mountpoint: "/home"},
				}),
			},
			fixup: false,
			expectedErrors: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "mountpoint /var required by policy is not present"},
				{Name: "Compliance", Description: "mountpoint /tmp required by policy is not present"},
			},
			expectedWarns: []v1.BlueprintLintItem{},
		},
		{
			name: "missing filesystems with fixup",
			policyBP: &blueprint.Blueprint{
				Customizations: &blueprint.Customizations{
					Filesystem: []blueprint.FilesystemCustomization{
						{Mountpoint: "/var", MinSize: 1024},
					},
				},
			},
			snapshotCust: nil,
			currentCust: &v1.Customizations{
				Filesystem: common.ToPtr([]v1.Filesystem{
					{Mountpoint: "/home"},
				}),
			},
			fixup:          true,
			expectedErrors: []v1.BlueprintLintItem{},
			expectedWarns:  []v1.BlueprintLintItem{},
			expectedCust: &v1.Customizations{
				Filesystem: common.ToPtr([]v1.Filesystem{
					{Mountpoint: "/home"},
					{Mountpoint: "/var", MinSize: 1024},
				}),
			},
		},
		{
			name: "obsolete filesystems - warnings only",
			policyBP: &blueprint.Blueprint{
				Customizations: &blueprint.Customizations{
					Filesystem: []blueprint.FilesystemCustomization{
						{Mountpoint: "/var"},
					},
				},
			},
			snapshotCust: &v1.Customizations{
				Filesystem: common.ToPtr([]v1.Filesystem{
					{Mountpoint: "/var"},
					{Mountpoint: "/obsolete"},
				}),
			},
			currentCust: &v1.Customizations{
				Filesystem: common.ToPtr([]v1.Filesystem{
					{Mountpoint: "/var"},
				}),
			},
			fixup:          false,
			expectedErrors: []v1.BlueprintLintItem{},
			expectedWarns: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "mountpoint /obsolete is no longer required by policy"},
			},
		},
		{
			name: "nil filesystem in current customizations",
			policyBP: &blueprint.Blueprint{
				Customizations: &blueprint.Customizations{
					Filesystem: []blueprint.FilesystemCustomization{
						{Mountpoint: "/var"},
					},
				},
			},
			snapshotCust: nil,
			currentCust: &v1.Customizations{
				Filesystem: nil,
			},
			fixup: false,
			expectedErrors: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "mountpoint /var required by policy is not present"},
			},
			expectedWarns: []v1.BlueprintLintItem{},
		},
		{
			name: "no filesystem customizations in policy",
			policyBP: &blueprint.Blueprint{
				Customizations: nil,
			},
			snapshotCust: &v1.Customizations{
				Filesystem: common.ToPtr([]v1.Filesystem{
					{Mountpoint: "/obsolete"},
				}),
			},
			currentCust: &v1.Customizations{
				Filesystem: common.ToPtr([]v1.Filesystem{
					{Mountpoint: "/home"},
				}),
			},
			fixup:          false,
			expectedErrors: []v1.BlueprintLintItem{},
			expectedWarns: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "mountpoint /obsolete is no longer required by policy"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a copy of currentCust to avoid modifying the original
			currentCustCopy := *tt.currentCust
			if tt.currentCust.Filesystem != nil {
				filesystemCopy := make([]v1.Filesystem, len(*tt.currentCust.Filesystem))
				copy(filesystemCopy, *tt.currentCust.Filesystem)
				currentCustCopy.Filesystem = common.ToPtr(filesystemCopy)
			}

			errors, warnings := v1.LintFilesystems(tt.policyBP, tt.snapshotCust, &currentCustCopy, tt.fixup)

			assert.Equal(t, tt.expectedErrors, errors)
			assert.Equal(t, tt.expectedWarns, warnings)

			if tt.fixup && tt.expectedCust != nil {
				assert.Equal(t, tt.expectedCust.Filesystem, currentCustCopy.Filesystem)
			}
		})
	}
}

// Test lintServices function for both adding missing services and removing obsolete services
func TestLintServices(t *testing.T) {
	tests := []struct {
		name           string
		policyBP       *blueprint.Blueprint
		snapshotCust   *v1.Customizations
		currentCust    *v1.Customizations
		fixup          bool
		expectedErrors []v1.BlueprintLintItem
		expectedWarns  []v1.BlueprintLintItem
		expectedCust   *v1.Customizations
	}{
		{
			name: "missing enabled services - errors only",
			policyBP: &blueprint.Blueprint{
				Customizations: &blueprint.Customizations{
					Services: &blueprint.ServicesCustomization{
						Enabled: []string{"required-service1", "required-service2"},
					},
				},
			},
			snapshotCust: nil,
			currentCust: &v1.Customizations{
				Services: &v1.Services{
					Enabled: common.ToPtr([]string{"existing-service"}),
				},
			},
			fixup: false,
			expectedErrors: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "service required-service1 required as enabled by policy is not present"},
				{Name: "Compliance", Description: "service required-service2 required as enabled by policy is not present"},
			},
			expectedWarns: []v1.BlueprintLintItem{},
		},
		{
			name: "missing masked services with fixup",
			policyBP: &blueprint.Blueprint{
				Customizations: &blueprint.Customizations{
					Services: &blueprint.ServicesCustomization{
						Masked: []string{"masked-service"},
					},
				},
			},
			snapshotCust: nil,
			currentCust: &v1.Customizations{
				Services: &v1.Services{
					Enabled: common.ToPtr([]string{"existing-service"}),
				},
			},
			fixup:          true,
			expectedErrors: []v1.BlueprintLintItem{},
			expectedWarns:  []v1.BlueprintLintItem{},
			expectedCust: &v1.Customizations{
				Services: &v1.Services{
					Enabled: common.ToPtr([]string{"existing-service"}),
					Masked:  common.ToPtr([]string{"masked-service"}),
				},
			},
		},
		{
			name: "obsolete services - warnings only",
			policyBP: &blueprint.Blueprint{
				Customizations: &blueprint.Customizations{
					Services: &blueprint.ServicesCustomization{
						Enabled: []string{"current-service"},
					},
				},
			},
			snapshotCust: &v1.Customizations{
				Services: &v1.Services{
					Enabled:  common.ToPtr([]string{"current-service", "obsolete-enabled"}),
					Masked:   common.ToPtr([]string{"obsolete-masked"}),
					Disabled: common.ToPtr([]string{"obsolete-disabled"}),
				},
			},
			currentCust: &v1.Customizations{
				Services: &v1.Services{
					Enabled: common.ToPtr([]string{"current-service"}),
				},
			},
			fixup:          false,
			expectedErrors: []v1.BlueprintLintItem{},
			expectedWarns: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "service obsolete-enabled is no longer required as enabled by policy"},
				{Name: "Compliance", Description: "service obsolete-masked is no longer required as masked by policy"},
				{Name: "Compliance", Description: "service obsolete-disabled is no longer required as disabled by policy"},
			},
		},
		{
			name: "nil services in current customizations",
			policyBP: &blueprint.Blueprint{
				Customizations: &blueprint.Customizations{
					Services: &blueprint.ServicesCustomization{
						Enabled: []string{"required-service"},
					},
				},
			},
			snapshotCust: nil,
			currentCust: &v1.Customizations{
				Services: nil,
			},
			fixup: false,
			expectedErrors: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "service required-service required as enabled by policy is not present"},
			},
			expectedWarns: []v1.BlueprintLintItem{},
		},
		{
			name: "no service customizations in policy",
			policyBP: &blueprint.Blueprint{
				Customizations: nil,
			},
			snapshotCust: &v1.Customizations{
				Services: &v1.Services{
					Enabled: common.ToPtr([]string{"obsolete-service"}),
				},
			},
			currentCust: &v1.Customizations{
				Services: &v1.Services{
					Enabled: common.ToPtr([]string{"some-service"}),
				},
			},
			fixup:          false,
			expectedErrors: []v1.BlueprintLintItem{},
			expectedWarns: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "service obsolete-service is no longer required as enabled by policy"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a copy of currentCust to avoid modifying the original
			currentCustCopy := *tt.currentCust
			if tt.currentCust.Services != nil {
				servicesCopy := *tt.currentCust.Services
				if tt.currentCust.Services.Enabled != nil {
					enabledCopy := make([]string, len(*tt.currentCust.Services.Enabled))
					copy(enabledCopy, *tt.currentCust.Services.Enabled)
					servicesCopy.Enabled = common.ToPtr(enabledCopy)
				}
				if tt.currentCust.Services.Masked != nil {
					maskedCopy := make([]string, len(*tt.currentCust.Services.Masked))
					copy(maskedCopy, *tt.currentCust.Services.Masked)
					servicesCopy.Masked = common.ToPtr(maskedCopy)
				}
				if tt.currentCust.Services.Disabled != nil {
					disabledCopy := make([]string, len(*tt.currentCust.Services.Disabled))
					copy(disabledCopy, *tt.currentCust.Services.Disabled)
					servicesCopy.Disabled = common.ToPtr(disabledCopy)
				}
				currentCustCopy.Services = &servicesCopy
			}

			errors, warnings := v1.LintServices(tt.policyBP, tt.snapshotCust, &currentCustCopy, tt.fixup)

			assert.Equal(t, tt.expectedErrors, errors)
			assert.Equal(t, tt.expectedWarns, warnings)

			if tt.fixup && tt.expectedCust != nil {
				assert.Equal(t, tt.expectedCust.Services, currentCustCopy.Services)
			}
		})
	}
}

// Test lintKernel function for both adding missing kernel settings and removing obsolete kernel settings
func TestLintKernel(t *testing.T) {
	tests := []struct {
		name           string
		policyBP       *blueprint.Blueprint
		snapshotCust   *v1.Customizations
		currentCust    *v1.Customizations
		fixup          bool
		expectedErrors []v1.BlueprintLintItem
		expectedWarns  []v1.BlueprintLintItem
		expectedCust   *v1.Customizations
	}{
		{
			name: "missing kernel name - error only",
			policyBP: &blueprint.Blueprint{
				Customizations: &blueprint.Customizations{
					Kernel: &blueprint.KernelCustomization{
						Name: "required-kernel",
					},
				},
			},
			snapshotCust: nil,
			currentCust: &v1.Customizations{
				Kernel: &v1.Kernel{
					Name: common.ToPtr("different-kernel"),
				},
			},
			fixup: false,
			expectedErrors: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "kernel name required-kernel required by policy not set"},
			},
			expectedWarns: []v1.BlueprintLintItem{},
		},
		{
			name: "missing kernel name with fixup",
			policyBP: &blueprint.Blueprint{
				Customizations: &blueprint.Customizations{
					Kernel: &blueprint.KernelCustomization{
						Name: "required-kernel",
					},
				},
			},
			snapshotCust: nil,
			currentCust: &v1.Customizations{
				Kernel: nil,
			},
			fixup:          true,
			expectedErrors: []v1.BlueprintLintItem{},
			expectedWarns:  []v1.BlueprintLintItem{},
			expectedCust: &v1.Customizations{
				Kernel: &v1.Kernel{
					Name: common.ToPtr("required-kernel"),
				},
			},
		},
		{
			name: "missing kernel append parameters",
			policyBP: &blueprint.Blueprint{
				Customizations: &blueprint.Customizations{
					Kernel: &blueprint.KernelCustomization{
						Append: "audit=1 selinux=1",
					},
				},
			},
			snapshotCust: nil,
			currentCust: &v1.Customizations{
				Kernel: &v1.Kernel{
					Append: common.ToPtr("audit=1"),
				},
			},
			fixup: false,
			expectedErrors: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "kernel command line parameter 'selinux=1' required by policy not set"},
			},
			expectedWarns: []v1.BlueprintLintItem{},
		},
		{
			name: "missing kernel append with fixup",
			policyBP: &blueprint.Blueprint{
				Customizations: &blueprint.Customizations{
					Kernel: &blueprint.KernelCustomization{
						Append: "audit=1 selinux=1",
					},
				},
			},
			snapshotCust: nil,
			currentCust: &v1.Customizations{
				Kernel: &v1.Kernel{
					Append: common.ToPtr("audit=1"),
				},
			},
			fixup:          true,
			expectedErrors: []v1.BlueprintLintItem{},
			expectedWarns:  []v1.BlueprintLintItem{},
			expectedCust: &v1.Customizations{
				Kernel: &v1.Kernel{
					Append: common.ToPtr("audit=1 selinux=1"),
				},
			},
		},
		{
			name: "obsolete kernel settings - warnings only",
			policyBP: &blueprint.Blueprint{
				Customizations: &blueprint.Customizations{
					Kernel: &blueprint.KernelCustomization{
						Name: "current-kernel",
					},
				},
			},
			snapshotCust: &v1.Customizations{
				Kernel: &v1.Kernel{
					Name:   common.ToPtr("obsolete-kernel"),
					Append: common.ToPtr("obsolete-param=1"),
				},
			},
			currentCust: &v1.Customizations{
				Kernel: &v1.Kernel{
					Name: common.ToPtr("current-kernel"),
				},
			},
			fixup:          false,
			expectedErrors: []v1.BlueprintLintItem{},
			expectedWarns: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "kernel name obsolete-kernel is no longer required by policy"},
				{Name: "Compliance", Description: "kernel command line parameter 'obsolete-param=1' is no longer required by policy"},
			},
		},
		{
			name: "nil kernel in current customizations",
			policyBP: &blueprint.Blueprint{
				Customizations: &blueprint.Customizations{
					Kernel: &blueprint.KernelCustomization{
						Name: "required-kernel",
					},
				},
			},
			snapshotCust: nil,
			currentCust: &v1.Customizations{
				Kernel: nil,
			},
			fixup: false,
			expectedErrors: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "kernel name required-kernel required by policy not set"},
			},
			expectedWarns: []v1.BlueprintLintItem{},
		},
		{
			name: "no kernel customizations in policy",
			policyBP: &blueprint.Blueprint{
				Customizations: nil,
			},
			snapshotCust: &v1.Customizations{
				Kernel: &v1.Kernel{
					Name: common.ToPtr("obsolete-kernel"),
				},
			},
			currentCust: &v1.Customizations{
				Kernel: &v1.Kernel{
					Name: common.ToPtr("some-kernel"),
				},
			},
			fixup:          false,
			expectedErrors: []v1.BlueprintLintItem{},
			expectedWarns: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "kernel name obsolete-kernel is no longer required by policy"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a copy of currentCust to avoid modifying the original
			currentCustCopy := *tt.currentCust
			if tt.currentCust.Kernel != nil {
				kernelCopy := *tt.currentCust.Kernel
				if tt.currentCust.Kernel.Name != nil {
					nameCopy := *tt.currentCust.Kernel.Name
					kernelCopy.Name = &nameCopy
				}
				if tt.currentCust.Kernel.Append != nil {
					appendCopy := *tt.currentCust.Kernel.Append
					kernelCopy.Append = &appendCopy
				}
				currentCustCopy.Kernel = &kernelCopy
			}

			errors, warnings := v1.LintKernel(tt.policyBP, tt.snapshotCust, &currentCustCopy, tt.fixup)

			assert.Equal(t, tt.expectedErrors, errors)
			assert.Equal(t, tt.expectedWarns, warnings)

			if tt.fixup && tt.expectedCust != nil {
				assert.Equal(t, tt.expectedCust.Kernel, currentCustCopy.Kernel)
			}
		})
	}
}

// Test lintFIPS function for both adding missing FIPS settings and removing obsolete FIPS settings
func TestLintFIPS(t *testing.T) {
	tests := []struct {
		name           string
		policyBP       *blueprint.Blueprint
		snapshotCust   *v1.Customizations
		currentCust    *v1.Customizations
		fixup          bool
		expectedErrors []v1.BlueprintLintItem
		expectedWarns  []v1.BlueprintLintItem
		expectedCust   *v1.Customizations
	}{
		{
			name: "FIPS required but not set - error only",
			policyBP: &blueprint.Blueprint{
				Customizations: &blueprint.Customizations{
					FIPS: common.ToPtr(true),
				},
			},
			snapshotCust: nil,
			currentCust: &v1.Customizations{
				Fips: nil,
			},
			fixup: false,
			expectedErrors: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "FIPS required 'true' by policy but not set"},
			},
			expectedWarns: []v1.BlueprintLintItem{},
		},
		{
			name: "FIPS required but disabled - error only",
			policyBP: &blueprint.Blueprint{
				Customizations: &blueprint.Customizations{
					FIPS: common.ToPtr(true),
				},
			},
			snapshotCust: nil,
			currentCust: &v1.Customizations{
				Fips: &v1.FIPS{
					Enabled: common.ToPtr(false),
				},
			},
			fixup: false,
			expectedErrors: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "FIPS required 'true' by policy but not set"},
			},
			expectedWarns: []v1.BlueprintLintItem{},
		},
		{
			name: "FIPS required with fixup",
			policyBP: &blueprint.Blueprint{
				Customizations: &blueprint.Customizations{
					FIPS: common.ToPtr(true),
				},
			},
			snapshotCust: nil,
			currentCust: &v1.Customizations{
				Fips: nil,
			},
			fixup:          true,
			expectedErrors: []v1.BlueprintLintItem{},
			expectedWarns:  []v1.BlueprintLintItem{},
			expectedCust: &v1.Customizations{
				Fips: &v1.FIPS{
					Enabled: common.ToPtr(true),
				},
			},
		},
		{
			name: "FIPS no longer required - warning only",
			policyBP: &blueprint.Blueprint{
				Customizations: &blueprint.Customizations{
					FIPS: common.ToPtr(false),
				},
			},
			snapshotCust: &v1.Customizations{
				Fips: &v1.FIPS{
					Enabled: common.ToPtr(true),
				},
			},
			currentCust: &v1.Customizations{
				Fips: &v1.FIPS{
					Enabled: common.ToPtr(true),
				},
			},
			fixup:          false,
			expectedErrors: []v1.BlueprintLintItem{},
			expectedWarns: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "FIPS is no longer required by policy"},
			},
		},
		{
			name: "FIPS not required in policy",
			policyBP: &blueprint.Blueprint{
				Customizations: nil,
			},
			snapshotCust: &v1.Customizations{
				Fips: &v1.FIPS{
					Enabled: common.ToPtr(true),
				},
			},
			currentCust: &v1.Customizations{
				Fips: &v1.FIPS{
					Enabled: common.ToPtr(true),
				},
			},
			fixup:          false,
			expectedErrors: []v1.BlueprintLintItem{},
			expectedWarns: []v1.BlueprintLintItem{
				{Name: "Compliance", Description: "FIPS is no longer required by policy"},
			},
		},
		{
			name: "FIPS correctly configured - no errors or warnings",
			policyBP: &blueprint.Blueprint{
				Customizations: &blueprint.Customizations{
					FIPS: common.ToPtr(true),
				},
			},
			snapshotCust: nil,
			currentCust: &v1.Customizations{
				Fips: &v1.FIPS{
					Enabled: common.ToPtr(true),
				},
			},
			fixup:          false,
			expectedErrors: []v1.BlueprintLintItem{},
			expectedWarns:  []v1.BlueprintLintItem{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a copy of currentCust to avoid modifying the original
			currentCustCopy := *tt.currentCust
			if tt.currentCust.Fips != nil {
				fipsCopy := *tt.currentCust.Fips
				if tt.currentCust.Fips.Enabled != nil {
					enabledCopy := *tt.currentCust.Fips.Enabled
					fipsCopy.Enabled = &enabledCopy
				}
				currentCustCopy.Fips = &fipsCopy
			}

			errors, warnings := v1.LintFIPS(tt.policyBP, tt.snapshotCust, &currentCustCopy, tt.fixup)

			assert.Equal(t, tt.expectedErrors, errors)
			assert.Equal(t, tt.expectedWarns, warnings)

			if tt.fixup && tt.expectedCust != nil {
				assert.Equal(t, tt.expectedCust.Fips, currentCustCopy.Fips)
			}
		})
	}
}

// Test the fixup functionality comprehensively
func TestFixupFunctionality(t *testing.T) {
	t.Run("comprehensive fixup test", func(t *testing.T) {
		policyBP := &blueprint.Blueprint{
			Packages: []blueprint.Package{
				{Name: "required-pkg"},
			},
			Customizations: &blueprint.Customizations{
				Filesystem: []blueprint.FilesystemCustomization{
					{Mountpoint: "/var", MinSize: 1024},
				},
				Services: &blueprint.ServicesCustomization{
					Enabled: []string{"required-service"},
				},
				Kernel: &blueprint.KernelCustomization{
					Name:   "required-kernel",
					Append: "audit=1",
				},
				FIPS: common.ToPtr(true),
			},
		}

		currentCust := &v1.Customizations{
			Packages: common.ToPtr([]string{"existing-pkg"}),
		}

		// Test packages fixup
		errors, warnings := v1.LintPackages(policyBP, nil, currentCust, true)
		require.Empty(t, errors)
		require.Empty(t, warnings)
		require.Contains(t, *currentCust.Packages, "required-pkg")
		require.Contains(t, *currentCust.Packages, "existing-pkg")

		// Test filesystems fixup
		errors, warnings = v1.LintFilesystems(policyBP, nil, currentCust, true)
		require.Empty(t, errors)
		require.Empty(t, warnings)
		require.NotNil(t, currentCust.Filesystem)
		require.Len(t, *currentCust.Filesystem, 1)
		require.Equal(t, "/var", (*currentCust.Filesystem)[0].Mountpoint)
		require.Equal(t, uint64(1024), (*currentCust.Filesystem)[0].MinSize)

		// Test services fixup
		errors, warnings = v1.LintServices(policyBP, nil, currentCust, true)
		require.Empty(t, errors)
		require.Empty(t, warnings)
		require.NotNil(t, currentCust.Services)
		require.NotNil(t, currentCust.Services.Enabled)
		require.Contains(t, *currentCust.Services.Enabled, "required-service")

		// Test kernel fixup
		errors, warnings = v1.LintKernel(policyBP, nil, currentCust, true)
		require.Empty(t, errors)
		require.Empty(t, warnings)
		require.NotNil(t, currentCust.Kernel)
		require.Equal(t, "required-kernel", *currentCust.Kernel.Name)
		require.Equal(t, "audit=1", *currentCust.Kernel.Append)

		// Test FIPS fixup
		errors, warnings = v1.LintFIPS(policyBP, nil, currentCust, true)
		require.Empty(t, errors)
		require.Empty(t, warnings)
		require.NotNil(t, currentCust.Fips)
		require.True(t, *currentCust.Fips.Enabled)
	})
}

// Test edge cases and error conditions
func TestLintEdgeCases(t *testing.T) {
	t.Run("empty policy blueprint", func(t *testing.T) {
		policyBP := &blueprint.Blueprint{}
		currentCust := &v1.Customizations{
			Packages: common.ToPtr([]string{"some-pkg"}),
		}

		errors, warnings := v1.LintPackages(policyBP, nil, currentCust, false)
		require.Empty(t, errors)
		require.Empty(t, warnings)
	})

	t.Run("nil policy blueprint", func(t *testing.T) {
		currentCust := &v1.Customizations{
			Packages: common.ToPtr([]string{"some-pkg"}),
		}

		errors, warnings := v1.LintPackages(nil, nil, currentCust, false)
		require.Empty(t, errors)
		require.Empty(t, warnings)
	})

	t.Run("nil current customizations", func(t *testing.T) {
		policyBP := &blueprint.Blueprint{
			Packages: []blueprint.Package{
				{Name: "required-pkg"},
			},
		}

		errors, warnings := v1.LintPackages(policyBP, nil, nil, false)
		require.Len(t, errors, 1)
		require.Equal(t, "package required-pkg required by policy is not present", errors[0].Description)
		require.Empty(t, warnings)
	})

	t.Run("empty strings in kernel append", func(t *testing.T) {
		policyBP := &blueprint.Blueprint{
			Customizations: &blueprint.Customizations{
				Kernel: &blueprint.KernelCustomization{
					Append: "audit=1  selinux=1", // Multiple spaces
				},
			},
		}
		currentCust := &v1.Customizations{
			Kernel: &v1.Kernel{
				Append: common.ToPtr("audit=1"),
			},
		}

		errors, warnings := v1.LintKernel(policyBP, nil, currentCust, false)
		require.Len(t, errors, 1)
		require.Equal(t, "kernel command line parameter 'selinux=1' required by policy not set", errors[0].Description)
		require.Empty(t, warnings)
	})
}
