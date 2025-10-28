package v1

import (
	"testing"

	"github.com/osbuild/blueprint/pkg/blueprint"
	"github.com/stretchr/testify/require"

	"github.com/osbuild/image-builder-crc/internal/common"
)

// ============================== PACKAGES ==============================

// Flow test: initial open shows errors, fixup applies, next open has no errors (packages)
func TestPackages_Additions_Flow_ErrorThenFixup_NoError(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Packages: []blueprint.Package{{Name: "pkg-required-1"}, {Name: "pkg-required-2"}},
	}

	current := &Customizations{Packages: common.ToPtr([]string{"pkg-existing"})}

	// Step 1: open (fixup=false) -> expect errors for missing packages
	errs := lintPackagesE(policyBP, current, false)
	warns := lintPackagesW(policyBP, nil)
	require.Len(t, errs, 2)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "package pkg-required-1 required by policy is not present")
	require.Contains(t, errs[1].Description, "package pkg-required-2 required by policy is not present")

	// Step 2: user chooses fixup -> apply changes, errors reported but fixup applied
	errs = lintPackagesE(policyBP, current, true)
	warns = lintPackagesW(policyBP, nil)
	require.Len(t, errs, 2)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "package pkg-required-1 required by policy is not present")
	require.Contains(t, errs[1].Description, "package pkg-required-2 required by policy is not present")
	require.ElementsMatch(t,
		[]string{"pkg-existing", "pkg-required-1", "pkg-required-2"},
		common.FromPtr(current.Packages),
	)

	// Step 3: open again (fixup=false) -> no errors now
	errs = lintPackagesE(policyBP, current, false)
	warns = lintPackagesW(policyBP, nil)
	require.Empty(t, errs)
	require.Empty(t, warns)
}

func TestPackages_Removals_FromSnapshot_Warns(t *testing.T) {
	policyBP := &blueprint.Blueprint{Packages: []blueprint.Package{{Name: "pkg-keep"}}}
	snapshot := &Customizations{Packages: common.ToPtr([]string{"pkg-keep", "pkg-obsolete"})}
	current := &Customizations{Packages: common.ToPtr([]string{"pkg-keep"})}

	errs := lintPackagesE(policyBP, current, false)
	warns := lintPackagesW(policyBP, snapshot)
	require.Empty(t, errs)
	require.Len(t, warns, 1)
	require.Equal(t, "Compliance", warns[0].Name)
	require.Contains(t, warns[0].Description, "package pkg-obsolete is no longer required by policy")
}

// ============================== SERVICES - ENABLED ==============================

// Flow test: initial open shows errors, fixup applies, next open has no errors (enabled services)
func TestServices_EnabledAdditions_Flow_ErrorThenFixup_NoError(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Services: &blueprint.ServicesCustomization{
				Enabled: []string{"svc-required-1", "svc-required-2"},
			},
		},
	}

	current := &Customizations{Services: &Services{Enabled: common.ToPtr([]string{"svc-existing"})}}

	// Step 1: open (fixup=false) -> expect errors for missing services
	errs := lintServicesE(policyBP, current, false)
	warns := lintServicesW(policyBP, nil)
	require.Len(t, errs, 2)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "service svc-required-1 required as enabled by policy is not present")
	require.Contains(t, errs[1].Description, "service svc-required-2 required as enabled by policy is not present")

	// Step 2: user chooses fixup -> apply changes, errors reported but fixup applied
	errs = lintServicesE(policyBP, current, true)
	warns = lintServicesW(policyBP, nil)
	require.Len(t, errs, 2)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "service svc-required-1 required as enabled by policy is not present")
	require.Contains(t, errs[1].Description, "service svc-required-2 required as enabled by policy is not present")
	require.ElementsMatch(t,
		[]string{"svc-existing", "svc-required-1", "svc-required-2"},
		common.FromPtr(current.Services.Enabled),
	)

	// Step 3: open again (fixup=false) -> no errors now
	errs = lintServicesE(policyBP, current, false)
	warns = lintServicesW(policyBP, nil)
	require.Empty(t, errs)
	require.Empty(t, warns)
}

func TestServices_EnabledRemovals_FromSnapshot_Warns(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Services: &blueprint.ServicesCustomization{
				Enabled: []string{"svc-keep"},
			},
		},
	}
	snapshot := &Customizations{Services: &Services{Enabled: common.ToPtr([]string{"svc-keep", "svc-obsolete"})}}
	current := &Customizations{Services: &Services{Enabled: common.ToPtr([]string{"svc-keep"})}}

	errs := lintServicesE(policyBP, current, false)
	warns := lintServicesW(policyBP, snapshot)
	require.Empty(t, errs)
	require.Len(t, warns, 1)
	require.Equal(t, "Compliance", warns[0].Name)
	require.Contains(t, warns[0].Description, "service svc-obsolete is no longer required as enabled by policy")
}

// ============================== SERVICES - DISABLED ==============================

// Flow test: initial open shows errors, fixup applies, next open has no errors (disabled services)
func TestServices_DisabledAdditions_Flow_ErrorThenFixup_NoError(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Services: &blueprint.ServicesCustomization{
				Disabled: []string{"svc-disable-1", "svc-disable-2"},
			},
		},
	}

	current := &Customizations{Services: &Services{Disabled: common.ToPtr([]string{"svc-existing"})}}

	// Step 1: open (fixup=false) -> expect errors for missing disabled services
	errs := lintServicesE(policyBP, current, false)
	warns := lintServicesW(policyBP, nil)
	require.Len(t, errs, 2)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "service svc-disable-1 required as disabled by policy is not present")
	require.Contains(t, errs[1].Description, "service svc-disable-2 required as disabled by policy is not present")

	// Step 2: user chooses fixup -> apply changes, errors reported but fixup applied
	errs = lintServicesE(policyBP, current, true)
	warns = lintServicesW(policyBP, nil)
	require.Len(t, errs, 2)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "service svc-disable-1 required as disabled by policy is not present")
	require.Contains(t, errs[1].Description, "service svc-disable-2 required as disabled by policy is not present")
	require.ElementsMatch(t,
		[]string{"svc-existing", "svc-disable-1", "svc-disable-2"},
		common.FromPtr(current.Services.Disabled),
	)

	// Step 3: open again (fixup=false) -> no errors now
	errs = lintServicesE(policyBP, current, false)
	warns = lintServicesW(policyBP, nil)
	require.Empty(t, errs)
	require.Empty(t, warns)
}

func TestServices_DisabledRemovals_FromSnapshot_Warns(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Services: &blueprint.ServicesCustomization{
				Disabled: []string{"svc-keep"},
			},
		},
	}
	snapshot := &Customizations{Services: &Services{Disabled: common.ToPtr([]string{"svc-keep", "svc-obsolete"})}}
	current := &Customizations{Services: &Services{Disabled: common.ToPtr([]string{"svc-keep"})}}

	errs := lintServicesE(policyBP, current, false)
	warns := lintServicesW(policyBP, snapshot)
	require.Empty(t, errs)
	require.Len(t, warns, 1)
	require.Equal(t, "Compliance", warns[0].Name)
	require.Contains(t, warns[0].Description, "service svc-obsolete is no longer required as disabled by policy")
}

// ============================== SERVICES - MASKED ==============================

// Flow test: initial open shows errors, fixup applies, next open has no errors (masked services)
func TestServices_MaskedAdditions_Flow_ErrorThenFixup_NoError(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Services: &blueprint.ServicesCustomization{
				Masked: []string{"svc-mask-1", "svc-mask-2"},
			},
		},
	}

	current := &Customizations{Services: &Services{Masked: common.ToPtr([]string{"svc-existing"})}}

	// Step 1: open (fixup=false) -> expect errors for missing masked services
	errs := lintServicesE(policyBP, current, false)
	warns := lintServicesW(policyBP, nil)
	require.Len(t, errs, 2)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "service svc-mask-1 required as masked by policy is not present")
	require.Contains(t, errs[1].Description, "service svc-mask-2 required as masked by policy is not present")

	// Step 2: user chooses fixup -> apply changes, errors reported but fixup applied
	errs = lintServicesE(policyBP, current, true)
	warns = lintServicesW(policyBP, nil)
	require.Len(t, errs, 2)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "service svc-mask-1 required as masked by policy is not present")
	require.Contains(t, errs[1].Description, "service svc-mask-2 required as masked by policy is not present")
	require.ElementsMatch(t,
		[]string{"svc-existing", "svc-mask-1", "svc-mask-2"},
		common.FromPtr(current.Services.Masked),
	)

	// Step 3: open again (fixup=false) -> no errors now
	errs = lintServicesE(policyBP, current, false)
	warns = lintServicesW(policyBP, nil)
	require.Empty(t, errs)
	require.Empty(t, warns)
}

func TestServices_MaskedRemovals_FromSnapshot_Warns(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Services: &blueprint.ServicesCustomization{
				Masked: []string{"svc-keep"},
			},
		},
	}
	snapshot := &Customizations{Services: &Services{Masked: common.ToPtr([]string{"svc-keep", "svc-obsolete"})}}
	current := &Customizations{Services: &Services{Masked: common.ToPtr([]string{"svc-keep"})}}

	errs := lintServicesE(policyBP, current, false)
	warns := lintServicesW(policyBP, snapshot)
	require.Empty(t, errs)
	require.Len(t, warns, 1)
	require.Equal(t, "Compliance", warns[0].Name)
	require.Contains(t, warns[0].Description, "service svc-obsolete is no longer required as masked by policy")
}

// ============================== FILESYSTEMS ==============================

// Flow test: initial open shows errors, fixup applies, next open has no errors (filesystems)
func TestFilesystems_Additions_Flow_ErrorThenFixup_NoError(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Filesystem: []blueprint.FilesystemCustomization{
				{Mountpoint: "/var/log", MinSize: 1000},
				{Mountpoint: "/tmp", MinSize: 2000},
			},
		},
	}

	current := &Customizations{Filesystem: common.ToPtr([]Filesystem{{Mountpoint: "/existing", MinSize: 500}})}

	// Step 1: open (fixup=false) -> expect errors for missing filesystems
	errs := lintFilesystemsE(policyBP, current, false)
	warns := lintFilesystemsW(policyBP, nil)
	require.Len(t, errs, 2)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "mountpoint /var/log required by policy is not present")
	require.Contains(t, errs[1].Description, "mountpoint /tmp required by policy is not present")

	// Step 2: user chooses fixup -> apply changes, errors reported but fixup applied
	errs = lintFilesystemsE(policyBP, current, true)
	warns = lintFilesystemsW(policyBP, nil)
	require.Len(t, errs, 2)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "mountpoint /var/log required by policy is not present")
	require.Contains(t, errs[1].Description, "mountpoint /tmp required by policy is not present")
	require.Len(t, common.FromPtr(current.Filesystem), 3)
	mountpoints := make([]string, len(common.FromPtr(current.Filesystem)))
	for i, fs := range common.FromPtr(current.Filesystem) {
		mountpoints[i] = fs.Mountpoint
	}
	require.ElementsMatch(t, []string{"/existing", "/var/log", "/tmp"}, mountpoints)

	// Check specific filesystems were added with correct MinSize
	for _, fs := range common.FromPtr(current.Filesystem) {
		switch fs.Mountpoint {
		case "/var/log":
			require.Equal(t, uint64(1000), fs.MinSize)
		case "/tmp":
			require.Equal(t, uint64(2000), fs.MinSize)
		case "/existing":
			require.Equal(t, uint64(500), fs.MinSize)
		}
	}

	// Step 3: open again (fixup=false) -> no errors now
	errs = lintFilesystemsE(policyBP, current, false)
	warns = lintFilesystemsW(policyBP, nil)
	require.Empty(t, errs)
	require.Empty(t, warns)
}

func TestFilesystems_Removals_FromSnapshot_Warns(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Filesystem: []blueprint.FilesystemCustomization{
				{Mountpoint: "/var/log", MinSize: 1000},
			},
		},
	}
	snapshot := &Customizations{Filesystem: common.ToPtr([]Filesystem{
		{Mountpoint: "/var/log", MinSize: 1000},
		{Mountpoint: "/obsolete", MinSize: 500},
	})}
	current := &Customizations{Filesystem: common.ToPtr([]Filesystem{{Mountpoint: "/var/log", MinSize: 1000}})}

	errs := lintFilesystemsE(policyBP, current, false)
	warns := lintFilesystemsW(policyBP, snapshot)
	require.Empty(t, errs)
	require.Len(t, warns, 1)
	require.Equal(t, "Compliance", warns[0].Name)
	require.Contains(t, warns[0].Description, "mountpoint /obsolete is no longer required by policy")
}

// ============================== KERNEL - NAME ==============================

// Flow test: initial open shows errors, fixup applies, next open has no errors (kernel name)
func TestKernel_NameAddition_Flow_ErrorThenFixup_NoError(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Kernel: &blueprint.KernelCustomization{
				Name: "kernel-rt",
			},
		},
	}

	current := &Customizations{Kernel: &Kernel{Name: common.ToPtr("kernel-standard")}}

	// Step 1: open (fixup=false) -> expect errors for incorrect kernel name
	errs := lintKernelE(policyBP, current, false)
	warns := lintKernelW(policyBP, nil)
	require.Len(t, errs, 1)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "kernel name kernel-rt required by policy not set")

	// Step 2: user chooses fixup -> apply changes, errors reported but fixup applied
	errs = lintKernelE(policyBP, current, true)
	warns = lintKernelW(policyBP, nil)
	require.Len(t, errs, 1)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "kernel name kernel-rt required by policy not set")
	require.NotNil(t, current.Kernel.Name)
	require.Equal(t, "kernel-rt", *current.Kernel.Name)

	// Step 3: open again (fixup=false) -> no errors now
	errs = lintKernelE(policyBP, current, false)
	warns = lintKernelW(policyBP, nil)
	require.Empty(t, errs)
	require.Empty(t, warns)
}

func TestKernel_NameRemoval_FromSnapshot_Warns(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Kernel: &blueprint.KernelCustomization{
				Name: "kernel-standard",
			},
		},
	}
	snapshot := &Customizations{Kernel: &Kernel{Name: common.ToPtr("kernel-obsolete")}}
	current := &Customizations{Kernel: &Kernel{Name: common.ToPtr("kernel-standard")}}

	errs := lintKernelE(policyBP, current, false)
	warns := lintKernelW(policyBP, snapshot)
	require.Empty(t, errs)
	require.Len(t, warns, 1)
	require.Equal(t, "Compliance", warns[0].Name)
	require.Contains(t, warns[0].Description, "kernel name kernel-obsolete is no longer required by policy")
}

// ============================== KERNEL - APPEND ==============================

// Flow test: initial open shows errors, fixup applies, next open has no errors (kernel append)
func TestKernel_AppendAddition_Flow_ErrorThenFixup_NoError(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Kernel: &blueprint.KernelCustomization{
				Append: "fips=1",
			},
		},
	}

	current := &Customizations{Kernel: &Kernel{Append: common.ToPtr("quiet splash")}}

	// Step 1: open (fixup=false) -> expect errors for missing kernel parameters
	errs := lintKernelE(policyBP, current, false)
	warns := lintKernelW(policyBP, nil)
	require.Len(t, errs, 1)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "kernel command line parameter 'fips=1' required by policy not set")

	// Step 2: user chooses fixup -> apply changes, errors reported but fixup applied
	errs = lintKernelE(policyBP, current, true)
	warns = lintKernelW(policyBP, nil)
	require.Len(t, errs, 1)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "kernel command line parameter 'fips=1' required by policy not set")
	require.NotNil(t, current.Kernel.Append)
	require.Contains(t, *current.Kernel.Append, "quiet splash")
	require.Contains(t, *current.Kernel.Append, "fips=1")

	// Step 3: open again (fixup=false) -> no errors now
	errs = lintKernelE(policyBP, current, false)
	warns = lintKernelW(policyBP, nil)
	require.Empty(t, errs)
	require.Empty(t, warns)
}

func TestKernel_AppendRemoval_FromSnapshot_Warns(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Kernel: &blueprint.KernelCustomization{
				Append: "audit=1",
			},
		},
	}
	snapshot := &Customizations{Kernel: &Kernel{Append: common.ToPtr("audit=1 obsolete=1")}}
	current := &Customizations{Kernel: &Kernel{Append: common.ToPtr("audit=1")}}

	errs := lintKernelE(policyBP, current, false)
	warns := lintKernelW(policyBP, snapshot)
	require.Empty(t, errs)
	require.Len(t, warns, 1)
	require.Equal(t, "Compliance", warns[0].Name)
	require.Contains(t, warns[0].Description, "kernel command line parameter 'obsolete=1' is no longer required by policy")
}

// ============================== FIPS ==============================

// Flow test: initial open shows errors, fixup applies, next open has no errors (FIPS enabled)
func TestFIPS_EnabledAddition_Flow_ErrorThenFixup_NoError(t *testing.T) {
	fipsTrue := true
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			FIPS: &fipsTrue,
		},
	}

	fipsFalse := false
	current := &Customizations{Fips: &FIPS{Enabled: &fipsFalse}}

	// Step 1: open (fixup=false) -> expect errors for FIPS not enabled
	errs := lintFIPSE(policyBP, current, false)
	warns := lintFIPSW(policyBP, nil)
	require.Len(t, errs, 1)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "FIPS required 'true' by policy but not set")

	// Step 2: user chooses fixup -> apply changes, errors reported but fixup applied
	errs = lintFIPSE(policyBP, current, true)
	warns = lintFIPSW(policyBP, nil)
	require.Len(t, errs, 1)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "FIPS required 'true' by policy but not set")
	require.NotNil(t, current.Fips)
	require.NotNil(t, current.Fips.Enabled)
	require.True(t, *current.Fips.Enabled)

	// Step 3: open again (fixup=false) -> no errors now
	errs = lintFIPSE(policyBP, current, false)
	warns = lintFIPSW(policyBP, nil)
	require.Empty(t, errs)
	require.Empty(t, warns)
}

func TestFIPS_NotSet_Fixup_CreatesAndEnables(t *testing.T) {
	fipsTrue := true
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			FIPS: &fipsTrue,
		},
	}
	current := &Customizations{} // No FIPS field set

	errs := lintFIPSE(policyBP, current, true)
	warns := lintFIPSW(policyBP, nil)
	require.Len(t, errs, 1)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "FIPS required 'true' by policy but not set")
	require.NotNil(t, current.Fips)
	require.NotNil(t, current.Fips.Enabled)
	require.True(t, *current.Fips.Enabled)
}

func TestFIPS_Removal_FromSnapshot_Warns(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			// No FIPS requirement in current policy
		},
	}
	fipsTrue := true
	fipsFalse := false
	snapshot := &Customizations{Fips: &FIPS{Enabled: &fipsTrue}}
	current := &Customizations{Fips: &FIPS{Enabled: &fipsFalse}}

	errs := lintFIPSE(policyBP, current, false)
	warns := lintFIPSW(policyBP, snapshot)
	require.Empty(t, errs)
	require.Len(t, warns, 1)
	require.Equal(t, "Compliance", warns[0].Name)
	require.Contains(t, warns[0].Description, "FIPS is no longer required by policy")
}

func TestFIPS_DisabledInPolicy_SnapshotEnabled_Warns(t *testing.T) {
	fipsFalse := false
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			FIPS: &fipsFalse,
		},
	}
	fipsTrue := true
	snapshot := &Customizations{Fips: &FIPS{Enabled: &fipsTrue}}
	current := &Customizations{Fips: &FIPS{Enabled: &fipsFalse}}

	errs := lintFIPSE(policyBP, current, false)
	warns := lintFIPSW(policyBP, snapshot)
	require.Empty(t, errs)
	require.Len(t, warns, 1)
	require.Equal(t, "Compliance", warns[0].Name)
	require.Contains(t, warns[0].Description, "FIPS is no longer required by policy")
}
