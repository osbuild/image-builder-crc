package v1

import (
	"testing"

	"github.com/osbuild/blueprint/pkg/blueprint"
	"github.com/stretchr/testify/require"

	"github.com/osbuild/image-builder-crc/internal/common"
)

// 1) Added items, fixup=false: expect errors (packages)
func TestPackages_Additions_NoFixup_Errors(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Packages: []blueprint.Package{{Name: "pkg-required-1"}, {Name: "pkg-required-2"}},
	}
	current := &Customizations{Packages: common.ToPtr([]string{"pkg-existing"})}

	errs, warns := lintPackages(policyBP, nil, current, false)
	require.Len(t, errs, 2)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "package pkg-required-1 required by policy is not present")
	require.Contains(t, errs[1].Description, "package pkg-required-2 required by policy is not present")
}

// 2) Added items, fixup=true: expect no errors and packages are added
func TestPackages_Additions_Fixup_ResolvesErrors(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Packages: []blueprint.Package{{Name: "pkg-required-1"}, {Name: "pkg-required-2"}},
	}
	current := &Customizations{Packages: common.ToPtr([]string{"pkg-existing"})}

	errs, warns := lintPackages(policyBP, nil, current, true)
	require.Empty(t, errs)
	require.Empty(t, warns)
	require.ElementsMatch(t,
		[]string{"pkg-existing", "pkg-required-1", "pkg-required-2"},
		common.FromPtr(current.Packages),
	)
}

// 3) Removed items (from snapshot): expect warnings (packages)
func TestPackages_Removals_FromSnapshot_Warns(t *testing.T) {
	policyBP := &blueprint.Blueprint{Packages: []blueprint.Package{{Name: "pkg-keep"}}}
	snapshot := &Customizations{Packages: common.ToPtr([]string{"pkg-keep", "pkg-obsolete"})}
	current := &Customizations{Packages: common.ToPtr([]string{"pkg-keep"})}

	errs, warns := lintPackages(policyBP, snapshot, current, false)
	require.Empty(t, errs)
	require.Len(t, warns, 1)
	require.Equal(t, "Compliance", warns[0].Name)
	require.Contains(t, warns[0].Description, "package pkg-obsolete is no longer required by policy")
}

// 1) Added services, fixup=false: expect errors (enabled services)
func TestServices_EnabledAdditions_NoFixup_Errors(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Services: &blueprint.ServicesCustomization{
				Enabled: []string{"svc-required-1", "svc-required-2"},
			},
		},
	}
	current := &Customizations{Services: &Services{Enabled: common.ToPtr([]string{"svc-existing"})}}

	errs, warns := lintServices(policyBP, nil, current, false)
	require.Len(t, errs, 2)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "service svc-required-1 required as enabled by policy is not present")
	require.Contains(t, errs[1].Description, "service svc-required-2 required as enabled by policy is not present")
}

// 2) Added services, fixup=true: expect no errors and services are added (enabled services)
func TestServices_EnabledAdditions_Fixup_ResolvesErrors(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Services: &blueprint.ServicesCustomization{
				Enabled: []string{"svc-required-1", "svc-required-2"},
			},
		},
	}
	current := &Customizations{Services: &Services{Enabled: common.ToPtr([]string{"svc-existing"})}}

	errs, warns := lintServices(policyBP, nil, current, true)
	require.Empty(t, errs)
	require.Empty(t, warns)
	require.ElementsMatch(t,
		[]string{"svc-existing", "svc-required-1", "svc-required-2"},
		common.FromPtr(current.Services.Enabled),
	)
}

// 3) Removed enabled services (from snapshot): expect warnings
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

	errs, warns := lintServices(policyBP, snapshot, current, false)
	require.Empty(t, errs)
	require.Len(t, warns, 1)
	require.Equal(t, "Compliance", warns[0].Name)
	require.Contains(t, warns[0].Description, "service svc-obsolete is no longer required as enabled by policy")
}

// 4) Added disabled services, fixup=false: expect errors
func TestServices_DisabledAdditions_NoFixup_Errors(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Services: &blueprint.ServicesCustomization{
				Disabled: []string{"svc-disable-1", "svc-disable-2"},
			},
		},
	}
	current := &Customizations{Services: &Services{Disabled: common.ToPtr([]string{"svc-existing"})}}

	errs, warns := lintServices(policyBP, nil, current, false)
	require.Len(t, errs, 2)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "service svc-disable-1 required as disabled by policy is not present")
	require.Contains(t, errs[1].Description, "service svc-disable-2 required as disabled by policy is not present")
}

// 5) Added disabled services, fixup=true: expect no errors and services are added
func TestServices_DisabledAdditions_Fixup_ResolvesErrors(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Services: &blueprint.ServicesCustomization{
				Disabled: []string{"svc-disable-1", "svc-disable-2"},
			},
		},
	}
	current := &Customizations{Services: &Services{Disabled: common.ToPtr([]string{"svc-existing"})}}

	errs, warns := lintServices(policyBP, nil, current, true)
	require.Empty(t, errs)
	require.Empty(t, warns)
	require.ElementsMatch(t,
		[]string{"svc-existing", "svc-disable-1", "svc-disable-2"},
		common.FromPtr(current.Services.Disabled),
	)
}

// 6) Removed disabled services (from snapshot): expect warnings
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

	errs, warns := lintServices(policyBP, snapshot, current, false)
	require.Empty(t, errs)
	require.Len(t, warns, 1)
	require.Equal(t, "Compliance", warns[0].Name)
	require.Contains(t, warns[0].Description, "service svc-obsolete is no longer required as disabled by policy")
}

// 7) Added masked services, fixup=false: expect errors
func TestServices_MaskedAdditions_NoFixup_Errors(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Services: &blueprint.ServicesCustomization{
				Masked: []string{"svc-mask-1", "svc-mask-2"},
			},
		},
	}
	current := &Customizations{Services: &Services{Masked: common.ToPtr([]string{"svc-existing"})}}

	errs, warns := lintServices(policyBP, nil, current, false)
	require.Len(t, errs, 2)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "service svc-mask-1 required as masked by policy is not present")
	require.Contains(t, errs[1].Description, "service svc-mask-2 required as masked by policy is not present")
}

// 8) Added masked services, fixup=true: expect no errors and services are added
func TestServices_MaskedAdditions_Fixup_ResolvesErrors(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Services: &blueprint.ServicesCustomization{
				Masked: []string{"svc-mask-1", "svc-mask-2"},
			},
		},
	}
	current := &Customizations{Services: &Services{Masked: common.ToPtr([]string{"svc-existing"})}}

	errs, warns := lintServices(policyBP, nil, current, true)
	require.Empty(t, errs)
	require.Empty(t, warns)
	require.ElementsMatch(t,
		[]string{"svc-existing", "svc-mask-1", "svc-mask-2"},
		common.FromPtr(current.Services.Masked),
	)
}

// 9) Removed masked services (from snapshot): expect warnings
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

	errs, warns := lintServices(policyBP, snapshot, current, false)
	require.Empty(t, errs)
	require.Len(t, warns, 1)
	require.Equal(t, "Compliance", warns[0].Name)
	require.Contains(t, warns[0].Description, "service svc-obsolete is no longer required as masked by policy")
}

// 1) Added filesystems, fixup=false: expect errors
func TestFilesystems_Additions_NoFixup_Errors(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Filesystem: []blueprint.FilesystemCustomization{
				{Mountpoint: "/var/log", MinSize: 1000},
				{Mountpoint: "/tmp", MinSize: 2000},
			},
		},
	}
	current := &Customizations{Filesystem: common.ToPtr([]Filesystem{{Mountpoint: "/existing", MinSize: 500}})}

	errs, warns := lintFilesystems(policyBP, nil, current, false)
	require.Len(t, errs, 2)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "mountpoint /var/log required by policy is not present")
	require.Contains(t, errs[1].Description, "mountpoint /tmp required by policy is not present")
}

// 2) Added filesystems, fixup=true: expect no errors and filesystems are added
func TestFilesystems_Additions_Fixup_ResolvesErrors(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Filesystem: []blueprint.FilesystemCustomization{
				{Mountpoint: "/var/log", MinSize: 1000},
				{Mountpoint: "/tmp", MinSize: 2000},
			},
		},
	}
	current := &Customizations{Filesystem: common.ToPtr([]Filesystem{{Mountpoint: "/existing", MinSize: 500}})}

	errs, warns := lintFilesystems(policyBP, nil, current, true)

	require.Empty(t, errs)
	require.Empty(t, warns)
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
}

// 3) Removed filesystems (from snapshot): expect warnings
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

	errs, warns := lintFilesystems(policyBP, snapshot, current, false)
	require.Empty(t, errs)
	require.Len(t, warns, 1)
	require.Equal(t, "Compliance", warns[0].Name)
	require.Contains(t, warns[0].Description, "mountpoint /obsolete is no longer required by policy")
}

// 1) Added kernel name, fixup=false: expect errors
func TestKernel_NameAddition_NoFixup_Errors(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Kernel: &blueprint.KernelCustomization{
				Name: "kernel-rt",
			},
		},
	}
	current := &Customizations{Kernel: &Kernel{Name: common.ToPtr("kernel-standard")}}

	errs, warns := lintKernel(policyBP, nil, current, false)
	require.Len(t, errs, 1)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "kernel name kernel-rt required by policy not set")
}

// 2) Added kernel name, fixup=true: expect no errors and kernel name is set
func TestKernel_NameAddition_Fixup_ResolvesErrors(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Kernel: &blueprint.KernelCustomization{
				Name: "kernel-rt",
			},
		},
	}
	current := &Customizations{Kernel: &Kernel{Name: common.ToPtr("kernel-standard")}}

	errs, warns := lintKernel(policyBP, nil, current, true)
	require.Empty(t, errs)
	require.Empty(t, warns)
	require.NotNil(t, current.Kernel.Name)
	require.Equal(t, "kernel-rt", *current.Kernel.Name)
}

// 3) Added kernel parameters, fixup=false: expect errors
func TestKernel_AppendAddition_NoFixup_Errors(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Kernel: &blueprint.KernelCustomization{
				Append: "audit=1 fips=1",
			},
		},
	}
	current := &Customizations{Kernel: &Kernel{Append: common.ToPtr("quiet splash")}}

	errs, warns := lintKernel(policyBP, nil, current, false)
	require.Len(t, errs, 2)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "kernel command line parameter 'audit=1' required by policy not set")
	require.Contains(t, errs[1].Description, "kernel command line parameter 'fips=1' required by policy not set")
}

// 4) Added kernel parameters, fixup=true: expect no errors and parameters are added
func TestKernel_AppendAddition_Fixup_ResolvesErrors(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			Kernel: &blueprint.KernelCustomization{
				Append: "fips=1",
			},
		},
	}
	current := &Customizations{Kernel: &Kernel{Append: common.ToPtr("quiet splash")}}

	errs, warns := lintKernel(policyBP, nil, current, true)
	require.Empty(t, errs)
	require.Empty(t, warns)
	require.NotNil(t, current.Kernel.Append)
	require.Contains(t, *current.Kernel.Append, "quiet splash")
	require.Contains(t, *current.Kernel.Append, "fips=1")
}

// 5) Removed kernel name (from snapshot): expect warnings
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

	errs, warns := lintKernel(policyBP, snapshot, current, false)
	require.Empty(t, errs)
	require.Len(t, warns, 1)
	require.Equal(t, "Compliance", warns[0].Name)
	require.Contains(t, warns[0].Description, "kernel name kernel-obsolete is no longer required by policy")
}

// 6) Removed kernel parameters (from snapshot): expect warnings
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

	errs, warns := lintKernel(policyBP, snapshot, current, false)
	require.Empty(t, errs)
	require.Len(t, warns, 1)
	require.Equal(t, "Compliance", warns[0].Name)
	require.Contains(t, warns[0].Description, "kernel command line parameter 'obsolete=1' is no longer required by policy")
}

// 1) Added FIPS enabled, fixup=false: expect errors
func TestFIPS_EnabledAddition_NoFixup_Errors(t *testing.T) {
	fipsTrue := true
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			FIPS: &fipsTrue,
		},
	}
	fipsFalse := false
	current := &Customizations{Fips: &FIPS{Enabled: &fipsFalse}}

	errs, warns := lintFIPS(policyBP, nil, current, false)
	require.Len(t, errs, 1)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "FIPS required 'true' by policy but not set")
}

// 2) Added FIPS enabled, fixup=true: expect no errors and FIPS is enabled
func TestFIPS_EnabledAddition_Fixup_ResolvesErrors(t *testing.T) {
	fipsTrue := true
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			FIPS: &fipsTrue,
		},
	}
	fipsFalse := false
	current := &Customizations{Fips: &FIPS{Enabled: &fipsFalse}}

	errs, warns := lintFIPS(policyBP, nil, current, true)
	require.Empty(t, errs)
	require.Empty(t, warns)
	require.NotNil(t, current.Fips)
	require.NotNil(t, current.Fips.Enabled)
	require.True(t, *current.Fips.Enabled)
}

// 3) FIPS not set initially, fixup=true: expect FIPS struct is created and enabled
func TestFIPS_NotSet_Fixup_CreatesAndEnables(t *testing.T) {
	fipsTrue := true
	policyBP := &blueprint.Blueprint{
		Customizations: &blueprint.Customizations{
			FIPS: &fipsTrue,
		},
	}
	current := &Customizations{} // No FIPS field set

	errs, warns := lintFIPS(policyBP, nil, current, true)
	require.Empty(t, errs)
	require.Empty(t, warns)
	require.NotNil(t, current.Fips)
	require.NotNil(t, current.Fips.Enabled)
	require.True(t, *current.Fips.Enabled)
}

// 4) Removed FIPS (from snapshot): expect warnings when no longer required
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

	errs, warns := lintFIPS(policyBP, snapshot, current, false)
	require.Empty(t, errs)
	require.Len(t, warns, 1)
	require.Equal(t, "Compliance", warns[0].Name)
	require.Contains(t, warns[0].Description, "FIPS is no longer required by policy")
}

// 5) FIPS disabled in policy, snapshot had it enabled: expect warnings
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

	errs, warns := lintFIPS(policyBP, snapshot, current, false)
	require.Empty(t, errs)
	require.Len(t, warns, 1)
	require.Equal(t, "Compliance", warns[0].Name)
	require.Contains(t, warns[0].Description, "FIPS is no longer required by policy")
}

// Flow test: initial open shows errors, fixup applies, next open has no errors
func TestPackages_Additions_Flow_ErrorThenFixup_NoError(t *testing.T) {
	policyBP := &blueprint.Blueprint{
		Packages: []blueprint.Package{{Name: "pkg-required-1"}, {Name: "pkg-required-2"}},
	}

	current := &Customizations{Packages: common.ToPtr([]string{"pkg-existing"})}

	// Step 1: open (fixup=false) -> expect errors for missing packages
	errs, warns := lintPackages(policyBP, nil, current, false)
	require.Len(t, errs, 2)
	require.Empty(t, warns)
	require.Equal(t, "Compliance", errs[0].Name)
	require.Contains(t, errs[0].Description, "package pkg-required-1 required by policy is not present")
	require.Contains(t, errs[1].Description, "package pkg-required-2 required by policy is not present")

	// Step 2: user chooses fixup -> apply changes, no errors
	errs, warns = lintPackages(policyBP, nil, current, true)
	require.Empty(t, errs)
	require.Empty(t, warns)
	require.ElementsMatch(t,
		[]string{"pkg-existing", "pkg-required-1", "pkg-required-2"},
		common.FromPtr(current.Packages),
	)

	// Step 3: open again (fixup=false) -> no errors now
	errs, warns = lintPackages(policyBP, nil, current, false)
	require.Empty(t, errs)
	require.Empty(t, warns)
}
