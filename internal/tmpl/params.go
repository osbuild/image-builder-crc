package tmpl

type AAPRegistrationServiceUnitParams any

type AAPRegistrationParams struct {
	HostConfigKey       string
	AnsibleCallbackUrl  string
	SkipTlsVerification bool
}
