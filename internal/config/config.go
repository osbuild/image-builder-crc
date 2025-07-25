package config

import "strings"

// Do not write this config to logs or stdout, it contains secrets!
type ImageBuilderConfig struct {
	ListenAddress            string `env:"LISTEN_ADDRESS"`
	LogLevel                 string `env:"LOG_LEVEL"`
	LogGroup                 string `env:"CW_LOG_GROUP"`
	CwRegion                 string `env:"CW_AWS_REGION"`
	CwAccessKeyID            string `env:"CW_AWS_ACCESS_KEY_ID"`
	CwSecretAccessKey        string `env:"CW_AWS_SECRET_ACCESS_KEY"`
	ComposerURL              string `env:"COMPOSER_URL"`
	ComposerTokenURL         string `env:"COMPOSER_TOKEN_URL"`
	ComposerClientId         string `env:"COMPOSER_CLIENT_ID"`
	ComposerClientSecret     string `env:"COMPOSER_CLIENT_SECRET"`
	ComposerCA               string `env:"COMPOSER_CA_PATH"`
	OsbuildRegion            string `env:"OSBUILD_AWS_REGION"`
	OsbuildGCPRegion         string `env:"OSBUILD_GCP_REGION"`
	OsbuildGCPBucket         string `env:"OSBUILD_GCP_BUCKET"`
	DistributionsDir         string `env:"DISTRIBUTIONS_DIR"`
	MigrationsDir            string `env:"MIGRATIONS_DIR"`
	TernExecutable           string `env:"TERN_EXECUTABLE"`
	TernMigrationsDir        string `env:"TERN_MIGRATIONS_DIR"`
	PGHost                   string `env:"PGHOST"`
	PGPort                   string `env:"PGPORT"`
	PGDatabase               string `env:"PGDATABASE"`
	PGUser                   string `env:"PGUSER"`
	PGPassword               string `env:"PGPASSWORD"`
	PGSSLMode                string `env:"PGSSLMODE"`
	QuotaFile                string `env:"QUOTA_FILE"`
	AllowFile                string `env:"ALLOW_FILE"`
	SplunkHost               string `env:"SPLUNK_HEC_HOST"`
	SplunkPort               string `env:"SPLUNK_HEC_PORT"`
	SplunkToken              string `env:"SPLUNK_HEC_TOKEN"`
	ProvisioningURL          string `env:"PROVISIONING_URL"`
	ContentSourcesURL        string `env:"CONTENT_SOURCES_URL"`
	ContentSourcesRepoURL    string `env:"CONTENT_SOURCES_REPO_URL"`
	ContentSourcesRepoPrefix string `env:"CONTENT_SOURCES_REPO_PREFIX"`
	RecommendURL             string `env:"RECOMMENDATIONS_URL"`
	RecommendTokenURL        string `env:"RECOMMENDATIONS_TOKEN_URL"`
	RecommendClientId        string `env:"RECOMMENDATIONS_CLIENT_ID"`
	RecommendSecret          string `env:"RECOMMENDATIONS_CLIENT_SECRET"`
	RecommendProxy           string `env:"RECOMMENDATIONS_PROXY"`
	RecommendCA              string `env:"RECOMMENDATIONS_CA_PATH"`
	ComplianceURL            string `env:"COMPLIANCE_URL"`
	GlitchTipDSN             string `env:"GLITCHTIP_DSN"`
	FedoraAuth               bool   `env:"FEDORA_AUTH"`
	DeploymentChannel        string `env:"CHANNEL"`
	UnleashURL               string `env:"UNLEASH_URL"`
	UnleashToken             string `env:"UNLEASH_TOKEN"`
	InsightsClientProxy      string `env:"INSIGHTS_CLIENT_PROXY"`
	PatchURL                 string `env:"PATCH_URL"`
}

func (ibc *ImageBuilderConfig) IsDebug() bool {
	level := strings.ToUpper(ibc.LogLevel)
	return level == "TRACE" || level == "DEBUG"
}
