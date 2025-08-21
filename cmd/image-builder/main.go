package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	sentryecho "github.com/getsentry/sentry-go/echo"
	"github.com/labstack/echo/v4"
	fedora_identity "github.com/osbuild/community-gateway/oidc-authorizer/pkg/identity"
	"github.com/osbuild/image-builder-crc/internal/clients/compliance"
	"github.com/osbuild/image-builder-crc/internal/clients/composer"
	"github.com/osbuild/image-builder-crc/internal/clients/content_sources"
	"github.com/osbuild/image-builder-crc/internal/clients/provisioning"
	"github.com/osbuild/image-builder-crc/internal/clients/recommendations"
	"github.com/osbuild/image-builder-crc/internal/config"
	"github.com/osbuild/image-builder-crc/internal/db"
	"github.com/osbuild/image-builder-crc/internal/distribution"
	"github.com/osbuild/image-builder-crc/internal/oauth2"
	"github.com/osbuild/image-builder-crc/internal/unleash"
	v1 "github.com/osbuild/image-builder-crc/internal/v1"
	echoproxy "github.com/osbuild/logging/pkg/echo"
	"github.com/osbuild/logging/pkg/sinit"
	"github.com/redhatinsights/identity"
)

func main() {
	conf := config.ImageBuilderConfig{
		ListenAddress: "localhost:8086",
		LogLevel:      "INFO",
		PGHost:        "localhost",
		PGPort:        "5432",
		PGDatabase:    "imagebuilder",
		PGUser:        "postgres",
		PGPassword:    "foobar",
		PGSSLMode:     "prefer",
	}

	ctx := context.Background()

	err := config.LoadConfigFromEnv(&conf)
	if err != nil {
		panic(err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "image-builder-unknown"
	}

	loggingConfig := sinit.LoggingConfig{
		StdoutConfig: sinit.StdoutConfig{
			Enabled: true,
			Level:   conf.LogLevel,
			Format:  "text",
		},
		SplunkConfig: sinit.SplunkConfig{
			Enabled:  conf.SplunkHost != "" && conf.SplunkPort != "" && conf.SplunkToken != "",
			Level:    conf.LogLevel,
			URL:      fmt.Sprintf("https://%s:%s/services/collector/event", conf.SplunkHost, conf.SplunkPort),
			Token:    conf.SplunkToken,
			Source:   "image-builder",
			Hostname: hostname,
		},
		CloudWatchConfig: sinit.CloudWatchConfig{
			Enabled:      conf.CwAccessKeyID != "" && conf.CwSecretAccessKey != "" && conf.CwRegion != "",
			Level:        conf.LogLevel,
			AWSRegion:    conf.CwRegion,
			AWSSecret:    conf.CwSecretAccessKey,
			AWSKey:       conf.CwAccessKeyID,
			AWSLogGroup:  conf.LogGroup,
			AWSLogStream: hostname,
		},
		SentryConfig: sinit.SentryConfig{
			Enabled: conf.GlitchTipDSN != "",
			DSN:     conf.GlitchTipDSN,
		},
		TracingConfig: sinit.TracingConfig{
			Enabled: true,
			ContextCallback: func(ctx context.Context, attrs []slog.Attr) ([]slog.Attr, error) {
				if conf.FedoraAuth {
					val := ctx.Value(fedora_identity.IDHeaderKey)
					if val == nil {
						return attrs, nil
					}
					id, ok := val.(*fedora_identity.Identity)
					if !ok {
						return attrs, nil
					}

					if id.User != "" {
						attrs = append(attrs, slog.String("user", id.User))
					}
				} else {
					id, ok := identity.Get(ctx)
					if !ok {
						return attrs, nil
					}

					if id.Identity.OrgID != "" {
						attrs = append(attrs, slog.String("org_id", id.Identity.OrgID))
					}
					if id.Identity.User.Username != "" {
						attrs = append(attrs, slog.String("user", id.Identity.User.Username))
					}
				}

				return attrs, nil
			},
		},
	}

	err = sinit.InitializeLogging(ctx, loggingConfig)
	if err != nil {
		panic(err)
	}
	defer sinit.Flush()

	slog.Info("starting image-builder",
		"splunk", loggingConfig.SplunkConfig.Enabled,
		"cloudwatch", loggingConfig.CloudWatchConfig.Enabled,
		"sentry", loggingConfig.SentryConfig.Enabled,
	)

	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", conf.PGUser, conf.PGPassword, conf.PGHost, conf.PGPort, conf.PGDatabase, conf.PGSSLMode)
	dbase, err := db.InitDBConnectionPool(ctx, connStr)
	if err != nil {
		panic(err)
	}

	composerConf := composer.ComposerClientConfig{
		URL: conf.ComposerURL,
		CA:  conf.ComposerCA,
		Tokener: &oauth2.LazyToken{
			Url:          conf.ComposerTokenURL,
			ClientId:     conf.ComposerClientId,
			ClientSecret: conf.ComposerClientSecret,
		},
	}

	recommendationConf := recommendations.RecommendationsClientConfig{
		URL:   conf.RecommendURL,
		CA:    conf.RecommendCA,
		Proxy: conf.RecommendProxy,
		Tokener: &oauth2.LazyToken{
			Url:          conf.RecommendTokenURL,
			ClientId:     conf.RecommendClientId,
			ClientSecret: conf.RecommendSecret,
		},
	}
	compClient, err := composer.NewClient(composerConf)
	if err != nil {
		panic(err)
	}
	provClient, err := provisioning.NewClient(provisioning.ProvisioningClientConfig{
		URL: conf.ProvisioningURL,
	})
	if err != nil {
		panic(err)
	}

	csClient, err := content_sources.NewClient(content_sources.ContentSourcesClientConfig{
		URL: conf.ContentSourcesURL,
	})
	if err != nil {
		panic(err)
	}

	recommendClient, err := recommendations.NewClient(recommendationConf)
	if err != nil {
		panic(err)
	}

	complianceClient := compliance.NewClient(compliance.ComplianceClientConfig{
		URL: conf.ComplianceURL,
	})

	adr, err := distribution.LoadDistroRegistry(conf.DistributionsDir)
	if err != nil {
		panic(err)
	}

	if len(adr.Available(true).List()) == 0 {
		panic("no distributions defined")
	}

	if conf.UnleashURL != "" {
		err = unleash.Initialize(unleash.Config{
			URL:   conf.UnleashURL,
			Token: conf.UnleashToken,
		})
		if err != nil {
			panic(err)
		}
	}

	// middleware is defined in v1.Attach
	echoServer := echo.New()
	echoServer.HideBanner = true
	echoServer.Logger = echoproxy.NewProxyFor(slog.Default())

	if conf.GlitchTipDSN != "" {
		echoServer.Use(sentryecho.New(sentryecho.Options{}))
	}

	if conf.IsDebug() {
		echoServer.Debug = true
	}

	serverConfig := &v1.ServerConfig{
		EchoServer:       echoServer,
		CompClient:       compClient,
		ProvClient:       provClient,
		RecommendClient:  recommendClient,
		ComplianceClient: complianceClient,
		CSClient:         csClient,
		CSReposURL:       conf.ContentSourcesRepoURL,
		CSReposPrefix:    conf.ContentSourcesRepoPrefix,
		DBase:            dbase,

		AwsConfig: v1.AWSConfig{
			Region: conf.OsbuildRegion,
		},
		GcpConfig: v1.GCPConfig{
			Region: conf.OsbuildGCPRegion,
			Bucket: conf.OsbuildGCPBucket,
		},
		QuotaFile:           conf.QuotaFile,
		AllowFile:           conf.AllowFile,
		AllDistros:          adr,
		DistributionsDir:    conf.DistributionsDir,
		FedoraAuth:          conf.FedoraAuth,
		InsightsClientProxy: conf.InsightsClientProxy,
		PatchURL:            conf.PatchURL,
	}

	_, err = v1.Attach(serverConfig)
	if err != nil {
		panic(err)
	}

	slog.Info("🚀 starting image-builder server", "listen", conf.ListenAddress)
	err = echoServer.Start(conf.ListenAddress)
	if err != nil {
		panic(err)
	}
}
