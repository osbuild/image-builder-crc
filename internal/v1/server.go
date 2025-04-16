//go:generate go run -mod=mod github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen --config server.cfg.yaml api.yaml
package v1

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/osbuild/image-builder-crc/internal/clients/compliance"
	"github.com/osbuild/image-builder-crc/internal/clients/composer"
	"github.com/osbuild/image-builder-crc/internal/clients/content_sources"
	"github.com/osbuild/image-builder-crc/internal/clients/provisioning"
	"github.com/osbuild/image-builder-crc/internal/clients/recommendations"
	"github.com/osbuild/image-builder-crc/internal/common"
	"github.com/osbuild/image-builder-crc/internal/db"
	"github.com/osbuild/image-builder-crc/internal/distribution"
	"github.com/osbuild/image-builder-crc/internal/prometheus"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/routers"
	legacyrouter "github.com/getkin/kin-openapi/routers/legacy"
	"github.com/labstack/echo/v4"
	fedora_identity "github.com/osbuild/community-gateway/oidc-authorizer/pkg/identity"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redhatinsights/identity"
)

type Server struct {
	echo                *echo.Echo
	cClient             *composer.ComposerClient
	pClient             *provisioning.ProvisioningClient
	csClient            *content_sources.ContentSourcesClient
	csReposURL          *url.URL
	csReposPrefix       string
	rClient             *recommendations.RecommendationsClient
	complianceClient    *compliance.ComplianceClient
	spec                *openapi3.T
	router              routers.Router
	db                  db.DB
	aws                 AWSConfig
	gcp                 GCPConfig
	quotaFile           string
	allowList           common.AllowList
	allDistros          *distribution.AllDistroRegistry
	distributionsDir    string
	fedoraAuth          bool
	insightsClientProxy string
}

type ServerConfig struct {
	EchoServer          *echo.Echo
	CompClient          *composer.ComposerClient
	ProvClient          *provisioning.ProvisioningClient
	CSClient            *content_sources.ContentSourcesClient
	CSReposURL          string
	CSReposPrefix       string
	RecommendClient     *recommendations.RecommendationsClient
	ComplianceClient    *compliance.ComplianceClient
	DBase               db.DB
	AwsConfig           AWSConfig
	GcpConfig           GCPConfig
	QuotaFile           string
	AllowFile           string
	AllDistros          *distribution.AllDistroRegistry
	DistributionsDir    string
	FedoraAuth          bool
	InsightsClientProxy string
}

type AWSConfig struct {
	Region string
}

type GCPConfig struct {
	Region string
	Bucket string
}

type Handlers struct {
	server *Server
}

func Attach(conf *ServerConfig) (*Server, error) {
	spec, err := GetSwagger()
	if err != nil {
		return nil, err
	}

	router, err := legacyrouter.NewRouter(spec)
	if err != nil {
		return nil, err
	}

	majorVersion := strings.Split(spec.Info.Version, ".")[0]

	allowList, err := common.LoadAllowList(conf.AllowFile)
	if err != nil {
		return nil, err
	}

	csReposURL, err := url.Parse(conf.CSReposURL)
	if err != nil {
		return nil, err
	}

	s := Server{
		conf.EchoServer,
		conf.CompClient,
		conf.ProvClient,
		conf.CSClient,
		csReposURL,
		conf.CSReposPrefix,
		conf.RecommendClient,
		conf.ComplianceClient,
		spec,
		router,
		conf.DBase,
		conf.AwsConfig,
		conf.GcpConfig,
		conf.QuotaFile,
		allowList,
		conf.AllDistros,
		conf.DistributionsDir,
		conf.FedoraAuth,
		conf.InsightsClientProxy,
	}
	var h Handlers
	h.server = &s
	s.echo.Binder = binder{}
	s.echo.HTTPErrorHandler = s.HTTPErrorHandler

	middlewaresNoAuth := []echo.MiddlewareFunc{
		prometheus.StatusMiddleware,
	}

	var middlewares []echo.MiddlewareFunc

	if s.fedoraAuth {
		middlewares = append(middlewaresNoAuth, echo.WrapMiddleware(fedora_identity.Extractor))
	} else {
		middlewares = append(middlewaresNoAuth, echo.WrapMiddleware(identity.Extractor), echo.WrapMiddleware(identity.BasePolicy))
	}

	middlewaresNoAuth = append(middlewaresNoAuth, prometheus.PrometheusMW)
	middlewares = append(middlewares, s.noAssociateAccounts, s.ValidateRequest, prometheus.PrometheusMW)

	RegisterHandlers(s.echo.Group(fmt.Sprintf("%s/v%s", RoutePrefix(), majorVersion), middlewares...), &h)
	RegisterHandlers(s.echo.Group(fmt.Sprintf("%s/v%s", RoutePrefix(), spec.Info.Version), middlewares...), &h)

	// noAuth routes have to be registered manually without those validating middleware functions,
	// and they are not generated by oapi-codegen
	s.echo.GET(fmt.Sprintf("%s/v%s/openapi.json", RoutePrefix(), majorVersion), h.GetOpenapiJson, middlewaresNoAuth...)
	s.echo.GET(fmt.Sprintf("%s/v%s/openapi.json", RoutePrefix(), spec.Info.Version), h.GetOpenapiJson, middlewaresNoAuth...)
	s.echo.GET("/openapi.json", h.GetOpenapiJson, middlewaresNoAuth...)

	/* Used for the livenessProbe */
	s.echo.GET("/status", func(c echo.Context) error {
		return h.GetVersion(c)
	})

	/* Used for the readinessProbe */
	h.server.echo.GET("/ready", func(c echo.Context) error {
		return h.GetReadiness(c)
	})

	h.server.echo.GET("/metrics", echo.WrapHandler(promhttp.Handler()))
	return &s, nil
}

func RoutePrefix() string {
	pathPrefix, ok := os.LookupEnv("PATH_PREFIX")
	if !ok {
		pathPrefix = "api"
	}
	appName, ok := os.LookupEnv("APP_NAME")
	if !ok {
		appName = "image-builder"
	}
	return fmt.Sprintf("/%s/%s", pathPrefix, appName)
}

// A simple echo.Binder(), which only accepts application/json, but is more
// strict than echo's DefaultBinder. It does not handle binding query
// parameters either.
type binder struct{}

func (b binder) Bind(i interface{}, ctx echo.Context) error {
	request := ctx.Request()
	if request.ContentLength == 0 {
		return nil
	}

	contentType := request.Header["Content-Type"]
	if len(contentType) != 1 || contentType[0] != "application/json" {
		return echo.NewHTTPError(http.StatusUnsupportedMediaType, "request must be json-encoded")
	}

	err := json.NewDecoder(request.Body).Decode(i)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("cannot parse request body: %v", err))
	}

	return nil
}

func (s *Server) HTTPErrorHandler(err error, c echo.Context) {
	var errors []HTTPError
	he, ok := err.(*echo.HTTPError)
	if ok {
		if he.Internal != nil {
			if herr, ok := he.Internal.(*echo.HTTPError); ok {
				he = herr
			}
		}
	} else {
		he = &echo.HTTPError{
			Code:    http.StatusInternalServerError,
			Message: http.StatusText(http.StatusInternalServerError),
		}
	}

	internalError := he.Code >= http.StatusInternalServerError && he.Code <= http.StatusNetworkAuthenticationRequired
	if internalError {
		c.Logger().Errorf("Internal error %v: %v, %v", he.Code, he.Message, err)
		// TODO deprecate in favour of the status middleware
		if strings.HasSuffix(c.Path(), "/compose") {
			prometheus.ComposeErrors.Inc()
		}
	} else if err != nil {
		c.Logger().Warnf("HTTP error: %s", err)
	}

	errors = append(errors, HTTPError{
		Title:  strconv.Itoa(he.Code),
		Detail: fmt.Sprintf("%v", he.Message),
	})

	// Send response
	if !c.Response().Committed {
		if c.Request().Method == http.MethodHead {
			err = c.NoContent(he.Code)
		} else {
			err = c.JSON(he.Code, &HTTPErrorList{
				errors,
			})
		}
		if err != nil {
			c.Logger().Error(err)
		}
	}
}

func (s *Server) distroRegistry(ctx echo.Context) *distribution.DistroRegistry {
	entitled := false
	id, err := s.getIdentity(ctx)
	if err != nil {
		ctx.Logger().Error("Unable to get entitlement")
	}

	entitled = id.IsEntitled(ctx, "rhel")
	return s.allDistros.Available(entitled)
}

// wraps DistroRegistry.Get and verifies the user has access
func (s *Server) getDistro(ctx echo.Context, distro Distributions) (*distribution.DistributionFile, error) {
	d, err := s.distroRegistry(ctx).Get(string(distro))
	if err == distribution.ErrDistributionNotFound {
		return nil, echo.NewHTTPError(http.StatusBadRequest, err)
	}
	if err != nil {
		return nil, err
	}

	id, err := s.getIdentity(ctx)
	if err != nil {
		return nil, err
	}

	if d.IsRestricted() {
		allowOk, err := s.allowList.IsAllowed(id.OrgID(), d.Distribution.Name)
		if err != nil {
			return nil, echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		if !allowOk {
			message := fmt.Sprintf("This account's organization is not authorized to build %s images", string(d.Distribution.Name))
			return nil, echo.NewHTTPError(http.StatusForbidden, message)
		}
	}
	return d, nil
}
