package v1

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/labstack/echo/v4"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/osbuild/image-builder-crc/internal/clients/content_sources"
	"github.com/osbuild/image-builder-crc/internal/common"
	"github.com/osbuild/image-builder-crc/internal/db"
	"github.com/osbuild/images/pkg/crypt"
)

var (
	blueprintNameRegex         = regexp.MustCompile(`\S+`)
	customizationUserNameRegex = regexp.MustCompile(`\S+`)
	blueprintInvalidNameDetail = "The blueprint name must contain at least two characters."
)

type BlueprintBody struct {
	Customizations Customizations `json:"customizations"`
	Distribution   Distributions  `json:"distribution"`
	ImageRequests  []ImageRequest `json:"image_requests"`
}

type BlueprintBodyOption func(*BlueprintBody)

func (u *User) CryptPassword() error {
	// Prevent empty and already hashed password  from being hashed
	if u.Password == nil || len(*u.Password) == 0 || crypt.PasswordIsCrypted(*u.Password) {
		return nil
	}

	pw, err := crypt.CryptSHA512(*u.Password)
	if err != nil {
		return err
	}
	*u.Password = pw
	return nil
}

// Set password to nil if it is not nil
func (u *User) RedactPassword() {
	if u.Password != nil {
		u.HasPassword = common.ToPtr(true)
	} else {
		u.HasPassword = common.ToPtr(false)
	}
	u.Password = nil
}

func (bb *BlueprintBody) CryptPasswords() error {
	if bb.Customizations.Users != nil {
		for i := range *bb.Customizations.Users {
			err := (*bb.Customizations.Users)[i].CryptPassword()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (bb *BlueprintBody) RedactPasswords() {
	if bb.Customizations.Users != nil {
		for i := range *bb.Customizations.Users {
			(*bb.Customizations.Users)[i].RedactPassword()
		}
	}
}

func (bb *BlueprintBody) RedactCertificates() {
	bb.Customizations.Cacerts = nil
}

func (bb *BlueprintBody) RedactAAPRegistration() {
	if bb.Customizations.AAPRegistration != nil {
		bb.Customizations.AAPRegistration.HostConfigKey = ""
	}
}

// Merges Password or SshKey from other User struct to this User struct if it is not set
func (u *User) MergeExisting(other User) {
	if u.Password == nil {
		u.Password = other.Password
	}
	if u.SshKey == nil {
		u.SshKey = other.SshKey
	}
}

var ErrMissingUserName = errors.New("missing user name")

// User must have name and non-empty password or ssh key
func (u *User) Valid() error {
	if !customizationUserNameRegex.MatchString(u.Name) {
		return ErrMissingUserName
	}
	return nil
}

func (u *User) MergeForUpdate(userData []User) error {
	// If both password and ssh_key in request user we don't need to fetch user from DB
	if !(u.Password != nil && len(*u.Password) > 0 && u.SshKey != nil && len(*u.SshKey) > 0) {
		eui := slices.IndexFunc(userData, func(eu User) bool {
			return eu.Name == u.Name
		})

		if eui == -1 { // User not found in DB
			err := u.Valid()
			if err != nil {
				return err
			}
		} else {
			u.MergeExisting(userData[eui])
		}
	}

	// If there is empty string in password or ssh_key, it means that we should remove it (set to nil)
	if u.Password != nil && *u.Password == "" {
		u.Password = nil
	}
	if u.SshKey != nil && *u.SshKey == "" {
		u.SshKey = nil
	}

	if err := u.Valid(); err != nil {
		return err
	}
	return nil
}

// Helper function to build service snapshots if compliance policy exists
func (h *Handlers) buildServiceSnapshots(ctx echo.Context, customizations *Customizations, distribution Distributions) (*db.ServiceSnapshots, error) {
	if customizations.Openscap == nil {
		return nil, nil
	}

	compl, err := customizations.Openscap.AsOpenSCAPCompliance()
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "error in AsOpenSCAPCompliance", "error", err.Error())
		return nil, err
	}

	var cust Customizations
	cust.Openscap = customizations.Openscap

	_, err = h.lintOpenscap(ctx, &cust, true, distribution)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "error getting policy customizations via lintOpenscap",
			"error", err.Error(), "distribution", distribution, "policy_id", compl.PolicyId.String())
		return nil, err
	}

	policyCustomizationsJSON, err := json.Marshal(cust)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "error marshaling policy customizations to JSON",
			"error", err.Error(), "policy_id", compl.PolicyId.String())
		return nil, err
	}

	serviceSnapshots := &db.ServiceSnapshots{
		Compliance: &db.ComplianceSnapshot{
			PolicyId:             compl.PolicyId,
			PolicyCustomizations: policyCustomizationsJSON,
		},
	}

	slog.DebugContext(ctx.Request().Context(), "built compliance snapshot",
		"policy_id", compl.PolicyId,
		"distribution", distribution)

	return serviceSnapshots, nil
}

// Util function used to create and update Blueprint from API request (WRITE)
func BlueprintFromAPI(cbr CreateBlueprintRequest) (BlueprintBody, error) {
	bb := BlueprintBody{
		Customizations: cbr.Customizations,
		Distribution:   cbr.Distribution,
		ImageRequests:  cbr.ImageRequests,
	}
	err := bb.CryptPasswords()
	if err != nil {
		return BlueprintBody{}, err
	}
	return bb, nil
}

// Util function used to create Blueprint sctruct from DB entry (READ)
func BlueprintFromEntry(be *db.BlueprintEntry, options ...BlueprintBodyOption) (BlueprintBody, error) {
	var result BlueprintBody
	err := json.Unmarshal(be.Body, &result)
	if err != nil {
		return BlueprintBody{}, err
	}

	for _, option := range options {
		option(&result)
	}

	return result, nil
}

func WithRedactedPasswords() BlueprintBodyOption {
	return func(bp *BlueprintBody) {
		bp.RedactPasswords()
	}
}

func WithRedactedCertificates() BlueprintBodyOption {
	return func(bp *BlueprintBody) {
		bp.RedactCertificates()
	}
}

func WithRedactedAAPRegistration() BlueprintBodyOption {
	return func(bp *BlueprintBody) {
		bp.RedactAAPRegistration()
	}
}

func WithRedactedFiles(paths []string) BlueprintBodyOption {
	return func(bp *BlueprintBody) {
		if bp.Customizations.Files != nil {
			files := slices.DeleteFunc(*bp.Customizations.Files, func(file File) bool {
				return slices.Contains(paths, file.Path)
			})
			if len(files) == 0 {
				bp.Customizations.Files = nil
			} else {
				bp.Customizations.Files = &files
			}
		}
	}
}

func (h *Handlers) CreateBlueprint(ctx echo.Context) error {
	userID, err := h.server.getIdentity(ctx)
	if err != nil {
		return err
	}

	var blueprintRequest CreateBlueprintRequest
	err = ctx.Bind(&blueprintRequest)
	if err != nil {
		return err
	}

	var metadata []byte
	if blueprintRequest.Metadata != nil {
		metadata, err = json.Marshal(blueprintRequest.Metadata)
		if err != nil {
			return err
		}
	}

	if !blueprintNameRegex.MatchString(blueprintRequest.Name) {
		return ctx.JSON(http.StatusUnprocessableEntity, HTTPErrorList{
			Errors: []HTTPError{{
				Title:  "Invalid blueprint name",
				Detail: blueprintInvalidNameDetail,
			}},
		})
	}

	id := uuid.New()
	versionId := uuid.New()
	slog.DebugContext(ctx.Request().Context(), "inserting blueprint",
		"name", blueprintRequest.Name,
		"id", id,
		"org_id", userID.OrgID(),
		"account", userID.AccountNumber())

	desc := ""
	if blueprintRequest.Description != nil {
		desc = *blueprintRequest.Description
	}

	users := blueprintRequest.Customizations.Users
	if users != nil {
		for _, user := range *users {
			// Make sure every user has either ssh key or password set
			if err := user.Valid(); err != nil {
				return ctx.JSON(http.StatusUnprocessableEntity, HTTPErrorList{
					Errors: []HTTPError{{
						Title:  "Invalid user",
						Detail: err.Error(),
					}},
				})
			}
		}
	}

	blueprint, err := BlueprintFromAPI(blueprintRequest)
	if err != nil {
		return err
	}

	body, err := json.Marshal(blueprint)
	if err != nil {
		return err
	}

	serviceSnapshots, err := h.buildServiceSnapshots(ctx, &blueprintRequest.Customizations, blueprintRequest.Distribution)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "error building service snapshots",
			"blueprint_id", id,
			"error", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to build compliance snapshots")
	}

	var serviceSnapshotsJSON json.RawMessage
	if serviceSnapshots != nil {
		serviceSnapshotsJSON, err = json.Marshal(serviceSnapshots)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to marshal service snapshots")
		}
	}

	err = h.server.db.InsertBlueprint(ctx.Request().Context(), id, versionId, userID.OrgID(), userID.AccountNumber(), blueprintRequest.Name, desc, body, metadata, serviceSnapshotsJSON)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "error inserting blueprint with service snapshots into db",
			"error", err.Error())

		var e *pgconn.PgError
		if errors.As(err, &e) && e.Code == pgerrcode.UniqueViolation {
			return ctx.JSON(http.StatusUnprocessableEntity, HTTPErrorList{
				Errors: []HTTPError{{
					Title:  "Name not unique",
					Detail: "A blueprint with the same name already exists.",
				}},
			})
		}
		return err
	}
	return ctx.JSON(http.StatusCreated, ComposeResponse{
		Id: id,
	})
}

func (h *Handlers) GetBlueprint(ctx echo.Context, id openapi_types.UUID, params GetBlueprintParams) error {
	userID, err := h.server.getIdentity(ctx)
	if err != nil {
		return err
	}
	slog.DebugContext(ctx.Request().Context(), "fetching blueprint", "id", id)
	if params.Version != nil && *params.Version <= 0 {
		if *params.Version != -1 {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid version number")
		}
		params.Version = nil
	}

	blueprintEntry, err := h.server.db.GetBlueprint(ctx.Request().Context(), id, userID.OrgID(), params.Version)
	if err != nil {
		if errors.Is(err, db.ErrBlueprintNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err)
		}
		return err
	}

	blueprint, err := BlueprintFromEntry(
		blueprintEntry,
		WithRedactedPasswords(),
	)
	if err != nil {
		return err
	}

	lintErrors, err := h.lintBlueprint(ctx, &blueprint, false)
	if err != nil {
		return err
	}

	blueprintResponse := BlueprintResponse{
		Id:             id,
		Name:           blueprintEntry.Name,
		Description:    blueprintEntry.Description,
		ImageRequests:  blueprint.ImageRequests,
		Distribution:   blueprint.Distribution,
		Customizations: blueprint.Customizations,
		Lint: BlueprintLint{
			Errors: lintErrors,
		},
	}

	return ctx.JSON(http.StatusOK, blueprintResponse)
}

func (h *Handlers) lintBlueprint(ctx echo.Context, blueprint *BlueprintBody, fixup bool) ([]BlueprintLintItem, error) {
	lintErrors := []BlueprintLintItem{}

	if errors, err := h.lintOpenscap(ctx, &blueprint.Customizations, fixup, blueprint.Distribution); err != nil {
		return nil, err
	} else {
		lintErrors = append(lintErrors, errors...)
	}
	return lintErrors, nil
}

func (h *Handlers) ExportBlueprint(ctx echo.Context, id openapi_types.UUID) error {
	userID, err := h.server.getIdentity(ctx)
	if err != nil {
		return err
	}
	blueprintEntry, err := h.server.db.GetBlueprint(ctx.Request().Context(), id, userID.OrgID(), nil)
	if err != nil {
		if errors.Is(err, db.ErrBlueprintNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err)
		}
		return err
	}

	// Preventing users from exporting their tokens for Satellite registration, their certificates or passwords
	blueprint, err := BlueprintFromEntry(
		blueprintEntry,
		WithRedactedPasswords(),
		WithRedactedCertificates(),
		WithRedactedAAPRegistration(),
		WithRedactedFiles([]string{
			"/etc/systemd/system/register-satellite.service",
			"/usr/local/sbin/register-satellite",
			"/usr/local/sbin/aap-first-boot-reg",
		}),
	)
	if err != nil {
		return err
	}

	blueprint.Customizations.Subscription = nil
	blueprintExportResponse := BlueprintExportResponse{
		Name:           blueprintEntry.Name,
		Description:    blueprintEntry.Description,
		Distribution:   blueprint.Distribution,
		Customizations: blueprint.Customizations,
		Metadata: BlueprintMetadata{
			ExportedAt: time.Now().UTC().String(),
			ParentId:   &id,
		},
	}

	if len(blueprint.ImageRequests) != 0 {
		blueprintExportResponse.SnapshotDate = blueprint.ImageRequests[0].SnapshotDate
	}

	repoUUIDs := []string{}
	if blueprint.Customizations.CustomRepositories != nil {
		for _, repo := range *blueprint.Customizations.CustomRepositories {
			repoUUIDs = append(repoUUIDs, repo.Id)
		}
	}

	exportedRepositoriesResp, err := h.server.csClient.BulkExportRepositories(ctx.Request().Context(), content_sources.ApiRepositoryExportRequest{
		RepositoryUuids: repoUUIDs,
	})
	if err != nil {
		return err
	}
	defer closeBody(ctx, exportedRepositoriesResp.Body)

	if exportedRepositoriesResp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("unable to fetch custom repositories, got %v response", exportedRepositoriesResp.StatusCode)
	}

	if exportedRepositoriesResp.Body == nil {
		slog.WarnContext(ctx.Request().Context(), "unable to export custom repositories, empty body")
		return ctx.JSON(http.StatusOK, blueprintExportResponse)
	}

	bodyBytes, err := io.ReadAll(exportedRepositoriesResp.Body)
	if err != nil {
		return err
	}

	if len(bodyBytes) != 0 {
		// Saving the custom repositories in the object format
		var result []map[string]interface{}
		err = json.Unmarshal(bodyBytes, &result)
		if err != nil {
			return fmt.Errorf("unable to export custom repositories: %w, %s", err, string(bodyBytes))
		}
		blueprintExportResponse.ContentSources = &result
	}

	return ctx.JSON(http.StatusOK, blueprintExportResponse)
}

func (h *Handlers) UpdateBlueprint(ctx echo.Context, blueprintId uuid.UUID) error {
	userID, err := h.server.getIdentity(ctx)
	if err != nil {
		return err
	}

	var blueprintRequest CreateBlueprintRequest
	err = ctx.Bind(&blueprintRequest)
	if err != nil {
		return err
	}

	if !blueprintNameRegex.MatchString(blueprintRequest.Name) {
		return ctx.JSON(http.StatusUnprocessableEntity, HTTPErrorList{
			Errors: []HTTPError{{
				Title:  "Invalid blueprint name",
				Detail: blueprintInvalidNameDetail,
			}},
		})
	}

	if blueprintRequest.Customizations.Users != nil {
		be, err := h.server.db.GetBlueprint(ctx.Request().Context(), blueprintId, userID.OrgID(), nil)
		if err != nil {
			if errors.Is(err, db.ErrBlueprintNotFound) {
				return echo.NewHTTPError(http.StatusNotFound, err)
			}
			return err
		}
		eb, err := BlueprintFromEntry(be)
		if err != nil {
			return err
		}

		if eb.Customizations.Users != nil {
			for i := range *blueprintRequest.Customizations.Users {
				err := (*blueprintRequest.Customizations.Users)[i].MergeForUpdate(*eb.Customizations.Users)
				if err != nil {
					return ctx.JSON(http.StatusUnprocessableEntity, HTTPErrorList{
						Errors: []HTTPError{{
							Title:  "Invalid user",
							Detail: err.Error(),
						}},
					})
				}
			}
		}
	}

	blueprint, err := BlueprintFromAPI(blueprintRequest)
	if err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, HTTPErrorList{
			Errors: []HTTPError{{
				Title:  "Invalid blueprint",
				Detail: err.Error(),
			}},
		})
	}

	body, err := json.Marshal(blueprint)
	if err != nil {
		return err
	}

	versionId := uuid.New()
	desc := ""
	if blueprintRequest.Description != nil {
		desc = *blueprintRequest.Description
	}

	serviceSnapshots, err := h.buildServiceSnapshots(ctx, &blueprintRequest.Customizations, blueprintRequest.Distribution)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "error building service snapshots",
			"blueprint_id", blueprintId,
			"error", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to build compliance snapshots")
	}

	var serviceSnapshotsJSON json.RawMessage
	if serviceSnapshots != nil {
		serviceSnapshotsJSON, err = json.Marshal(serviceSnapshots)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to marshal service snapshots")
		}
	}

	err = h.server.db.UpdateBlueprint(ctx.Request().Context(), versionId, blueprintId, userID.OrgID(), blueprintRequest.Name, desc, body, serviceSnapshotsJSON)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "error updating blueprint with service snapshots in db",
			"error", err)
		if errors.Is(err, db.ErrBlueprintNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err)
		}
		return err
	}
	return ctx.JSON(http.StatusCreated, ComposeResponse{
		Id: blueprintId,
	})
}

func (h *Handlers) ComposeBlueprint(ctx echo.Context, id openapi_types.UUID) error {
	var requestBody ComposeBlueprintJSONBody
	err := ctx.Bind(&requestBody)
	if err != nil {
		return err
	}

	userID, err := h.server.getIdentity(ctx)
	if err != nil {
		return err
	}

	blueprintEntry, err := h.server.db.GetBlueprint(ctx.Request().Context(), id, userID.OrgID(), nil)
	if err != nil {
		if errors.Is(err, db.ErrBlueprintNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err)
		}
		return err
	}
	blueprint, err := BlueprintFromEntry(
		blueprintEntry,
	)
	if err != nil {
		return err
	}
	composeResponses := make([]ComposeResponse, 0, len(blueprint.ImageRequests))
	clientId := ClientId("api")
	if ctx.Request().Header.Get("X-ImageBuilder-ui") == "mcp" {
		clientId = "mcp"
	} else if ctx.Request().Header.Get("X-ImageBuilder-ui") != "" {
		clientId = "ui"
	}
	for _, imageRequest := range blueprint.ImageRequests {
		if requestBody.ImageTypes != nil && !slices.Contains(*requestBody.ImageTypes, imageRequest.ImageType) {
			continue
		}
		composeRequest := ComposeRequest{
			Customizations:   &blueprint.Customizations,
			Distribution:     blueprint.Distribution,
			ImageRequests:    []ImageRequest{imageRequest},
			ImageName:        &blueprintEntry.Name,
			ImageDescription: &blueprintEntry.Description,
			ClientId:         &clientId,
		}
		composesResponse, err := h.handleCommonCompose(ctx, composeRequest, &blueprintEntry.VersionId)
		if err != nil {
			return err
		}
		composeResponses = append(composeResponses, composesResponse)
	}

	return ctx.JSON(http.StatusCreated, composeResponses)
}

func (h *Handlers) GetBlueprints(ctx echo.Context, params GetBlueprintsParams) error {
	userID, err := h.server.getIdentity(ctx)
	if err != nil {
		return err
	}

	limit := 100
	if params.Limit != nil && *params.Limit > 0 {
		limit = *params.Limit
	}

	offset := 0
	if params.Offset != nil {
		offset = *params.Offset
	}
	var blueprints []db.BlueprintWithNoBody
	var count int

	urlParams := url.Values{}
	if params.Name != nil && common.FromPtr(params.Name) != "" {
		urlParams.Add("name", *params.Name)
		blueprint, err := h.server.db.FindBlueprintByName(ctx.Request().Context(), userID.OrgID(), *params.Name)
		if err != nil {
			return err
		}
		if blueprint != nil {
			blueprints = []db.BlueprintWithNoBody{*blueprint}
			count = 1
		}
		// Else no blueprint found - return empty list and count = 0
	} else if params.Search != nil && common.FromPtr(params.Search) != "" {
		urlParams.Add("search", *params.Search)
		blueprints, count, err = h.server.db.FindBlueprints(ctx.Request().Context(), userID.OrgID(), *params.Search, limit, offset)
		if err != nil {
			return err
		}
	} else {
		blueprints, count, err = h.server.db.GetBlueprints(ctx.Request().Context(), userID.OrgID(), limit, offset)
		if err != nil {
			return err
		}
	}

	ctx.Logger().Debugf("Getting blueprint list of %d items", count)

	data := make([]BlueprintItem, 0, len(blueprints))
	for _, blueprint := range blueprints {
		data = append(data, BlueprintItem{
			Id:             blueprint.Id,
			Name:           blueprint.Name,
			Description:    blueprint.Description,
			Version:        blueprint.Version,
			LastModifiedAt: blueprint.LastModifiedAt.Format(time.RFC3339),
		})
	}

	return ctx.JSON(http.StatusOK, BlueprintsResponse{
		Meta:  ListResponseMeta{count},
		Links: h.newLinksWithExtraParams("blueprints", count, limit, urlParams),
		Data:  data,
	})
}

func (h *Handlers) GetBlueprintComposes(ctx echo.Context, blueprintId openapi_types.UUID, params GetBlueprintComposesParams) error {
	userID, err := h.server.getIdentity(ctx)
	if err != nil {
		return err
	}

	limit := 100
	if params.Limit != nil {
		if *params.Limit > 0 {
			limit = *params.Limit
		}
	}

	offset := 0
	if params.Offset != nil {
		offset = *params.Offset
	}
	ignoreImageTypeStrings := convertIgnoreImageTypeToSlice(params.IgnoreImageTypes)

	since := time.Hour * 24 * 14

	if params.BlueprintVersion != nil && *params.BlueprintVersion < 0 {
		*params.BlueprintVersion, err = h.server.db.GetLatestBlueprintVersionNumber(ctx.Request().Context(), userID.OrgID(), blueprintId)
		if err != nil {
			return err
		}
	}

	composes, err := h.server.db.GetBlueprintComposes(ctx.Request().Context(), userID.OrgID(), blueprintId, params.BlueprintVersion, since, limit, offset, ignoreImageTypeStrings)
	if err != nil {
		if errors.Is(err, db.ErrBlueprintNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err)
		}
		return err
	}
	count, err := h.server.db.CountBlueprintComposesSince(ctx.Request().Context(), userID.OrgID(), blueprintId, params.BlueprintVersion, since, ignoreImageTypeStrings)
	if err != nil {
		return err
	}

	data := make([]ComposesResponseItem, 0, len(composes))
	for _, c := range composes {
		bId := c.BlueprintId
		version := c.BlueprintVersion
		var cmpr ComposeRequest
		err = json.Unmarshal(c.Request, &cmpr)
		if err != nil {
			return err
		}
		data = append(data, ComposesResponseItem{
			BlueprintId:      &bId,
			BlueprintVersion: &version,
			CreatedAt:        c.CreatedAt.Format(time.RFC3339),
			Id:               c.Id,
			ImageName:        c.ImageName,
			Request:          cmpr,
			ClientId:         (*ClientId)(c.ClientId),
		})
	}

	linkParams := url.Values{}
	linkParams.Add("blueprint_id", blueprintId.String())
	if params.BlueprintVersion != nil {
		linkParams.Add("blueprint_version", strconv.Itoa(*params.BlueprintVersion))
	}
	return ctx.JSON(http.StatusOK, ComposesResponse{
		Data:  data,
		Meta:  ListResponseMeta{count},
		Links: h.newLinksWithExtraParams("composes", count, limit, linkParams),
	})
}

func (h *Handlers) DeleteBlueprint(ctx echo.Context, blueprintId openapi_types.UUID) error {
	userID, err := h.server.getIdentity(ctx)
	if err != nil {
		return err
	}

	err = h.server.db.DeleteBlueprint(ctx.Request().Context(), blueprintId, userID.OrgID())
	if err != nil {
		if errors.Is(err, db.ErrBlueprintNotFound) {
			return echo.NewHTTPError(http.StatusNotFound)
		}
		return err
	}
	return ctx.NoContent(http.StatusNoContent)
}

func (h *Handlers) FixupBlueprint(ctx echo.Context, id openapi_types.UUID) error {
	userID, err := h.server.getIdentity(ctx)
	if err != nil {
		return err
	}

	blueprintEntry, err := h.server.db.GetBlueprint(ctx.Request().Context(), id, userID.OrgID(), nil)
	if err != nil {
		if errors.Is(err, db.ErrBlueprintNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err)
		}
		return err
	}

	blueprint, err := BlueprintFromEntry(
		blueprintEntry,
		WithRedactedPasswords(),
	)
	if err != nil {
		return err
	}

	_, err = h.lintBlueprint(ctx, &blueprint, true)
	if err != nil {
		return err
	}

	var md BlueprintMetadata
	if len(blueprintEntry.Metadata) > 0 {
		err = json.Unmarshal(blueprintEntry.Metadata, &md)
		if err != nil {
			return err
		}
	}

	blueprintRequest := CreateBlueprintRequest{
		Name:           blueprintEntry.Name,
		Description:    &blueprintEntry.Description,
		Metadata:       &md,
		Distribution:   blueprint.Distribution,
		ImageRequests:  blueprint.ImageRequests,
		Customizations: blueprint.Customizations,
	}

	body, err := json.Marshal(blueprintRequest)
	if err != nil {
		return err
	}
	desc := common.FromPtr(blueprintRequest.Description)
	slog.DebugContext(ctx.Request().Context(), "starting buildServiceSnapshots during fixup",
		"blueprint_id", blueprintEntry.Id,
		"distribution", blueprintRequest.Distribution,
		"has_openscap", blueprintRequest.Customizations.Openscap != nil)

	serviceSnapshots, err := h.buildServiceSnapshots(ctx, &blueprintRequest.Customizations, blueprintRequest.Distribution)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "error building service snapshots during fixup",
			"blueprint_id", blueprintEntry.Id,
			"error", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to build compliance snapshots during fixup")
	}

	var serviceSnapshotsJSON json.RawMessage
	if serviceSnapshots != nil {
		serviceSnapshotsJSON, err = json.Marshal(serviceSnapshots)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to marshal service snapshots")
		}
	}

	versionId := uuid.New()
	err = h.server.db.UpdateBlueprint(ctx.Request().Context(), versionId, blueprintEntry.Id, userID.OrgID(), blueprintRequest.Name, desc, body, serviceSnapshotsJSON)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "error updating blueprint in db during fixup",
			"error", err)
		if errors.Is(err, db.ErrBlueprintNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err)
		}
		return err
	}

	return ctx.NoContent(http.StatusCreated)
}
