package v1

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/osbuild/image-builder-crc/internal/common"
)

func (h *Handlers) GetSourceList(ctx echo.Context, params GetSourceListParams) error {
	provider := ""
	if params.Provider != nil {
		provider = string(*params.Provider)
	}

	sourcesList, total, err := h.server.sourcesClient.ListProvisioningSources(ctx.Request().Context(), provider)
	if err != nil {
		ctx.Logger().Errorf("Error listing sources: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Unable to list sources")
	}

	data := make([]SourceResponse, len(sourcesList))
	for i, s := range sourcesList {
		data[i] = SourceResponse{
			Id:       common.ToPtr(s.ID),
			Name:     common.ToPtr(s.Name),
			Provider: common.ToPtr(s.Provider),
			Status:   common.ToPtr(s.Status),
			Uid:      common.ToPtr(s.UID),
		}
	}

	return ctx.JSON(http.StatusOK, SourceListResponse{
		Data: &data,
		Metadata: &struct {
			Links *struct {
				Next     *string `json:"next,omitempty"`
				Previous *string `json:"previous,omitempty"`
			} `json:"links,omitempty"`
			Total *int `json:"total,omitempty"`
		}{
			Total: &total,
		},
	})
}

func (h *Handlers) GetSourceUploadInfo(ctx echo.Context, id string) error {
	auth, err := h.server.sourcesClient.GetAuthentication(ctx.Request().Context(), id)
	if err != nil {
		ctx.Logger().Errorf("Error getting authentication for source %s: %v", id, err)
		return echo.NewHTTPError(http.StatusBadRequest, "Unable to get authentication for source")
	}

	response := SourceUploadInfoResponse{
		Provider: common.ToPtr(auth.ProviderType),
	}

	switch auth.ProviderType {
	case "aws":
		accountID, err := h.server.sourcesClient.ResolveSourceToAWSAccountID(ctx.Request().Context(), id)
		if err != nil {
			ctx.Logger().Errorf("Error resolving AWS account for source %s: %v", id, err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Unable to resolve AWS account ID")
		}
		response.Aws = &struct {
			AccountId *string `json:"account_id,omitempty"`
		}{
			AccountId: &accountID,
		}
	case "azure":
		response.Azure = &struct {
			ResourceGroups *[]string `json:"resource_groups,omitempty"`
			SubscriptionId *string   `json:"subscription_id,omitempty"`
			TenantId       *string   `json:"tenant_id,omitempty"`
		}{
			SubscriptionId: &auth.Payload,
		}
	case "gcp":
		// GCP upload info is currently empty in provisioning-backend
	}

	return ctx.JSON(http.StatusOK, response)
}
