package v1

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	"github.com/osbuild/image-builder-crc/internal/clients/recommendations"

	"github.com/labstack/echo/v4"
)

func (h *Handlers) RecommendPackage(ctx echo.Context) error {
	var req RecommendPackageRequest
	err := ctx.Bind(&req)
	if err != nil {
		return err
	}

	resp, err := h.handleRecommendationsResponse(ctx, req)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "Failed to recommendation package Response", "error", err)
		return err
	}

	return ctx.JSON(http.StatusOK, resp)
}

var supportedDistros = []string{"rhel-8", "rhel-9", "rhel-10"}

func (h *Handlers) handleRecommendationsResponse(ctx echo.Context, req RecommendPackageRequest) (RecommendationsResponse, error) {
	cloudRP := recommendations.RecommendPackageRequest{
		Packages:            req.Packages,
		RecommendedPackages: req.RecommendedPackages,
		Distribution:        req.Distribution.String(),
	}

	if !slices.Contains(supportedDistros, cloudRP.Distribution) {
		return RecommendationsResponse{}, echo.NewHTTPError(http.StatusBadRequest, fmt.Errorf("unsupported distribution %s", cloudRP.Distribution))
	}

	resp, err := h.server.rClient.RecommendationsPackages(ctx.Request().Context(), cloudRP)
	if err != nil {
		ctx.Logger().Errorf("Failed to get recommendation response: %v", err)
		return RecommendationsResponse{}, err
	}
	defer closeBody(ctx, resp.Body)

	var responsePackages RecommendationsResponse
	err = json.NewDecoder(resp.Body).Decode(&responsePackages)
	if err != nil {
		return RecommendationsResponse{}, err
	}

	slog.InfoContext(ctx.Request().Context(), "Package recommendation",
		"stats", true,
		"packages", req.Packages,
		"amount", req.RecommendedPackages,
		"distribution", req.Distribution,
		"response", responsePackages.Packages,
		"model", responsePackages.ModelVersion,
	)

	if len(responsePackages.Packages) == 0 {
		return RecommendationsResponse{}, nil
	}

	return responsePackages, nil
}
