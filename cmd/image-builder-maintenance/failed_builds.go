package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/google/uuid"
	"github.com/osbuild/image-builder-crc/internal/clients/composer"
	"github.com/osbuild/image-builder-crc/internal/oauth2"
	v1 "github.com/osbuild/image-builder-crc/internal/v1"
)

const (
	sentryMaxExtraFieldBytes = 4096
	truncatedMiddle          = " [... truncated ...] "
	window                   = 24 * time.Hour

	sqlListRecentComposes = `
		SELECT job_id, request, org_id, image_name, created_at
		FROM composes
		WHERE created_at >= $1 AND deleted = FALSE
		ORDER BY created_at DESC`
)

type recentCompose struct {
	JobID     uuid.UUID
	Request   json.RawMessage
	OrgID     string
	ImageName *string
	CreatedAt time.Time
}

func ReportFailedBuilds(ctx context.Context, conf Config, dbURL string) error {
	slog.InfoContext(ctx, "starting failed build reporting", "window", window.String())

	db, err := newDB(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			slog.ErrorContext(ctx, "error closing database connection", "err", closeErr)
		}
	}()

	since := time.Now().Add(-window)
	composes, err := listRecentComposes(ctx, db, since)
	if err != nil {
		return fmt.Errorf("listing recent composes: %w", err)
	}

	composerClient, err := composer.NewClient(composer.ComposerClientConfig{
		URL: conf.ComposerURL,
		CA:  conf.ComposerCA,
		Tokener: &oauth2.LazyToken{
			Url:          conf.ComposerTokenURL,
			ClientId:     conf.ComposerClientId,
			ClientSecret: conf.ComposerClientSecret,
		},
	})
	if err != nil {
		return fmt.Errorf("creating composer client: %w", err)
	}

	sentryEnabled := conf.GlitchTipDSN != ""
	if !sentryEnabled {
		slog.InfoContext(ctx, "GLITCHTIP_DSN not set, failed builds will be logged but not sent to Sentry")
	}

	var checked, failed, reported, skipped, errors int

	for _, compose := range composes {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		checked++
		status, statusErr := fetchComposeStatus(ctx, composerClient, compose.JobID)
		if statusErr != nil {
			errors++
			slog.WarnContext(ctx, "failed to fetch compose status", "compose_id", compose.JobID, "err", statusErr)
			continue
		}

		if !isComposeFailed(status) {
			skipped++
			continue
		}

		failed++
		errorSummary := buildFailureMessage(status)
		requestJSON, err := prepareComposeRequestJSON(compose.Request)
		if err != nil {
			errors++
			slog.ErrorContext(ctx, "failed to prepare compose request JSON", "compose_id", compose.JobID, "err", err)
			continue
		}

		manifestJSON := fetchComposeManifestJSON(ctx, composerClient, compose.JobID)

		if conf.DryRun {
			slog.InfoContext(ctx, "dry run, would report failed build",
				"compose_id", compose.JobID,
				"org_id", compose.OrgID,
				"message", errorSummary,
				"request_bytes", len(requestJSON),
				"manifest_bytes", len(manifestJSON),
			)
			reported++
			continue
		}

		if sentryEnabled {
			if reportErr := reportFailedBuildToSentry(ctx, compose, errorSummary, requestJSON, manifestJSON); reportErr != nil {
				errors++
				slog.ErrorContext(ctx, "failed to report build failure to Sentry", "compose_id", compose.JobID, "err", reportErr)
				continue
			}
		} else {
			slog.ErrorContext(ctx, "build failure",
				"message", errorSummary,
				"compose_id", compose.JobID,
				"org_id", compose.OrgID,
				"image_name", imageNameOrEmpty(compose.ImageName),
				"build_failure", true,
			)
		}

		reported++
	}

	slog.InfoContext(ctx, "failed build reporting done",
		"checked", checked,
		"failed", failed,
		"reported", reported,
		"skipped", skipped,
		"errors", errors,
	)

	return nil
}

func listRecentComposes(ctx context.Context, db maintenanceDB, since time.Time) ([]recentCompose, error) {
	rows, err := db.Conn.Query(ctx, sqlListRecentComposes, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var composes []recentCompose
	for rows.Next() {
		var compose recentCompose
		if err := rows.Scan(&compose.JobID, &compose.Request, &compose.OrgID, &compose.ImageName, &compose.CreatedAt); err != nil {
			return nil, err
		}
		composes = append(composes, compose)
	}

	return composes, rows.Err()
}

func fetchComposeStatus(ctx context.Context, client *composer.ComposerClient, id uuid.UUID) (composer.ComposeStatus, error) {
	resp, err := client.ComposeStatus(ctx, id)
	if err != nil {
		return composer.ComposeStatus{}, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var status composer.ComposeStatus
		if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
			return composer.ComposeStatus{}, fmt.Errorf("decoding compose status: %w", err)
		}
		return status, nil
	case http.StatusNotFound:
		return composer.ComposeStatus{}, fmt.Errorf("compose not found in composer")
	default:
		body, _ := io.ReadAll(resp.Body)
		return composer.ComposeStatus{}, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
}

func fetchComposeManifestJSON(ctx context.Context, client *composer.ComposerClient, id uuid.UUID) []byte {
	resp, err := client.ComposeManifests(ctx, id)
	if err != nil {
		slog.WarnContext(ctx, "failed to fetch compose manifests", "compose_id", id, "err", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.WarnContext(ctx, "compose manifests not available", "compose_id", id, "status", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.WarnContext(ctx, "failed to read compose manifests", "compose_id", id, "err", err)
		return nil
	}

	pretty, err := prettyPrintJSON(body)
	if err != nil {
		slog.WarnContext(ctx, "failed to pretty-print manifest JSON", "compose_id", id, "err", err)
		return body
	}

	return pretty
}

func isComposeFailed(status composer.ComposeStatus) bool {
	if status.Status == composer.ComposeStatusValueFailure {
		return true
	}
	if status.ImageStatus.Status == composer.ImageStatusValueFailure {
		return true
	}
	if status.ImageStatuses != nil {
		for _, imageStatus := range *status.ImageStatuses {
			if imageStatus.Status == composer.ImageStatusValueFailure {
				return true
			}
		}
	}
	return false
}

func buildFailureMessage(status composer.ComposeStatus) string {
	reasons := collectFailureReasons(status)
	if len(reasons) == 0 {
		return "BUILD FAILURE: unknown error"
	}
	return "BUILD FAILURE: " + strings.Join(reasons, ": ")
}

func collectFailureReasons(status composer.ComposeStatus) []string {
	var reasons []string
	reasons = append(reasons, collectErrorReasons(status.ImageStatus.Error)...)
	if status.ImageStatuses != nil {
		for _, imageStatus := range *status.ImageStatuses {
			reasons = append(reasons, collectErrorReasons(imageStatus.Error)...)
		}
	}
	return reasons
}

func collectErrorReasons(err *composer.ComposeStatusError) []string {
	if err == nil {
		return nil
	}

	reasons := []string{err.Reason}
	if err.Details == nil {
		return reasons
	}

	if detailStr, ok := err.Details.(string); ok {
		return append(reasons, detailStr)
	}

	encoded, marshalErr := json.Marshal(err.Details)
	if marshalErr != nil {
		return reasons
	}

	var nested []composer.ComposeStatusError
	if json.Unmarshal(encoded, &nested) == nil {
		for i := range nested {
			reasons = append(reasons, collectErrorReasons(&nested[i])...)
		}
		return reasons
	}

	var single composer.ComposeStatusError
	if json.Unmarshal(encoded, &single) == nil && single.Reason != "" {
		reasons = append(reasons, collectErrorReasons(&single)...)
	}

	return reasons
}

func prepareComposeRequestJSON(raw json.RawMessage) ([]byte, error) {
	var composeRequest v1.ComposeRequest
	if err := json.Unmarshal(raw, &composeRequest); err != nil {
		return prettyPrintJSON(raw)
	}

	if composeRequest.Customizations != nil && composeRequest.Customizations.Users != nil {
		users := *composeRequest.Customizations.Users
		for i := range users {
			users[i].RedactPassword()
		}
	}

	return json.MarshalIndent(composeRequest, "", "  ")
}

func prettyPrintJSON(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return raw, nil
	}

	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return raw, nil
	}

	return json.MarshalIndent(value, "", "  ")
}

func reportFailedBuildToSentry(ctx context.Context, compose recentCompose, message string, requestJSON, manifestJSON []byte) error {
	event := newBuildFailureEvent(compose, message)

	attachments := []*sentry.Attachment{
		{
			Filename:    "compose-request.json",
			ContentType: "application/json",
			Payload:     requestJSON,
		},
	}
	if len(manifestJSON) > 0 {
		attachments = append(attachments, &sentry.Attachment{
			Filename:    "manifest.json",
			ContentType: "application/json",
			Payload:     manifestJSON,
		})
	}
	event.Attachments = attachments

	if eventID := sentry.CaptureEvent(event); eventID != nil {
		return nil
	}

	// This fallback can be dropped once file upload feature (attachments) is enabled. It was confirmed by AppSRE that
	// they can do this for us if we ask them to. The helper newBuildFailureEvent could be dropped as well.
	slog.WarnContext(ctx, "Sentry rejected event with attachments, retrying with trimmed inline JSON",
		"compose_id", compose.JobID,
	)

	fallback := newBuildFailureEvent(compose, message)
	fallback.Extra["attachments_fallback"] = true
	fallback.Extra["compose_request"] = trimForSentryField(ctx, string(requestJSON), sentryMaxExtraFieldBytes)
	if len(manifestJSON) > 0 {
		fallback.Extra["manifest"] = trimForSentryField(ctx, string(manifestJSON), sentryMaxExtraFieldBytes)
	}

	if eventID := sentry.CaptureEvent(fallback); eventID == nil {
		return fmt.Errorf("sentry capture failed with and without attachments")
	}

	return nil
}

func newBuildFailureEvent(compose recentCompose, message string) *sentry.Event {
	imageName := imageNameOrEmpty(compose.ImageName)
	return &sentry.Event{
		Level:   sentry.LevelError,
		Message: message,
		Tags: map[string]string{
			"compose_id": compose.JobID.String(),
			"org_id":     compose.OrgID,
		},
		Extra: map[string]interface{}{
			"build_failure": true,
			"image_name":    imageName,
			"created_at":    compose.CreatedAt.UTC().Format(time.RFC3339),
		},
	}
}

func trimForSentryField(ctx context.Context, s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}

	available := maxBytes - len(truncatedMiddle)
	if available <= 0 {
		return s[:maxBytes]
	}

	headBytes := available / 2
	tailBytes := available - headBytes
	trimmed := s[:headBytes] + truncatedMiddle + s[len(s)-tailBytes:]

	slog.WarnContext(ctx, "trimmed Sentry extra field",
		"original_bytes", len(s),
		"trimmed_bytes", len(trimmed),
	)

	return trimmed
}

func imageNameOrEmpty(imageName *string) string {
	if imageName == nil {
		return ""
	}
	return *imageName
}
