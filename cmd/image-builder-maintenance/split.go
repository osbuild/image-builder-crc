package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/osbuild/image-builder-crc/internal/db"
)

const (
	blueprintNameMaxLen = 200
	splitBatchSize      = 500
)

var errNoUniqueName = errors.New("could not allocate unique name")

const sqlReparentComposes = `
		UPDATE composes c
		SET blueprint_version_id = $1
		FROM blueprint_versions bv
		WHERE c.blueprint_version_id = bv.id
			AND bv.blueprint_id = $2
			AND c.org_id = $3
			AND c.deleted = FALSE
			AND c.request->'image_requests'->0->>'image_type' = $4
			AND c.request->'image_requests'->0->>'architecture' = $5`

const sqlListMultiTargetBlueprints = `
		SELECT b.id, b.org_id, b.account_number, b.name,
			COALESCE(b.description, ''), b.metadata, bv.body, bv.service_snapshots
		FROM blueprints b
		INNER JOIN blueprint_versions bv ON bv.blueprint_id = b.id
		INNER JOIN (
			SELECT blueprint_id, MAX(version) AS version
			FROM blueprint_versions
			GROUP BY blueprint_id
		) latest ON latest.blueprint_id = bv.blueprint_id AND latest.version = bv.version
		WHERE b.deleted = FALSE
			AND b.id > $1
			AND jsonb_array_length(bv.body->'image_requests') > 1
		ORDER BY b.id
		LIMIT $2`

type multiTargetBlueprint struct {
	ID               uuid.UUID
	OrgID            string
	AccountNumber    string
	Name             string
	Description      string
	Metadata         json.RawMessage
	Body             json.RawMessage
	ServiceSnapshots json.RawMessage
}

type imageRequestMeta struct {
	ImageType    string `json:"image_type"`
	Architecture string `json:"architecture"`
}

type targetKey struct {
	imageType    string
	architecture string
}

func targetKeyFromMeta(meta imageRequestMeta) targetKey {
	return targetKey{imageType: meta.ImageType, architecture: meta.Architecture}
}

// SplitMultiTargetBlueprints finds latest non-deleted blueprints with more than
// one image_requests entry and creates one new blueprint per target. After a
// source is fully split, it is soft-deleted.
func SplitMultiTargetBlueprints(ctx context.Context, dbURL string, dryRun bool) error {
	d, err := db.InitDBConnectionPool(ctx, dbURL)
	if err != nil {
		return err
	}
	defer d.Close()

	tx, err := d.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			slog.ErrorContext(ctx, "failed to rollback transaction", "err", err)
		}
	}()

	created := 0
	skipped := 0
	sources := 0
	deleted := 0
	afterID := uuid.Nil

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		batch, err := nextMultiTargetBatch(ctx, tx, afterID, splitBatchSize)
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			break
		}

		for _, src := range batch {
			sp, err := tx.Begin(ctx)
			if err != nil {
				return err
			}

			nCreated, didDelete, err := splitOneBlueprint(ctx, sp, src, dryRun)
			if err != nil {
				_ = sp.Rollback(ctx)
				slog.ErrorContext(ctx, "skipping blueprint that could not be split",
					"blueprint_id", src.ID,
					"org_id", src.OrgID,
					"source_name", src.Name,
					"err", err)
				skipped++
				sources++
				afterID = src.ID
				continue
			}

			if err := sp.Commit(ctx); err != nil {
				return err
			}

			created += nCreated
			sources++
			if didDelete {
				deleted++
			}
			afterID = src.ID
		}

		if len(batch) < splitBatchSize {
			break
		}
	}

	slog.InfoContext(ctx, "blueprint split summary",
		"dry_run", dryRun,
		"multi_target_blueprints", sources,
		"created", created,
		"skipped", skipped,
		"deleted", deleted)

	if dryRun {
		return nil
	}
	return tx.Commit(ctx)
}

// nextMultiTargetBatch returns the next page of live multi-target blueprints after `afterID`.
func nextMultiTargetBatch(ctx context.Context, tx pgx.Tx, afterID uuid.UUID, limit int) ([]multiTargetBlueprint, error) {
	rows, err := tx.Query(ctx, sqlListMultiTargetBlueprints, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []multiTargetBlueprint
	for rows.Next() {
		var src multiTargetBlueprint
		err = rows.Scan(&src.ID, &src.OrgID, &src.AccountNumber, &src.Name,
			&src.Description, &src.Metadata, &src.Body, &src.ServiceSnapshots)
		if err != nil {
			return nil, err
		}
		result = append(result, src)
	}
	return result, rows.Err()
}

// splitOneBlueprint creates one child per image request, then soft-deletes the
// original. Any failure rolls back the caller's savepoint.
func splitOneBlueprint(ctx context.Context, tx pgx.Tx, src multiTargetBlueprint, dryRun bool) (int, bool, error) {
	requests, err := extractImageRequests(src.Body)
	if err != nil {
		return 0, false, fmt.Errorf("blueprint %s: parse image_requests: %w", src.ID, err)
	}

	if dryRun {
		proposed := make([]string, 0, len(requests))
		claimed := make(map[string]struct{})
		for _, req := range requests {
			meta, err := parseImageRequestMeta(req)
			if err != nil {
				return 0, false, fmt.Errorf("blueprint %s: parse image request: %w", src.ID, err)
			}
			name, _, err := mapOneRequest(ctx, tx, src, req, meta, true, claimed)
			if err != nil {
				return 0, false, err
			}
			proposed = append(proposed, name)
		}
		slog.InfoContext(ctx, "dryrun",
			"blueprint_id", src.ID,
			"org_id", src.OrgID,
			"name", src.Name,
			"target_count", len(requests),
			"proposed_names", proposed,
			"would_delete", true)
		return len(requests), false, nil
	}

	childVersions := make(map[targetKey]uuid.UUID, len(requests))
	claimed := make(map[string]struct{})
	for _, req := range requests {
		meta, err := parseImageRequestMeta(req)
		if err != nil {
			return 0, false, fmt.Errorf("blueprint %s: parse image request: %w", src.ID, err)
		}
		_, versionID, err := mapOneRequest(ctx, tx, src, req, meta, false, claimed)
		if err != nil {
			return 0, false, err
		}
		childVersions[targetKeyFromMeta(meta)] = versionID
	}

	reparented, err := reparentComposes(ctx, tx, src.OrgID, src.ID, childVersions)
	if err != nil {
		return 0, false, fmt.Errorf("blueprint %s: reparent composes: %w", src.ID, err)
	}
	if reparented > 0 {
		slog.InfoContext(ctx, "reparented composes to split children",
			"source_id", src.ID,
			"org_id", src.OrgID,
			"source_name", src.Name,
			"count", reparented)
	}

	err = db.DeleteBlueprintTx(ctx, tx, src.ID, src.OrgID)
	if err != nil {
		return 0, false, fmt.Errorf("blueprint %s: delete original: %w", src.ID, err)
	}
	slog.InfoContext(ctx, "soft-deleted original blueprint after split",
		"source_id", src.ID,
		"org_id", src.OrgID,
		"source_name", src.Name)
	return len(requests), true, nil
}

// mapOneRequest maps one image request to a new single-target blueprint, or
// proposes a name in dry-run. claimed tracks names already used in this split.
func mapOneRequest(ctx context.Context, tx pgx.Tx, src multiTargetBlueprint, req json.RawMessage, meta imageRequestMeta, dryRun bool, claimed map[string]struct{}) (string, uuid.UUID, error) {
	for {
		name, err := chooseSplitName(ctx, tx, src, meta, claimed)
		if err != nil {
			return "", uuid.Nil, fmt.Errorf("blueprint %s: choose name for %s/%s: %w",
				src.ID, meta.ImageType, meta.Architecture, err)
		}
		claimed[name] = struct{}{}

		if dryRun {
			slog.InfoContext(ctx, "dryrun would create blueprint",
				"source_id", src.ID,
				"org_id", src.OrgID,
				"source_name", src.Name,
				"new_name", name,
				"image_type", meta.ImageType,
				"architecture", meta.Architecture)
			return name, uuid.Nil, nil
		}

		body, err := bodyWithSingleImageRequest(src.Body, req)
		if err != nil {
			return "", uuid.Nil, fmt.Errorf("blueprint %s: build body: %w", src.ID, err)
		}

		inserted, versionID, err := insertSplitBlueprint(ctx, tx, src, name, body)
		if err != nil {
			return "", uuid.Nil, err
		}
		if !inserted {
			slog.InfoContext(ctx, "name collided on insert, retrying with another name",
				"blueprint_id", src.ID,
				"org_id", src.OrgID,
				"collided_name", name)
			continue
		}

		slog.InfoContext(ctx, "created blueprint from split",
			"source_id", src.ID,
			"org_id", src.OrgID,
			"source_name", src.Name,
			"new_name", name,
			"image_type", meta.ImageType,
			"architecture", meta.Architecture)
		return name, versionID, nil
	}
}

// reparentComposes moves composes from every version of sourceID to each child's v1,
// matched by image_type and architecture on the compose request.
func reparentComposes(ctx context.Context, tx pgx.Tx, orgID string, sourceID uuid.UUID, childVersions map[targetKey]uuid.UUID) (int, error) {
	reparented := 0
	for key, versionID := range childVersions {
		tag, err := tx.Exec(ctx, sqlReparentComposes, versionID, sourceID, orgID, key.imageType, key.architecture)
		if err != nil {
			return reparented, err
		}
		reparented += int(tag.RowsAffected())
	}
	return reparented, nil
}

// insertSplitBlueprint inserts the child in a savepoint so a unique-name
// collision can be retried without aborting the outer transaction.
func insertSplitBlueprint(ctx context.Context, tx pgx.Tx, src multiTargetBlueprint, name string, body json.RawMessage) (inserted bool, versionID uuid.UUID, err error) {
	blueprintID := uuid.New()
	versionID = uuid.New()
	sp, err := tx.Begin(ctx)
	if err != nil {
		return false, uuid.Nil, fmt.Errorf("blueprint %s: begin savepoint: %w", src.ID, err)
	}
	err = db.InsertBlueprintTx(ctx, sp, blueprintID, versionID, src.OrgID, src.AccountNumber,
		name, src.Description, body, src.Metadata, src.ServiceSnapshots)
	if err == nil {
		if err := sp.Commit(ctx); err != nil {
			return false, uuid.Nil, fmt.Errorf("blueprint %s: insert %q: %w", src.ID, name, err)
		}
		return true, versionID, nil
	}
	_ = sp.Rollback(ctx)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
		return false, uuid.Nil, nil
	}
	return false, uuid.Nil, fmt.Errorf("blueprint %s: insert %q: %w", src.ID, name, err)
}

// extractImageRequests returns the image_requests array from a blueprint body.
func extractImageRequests(body json.RawMessage) ([]json.RawMessage, error) {
	var parsed struct {
		ImageRequests []json.RawMessage `json:"image_requests"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	return parsed.ImageRequests, nil
}

// parseImageRequestMeta reads image_type and architecture from one image request.
func parseImageRequestMeta(req json.RawMessage) (imageRequestMeta, error) {
	var meta imageRequestMeta
	if err := json.Unmarshal(req, &meta); err != nil {
		return imageRequestMeta{}, err
	}
	return meta, nil
}

// bodyWithSingleImageRequest copies the source body with image_requests set to a single request.
func bodyWithSingleImageRequest(original json.RawMessage, request json.RawMessage) (json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(original, &obj); err != nil {
		return nil, err
	}
	arr, err := json.Marshal([]json.RawMessage{request})
	if err != nil {
		return nil, err
	}
	obj["image_requests"] = arr
	return json.Marshal(obj)
}

// clipTo truncates name to at most maxLen runes.
func clipTo(name string, maxLen int) string {
	if maxLen < 1 {
		maxLen = 1
	}
	if utf8.RuneCountInString(name) <= maxLen {
		return name
	}
	return string([]rune(name)[:maxLen])
}

// preferredSplitNames returns "{name} - {type}" then "{name} - {type}-{arch}", clipped to 200 runes.
func preferredSplitNames(srcName string, meta imageRequestMeta) (primary, secondary string) {
	typeSuffix := " - " + meta.ImageType
	archSuffix := fmt.Sprintf(" - %s-%s", meta.ImageType, meta.Architecture)
	primary = clipTo(srcName, blueprintNameMaxLen-utf8.RuneCountInString(typeSuffix)) + typeSuffix
	secondary = clipTo(srcName, blueprintNameMaxLen-utf8.RuneCountInString(archSuffix)) + archSuffix
	return primary, secondary
}

// chooseSplitName tries the primary name, then the secondary.
func chooseSplitName(ctx context.Context, tx pgx.Tx, src multiTargetBlueprint, meta imageRequestMeta, claimed map[string]struct{}) (string, error) {
	primary, secondary := preferredSplitNames(src.Name, meta)
	for _, name := range []string{primary, secondary} {
		free, err := unusedSplitName(ctx, tx, src.OrgID, name, claimed)
		if err != nil || free != "" {
			return free, err
		}
	}
	return "", errNoUniqueName
}

// unusedSplitName checks one candidate. It returns the name if free, or ("", nil) if taken.
func unusedSplitName(ctx context.Context, tx pgx.Tx, orgID, name string, claimed map[string]struct{}) (string, error) {
	if _, used := claimed[name]; used {
		return "", nil
	}

	existing, err := db.FindBlueprintByNameTx(ctx, tx, orgID, name)
	if err != nil {
		return "", err
	}
	if existing == nil {
		return name, nil
	}
	return "", nil
}
