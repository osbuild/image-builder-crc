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

var (
	errAlreadySplit = errors.New("already split")
	errNoUniqueName = errors.New("could not allocate unique name")
)

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
	defer func() { _ = tx.Rollback(ctx) }()

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
			nCreated, nSkipped, didDelete, err := splitOneBlueprint(ctx, tx, src, dryRun)
			if err != nil {
				return err
			}
			created += nCreated
			skipped += nSkipped
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

// nextMultiTargetBatch returns the next page of live multi-target blueprints after afterID.
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

// splitOneBlueprint creates one child per image request. The original is
// soft-deleted only when every request was created or already split.
func splitOneBlueprint(ctx context.Context, tx pgx.Tx, src multiTargetBlueprint, dryRun bool) (int, int, bool, error) {
	requests, err := extractImageRequests(src.Body)
	if err != nil {
		return 0, 0, false, fmt.Errorf("blueprint %s: parse image_requests: %w", src.ID, err)
	}

	created := 0
	skipped := 0
	complete := true
	proposed := make([]string, 0, len(requests))
	claimed := make(map[string]struct{})

	for _, req := range requests {
		meta, err := parseImageRequestMeta(req)
		if err != nil {
			slog.WarnContext(ctx, "skipping image request that could not be parsed",
				"blueprint_id", src.ID, "err", err)
			skipped++
			complete = false
			continue
		}

		name, err := mapOneRequest(ctx, tx, src, req, meta, dryRun, claimed)
		if errors.Is(err, errAlreadySplit) {
			skipped++
			continue
		}
		if errors.Is(err, errNoUniqueName) {
			skipped++
			complete = false
			continue
		}
		if err != nil {
			return created, skipped, false, err
		}
		proposed = append(proposed, name)
		created++
	}

	if dryRun {
		slog.InfoContext(ctx, "dryrun",
			"blueprint_id", src.ID,
			"org_id", src.OrgID,
			"name", src.Name,
			"target_count", len(requests),
			"proposed_names", proposed,
			"would_delete", complete)
		return created, skipped, false, nil
	}

	if !complete {
		return created, skipped, false, nil
	}

	err = db.DeleteBlueprintTx(ctx, tx, src.ID, src.OrgID)
	if err != nil {
		return created, skipped, false, fmt.Errorf("blueprint %s: delete original: %w", src.ID, err)
	}
	slog.InfoContext(ctx, "soft-deleted original blueprint after split",
		"source_id", src.ID,
		"org_id", src.OrgID,
		"source_name", src.Name)
	return created, skipped, true, nil
}

// mapOneRequest maps one image request to a new single-target blueprint, or
// proposes a name in dry-run. claimed tracks names already used in this split.
func mapOneRequest(ctx context.Context, tx pgx.Tx, src multiTargetBlueprint, req json.RawMessage, meta imageRequestMeta, dryRun bool, claimed map[string]struct{}) (string, error) {
	for {
		name, err := chooseSplitName(ctx, tx, src, meta, claimed)
		if err != nil {
			if errors.Is(err, errAlreadySplit) || errors.Is(err, errNoUniqueName) {
				slog.ErrorContext(ctx, "skipping image request",
					"blueprint_id", src.ID,
					"org_id", src.OrgID,
					"source_name", src.Name,
					"image_type", meta.ImageType,
					"architecture", meta.Architecture,
					"reason", err)
			}
			return "", err
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
			return name, nil
		}

		body, err := bodyWithSingleImageRequest(src.Body, req)
		if err != nil {
			return "", fmt.Errorf("blueprint %s: build body: %w", src.ID, err)
		}

		inserted, err := insertSplitBlueprint(ctx, tx, src, name, body)
		if err != nil {
			return "", err
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
		return name, nil
	}
}

// insertSplitBlueprint inserts the child in a savepoint so a unique-name
// collision can be retried without aborting the outer transaction.
func insertSplitBlueprint(ctx context.Context, tx pgx.Tx, src multiTargetBlueprint, name string, body json.RawMessage) (inserted bool, err error) {
	sp, err := tx.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("blueprint %s: begin savepoint: %w", src.ID, err)
	}
	err = db.InsertBlueprintTx(ctx, sp, uuid.New(), uuid.New(), src.OrgID, src.AccountNumber,
		name, src.Description, body, src.Metadata, src.ServiceSnapshots)
	if err == nil {
		if err := sp.Commit(ctx); err != nil {
			return false, fmt.Errorf("blueprint %s: insert %q: %w", src.ID, name, err)
		}
		return true, nil
	}
	_ = sp.Rollback(ctx)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
		return false, nil
	}
	return false, fmt.Errorf("blueprint %s: insert %q: %w", src.ID, name, err)
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

// chooseSplitName tries the primary name, then the secondary. Returns
// errAlreadySplit if a matching child exists, or errNoUniqueName if both are taken.
func chooseSplitName(ctx context.Context, tx pgx.Tx, src multiTargetBlueprint, meta imageRequestMeta, claimed map[string]struct{}) (string, error) {
	primary, secondary := preferredSplitNames(src.Name, meta)
	for _, name := range []string{primary, secondary} {
		free, err := unusedSplitName(ctx, tx, src.OrgID, name, meta, claimed)
		if err != nil || free != "" {
			return free, err
		}
	}
	return "", errNoUniqueName
}

// unusedSplitName checks one candidate. It returns the name if free,
// errAlreadySplit if a matching child already exists, or ("", nil) if the name is taken.
func unusedSplitName(ctx context.Context, tx pgx.Tx, orgID, name string, meta imageRequestMeta, claimed map[string]struct{}) (string, error) {
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

	// FindBlueprintByNameTx has no body; fetch it to see if this is already a split child.
	entry, err := db.GetBlueprintTx(ctx, tx, existing.Id, orgID, nil)
	if err != nil {
		if errors.Is(err, db.ErrBlueprintNotFound) {
			return name, nil
		}
		return "", err
	}
	if isMatchingSingleTarget(entry.Body, meta) {
		return "", errAlreadySplit
	}
	return "", nil
}

// isMatchingSingleTarget is true if body has exactly one image request with the same type and arch.
func isMatchingSingleTarget(body json.RawMessage, meta imageRequestMeta) bool {
	requests, err := extractImageRequests(body)
	if err != nil || len(requests) != 1 {
		return false
	}
	got, err := parseImageRequestMeta(requests[0])
	if err != nil {
		return false
	}
	if got.ImageType != meta.ImageType {
		return false
	}
	if meta.Architecture == "" || got.Architecture == "" {
		return true
	}
	return got.Architecture == meta.Architecture
}
