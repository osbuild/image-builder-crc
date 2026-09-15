//go:build dbtests

package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/osbuild/image-builder-crc/internal/db"
	"github.com/osbuild/image-builder-crc/internal/tutils"
	"github.com/stretchr/testify/require"
)

const (
	ANR1 = "000001"
	ANR2 = "000002"
	ANR3 = "000003"

	ORGID1 = "100000"
	ORGID2 = "100001"
	ORGID3 = "100002"

	EMAIL1 = "user1@test.test"

	fortnight = time.Hour * 24 * 14
)

// testExpireCompose testing expiration of compose only
// also tests vacuum
func testExpireCompose(ctx context.Context, t *testing.T) {
	connStr := tutils.ConnStr(t)
	d, err := newDB(ctx, connStr)
	require.NoError(t, err)

	dbComposesRetentionMonths := 5

	alreadyExpiredTime := time.Now().AddDate(0, (dbComposesRetentionMonths+1)*-1, 0)
	emailRetentionDate := time.Now().AddDate(0, dbComposesRetentionMonths*-1, 0)

	composeId := uuid.New()
	insert := "INSERT INTO composes(job_id, request, created_at, account_number, org_id) VALUES ($1, $2, $3, $4, $5)"
	_, err = d.Conn.Exec(ctx, insert, composeId, "{}", alreadyExpiredTime, ANR1, ORGID1)
	require.NoError(t, err)

	require.NoError(t, d.VacuumAnalyze(ctx))
	deleted, err := d.LogVacuumStats(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(0), deleted)

	rows, err := d.ExpiredComposesCount(ctx, emailRetentionDate)
	require.NoError(t, err)
	require.Equal(t, int64(1), rows)

	rows, err = d.DeleteComposes(ctx, emailRetentionDate)
	require.NoError(t, err)
	require.Equal(t, int64(1), rows)

	// assure data to be flushed for the vacuum test to work
	_, err = d.Conn.Exec(ctx, "CHECKPOINT")
	require.NoError(t, err)

	rows, err = d.ExpiredComposesCount(ctx, emailRetentionDate)
	require.NoError(t, err)
	require.Equal(t, int64(0), rows)

	require.NoError(t, d.VacuumAnalyze(ctx))
	_, err = d.LogVacuumStats(ctx)
	//deleted, err = d.LogVacuumStats()
	// skip check for now
	// until we found out why this works locally but not in
	// the github actions
	//require.Equal(t, int64(1), deleted)
	require.NoError(t, err)
}

func testExpireByCallingDBCleanup(ctx context.Context, t *testing.T) {
	connStr := tutils.ConnStr(t)
	d, err := newDB(ctx, connStr)
	require.NoError(t, err)

	dbComposesRetentionMonths := 5

	notYetExpiredTime := time.Now()
	alreadyExpiredTime := time.Now().AddDate(0, (dbComposesRetentionMonths+1)*-1, 0)
	emailRetentionDate := time.Now().AddDate(0, dbComposesRetentionMonths*-1, 0)

	composeIdNotYetExpired := uuid.New()
	insert := "INSERT INTO composes(job_id, request, created_at, account_number, org_id) VALUES ($1, $2, $3, $4, $5)"
	_, err = d.Conn.Exec(ctx, insert, composeIdNotYetExpired, "{}", notYetExpiredTime, ANR1, ORGID1)

	composeIdExpired := uuid.New()
	insert = "INSERT INTO composes(job_id, request, created_at, account_number, org_id) VALUES ($1, $2, $3, $4, $5)"
	_, err = d.Conn.Exec(ctx, insert, composeIdExpired, "{}", alreadyExpiredTime, ANR1, ORGID1)

	// two rows inserted, only one is expired
	rows, err := d.ExpiredComposesCount(ctx, emailRetentionDate)
	require.NoError(t, err)
	require.Equal(t, int64(1), rows)

	err = DBCleanup(ctx, connStr, false, dbComposesRetentionMonths)
	require.NoError(t, err)

	rows, err = d.ExpiredComposesCount(ctx, emailRetentionDate)
	require.NoError(t, err)
	require.Equal(t, int64(0), rows)
}

// testVacuum test if no vacuum is performed on a clean database
func testVacuum(ctx context.Context, t *testing.T) {
	d, err := newDB(ctx, tutils.ConnStr(t))
	require.NoError(t, err)

	require.NoError(t, d.VacuumAnalyze(ctx))
	deleted, err := d.LogVacuumStats(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(0), deleted)
}

func testDryRun(ctx context.Context, t *testing.T) {
	connStr := tutils.ConnStr(t)
	d, err := newDB(ctx, connStr)
	require.NoError(t, err)

	dbComposesRetentionMonths := 5

	alreadyExpiredTime := time.Now().AddDate(0, (dbComposesRetentionMonths+1)*-1, 0)
	emailRetentionDate := time.Now().AddDate(0, dbComposesRetentionMonths*-1, 0)

	composeIdExpired := uuid.New()
	insert := "INSERT INTO composes(job_id, request, created_at, account_number, org_id) VALUES ($1, $2, $3, $4, $5)"
	_, err = d.Conn.Exec(ctx, insert, composeIdExpired, "{}", alreadyExpiredTime, ANR1, ORGID1)

	rows, err := d.ExpiredComposesCount(ctx, emailRetentionDate)
	require.NoError(t, err)
	require.Equal(t, int64(1), rows)

	err = DBCleanup(ctx, connStr, true, dbComposesRetentionMonths)
	require.NoError(t, err)

	// still there
	rows, err = d.ExpiredComposesCount(ctx, emailRetentionDate)
	require.NoError(t, err)
	require.Equal(t, int64(1), rows)
}

func testPool(ctx context.Context, t *testing.T) (db.DB, func()) {
	t.Helper()
	d, err := db.InitDBConnectionPool(ctx, tutils.ConnStr(t))
	require.NoError(t, err)
	return d, func() { d.Close() }
}

func insertBlueprint(ctx context.Context, t *testing.T, orgID, account, name, body string) uuid.UUID {
	t.Helper()
	d, closePool := testPool(ctx, t)
	defer closePool()
	id := uuid.New()
	err := d.InsertBlueprint(ctx, id, uuid.New(), orgID, account, name, "blueprint desc", json.RawMessage(body), nil, nil)
	require.NoError(t, err)
	return id
}

// count how many non-deleted blueprints an org has
func blueprintCount(ctx context.Context, t *testing.T, orgID string) int {
	t.Helper()
	d, closePool := testPool(ctx, t)
	defer closePool()
	_, count, err := d.GetBlueprints(ctx, orgID, 100, 0)
	require.NoError(t, err)
	return count
}

// names of non-deleted blueprints an org has
func blueprintNames(ctx context.Context, t *testing.T, orgID string) []string {
	t.Helper()
	d, closePool := testPool(ctx, t)
	defer closePool()
	bps, _, err := d.GetBlueprints(ctx, orgID, 100, 0)
	require.NoError(t, err)
	names := make([]string, 0, len(bps))
	for _, bp := range bps {
		names = append(names, bp.Name)
	}
	return names
}

// like blueprintCount, but includes deleted rows
func blueprintRowCountIncludingDeleted(ctx context.Context, t *testing.T, orgID string) int {
	t.Helper()
	d, err := newDB(ctx, tutils.ConnStr(t))
	require.NoError(t, err)
	defer func() { require.NoError(t, d.Close()) }()
	var count int
	err = d.Conn.QueryRow(ctx, `SELECT COUNT(*) FROM blueprints WHERE org_id = $1`, orgID).Scan(&count)
	require.NoError(t, err)
	return count
}

// latest body for a name; fails if missing
func blueprintBodyByName(ctx context.Context, t *testing.T, orgID, name string) json.RawMessage {
	t.Helper()
	d, closePool := testPool(ctx, t)
	defer closePool()
	found, err := d.FindBlueprintByName(ctx, orgID, name)
	require.NoError(t, err)
	require.NotNil(t, found, "blueprint %q not found", name)
	entry, err := d.GetBlueprint(ctx, found.Id, orgID, nil)
	require.NoError(t, err)
	return entry.Body
}

// fails if a blueprint with a given name exists
func requireNoBlueprintNamed(ctx context.Context, t *testing.T, orgID, name string) {
	t.Helper()
	d, closePool := testPool(ctx, t)
	defer closePool()
	found, err := d.FindBlueprintByName(ctx, orgID, name)
	require.NoError(t, err)
	require.Nil(t, found, "did not expect blueprint %q", name)
}

// image_type of the single request on a named blueprint.
func imageTypeByName(ctx context.Context, t *testing.T, orgID, name string) string {
	t.Helper()
	requests, err := extractImageRequests(blueprintBodyByName(ctx, t, orgID, name))
	require.NoError(t, err)
	require.Len(t, requests, 1)
	meta, err := parseImageRequestMeta(requests[0])
	require.NoError(t, err)
	return meta.ImageType
}

const multiTargetBody = `{
	"customizations": {"packages": ["vim"]},
	"distribution": "rhel-9",
	"image_requests": [
		{"image_type": "aws", "architecture": "x86_64"},
		{"image_type": "gcp", "architecture": "x86_64"}
	]
}`

const guestImageBody = `{
	"image_requests": [
		{"image_type": "guest-image", "architecture": "x86_64"}
	]
}`

const threeTargetBody = `{
	"image_requests": [
		{"image_type": "aws", "architecture": "x86_64"},
		{"image_type": "gcp", "architecture": "x86_64"},
		{"image_type": "azure", "architecture": "x86_64"}
	]
}`

const singleTargetBody = `{
	"image_requests": [
		{"image_type": "aws", "architecture": "x86_64"}
	]
}`

// Dry run does not create any blueprints
func testSplitDryRun(ctx context.Context, t *testing.T) {
	connStr := tutils.ConnStr(t)
	insertBlueprint(ctx, t, ORGID1, ANR1, "multi", multiTargetBody)

	err := SplitMultiTargetBlueprints(ctx, connStr, true)
	require.NoError(t, err)
	require.Equal(t, 1, blueprintCount(ctx, t, ORGID1))
}

// First run creates one blueprint per target
func testSplitLiveCreatesOnePerTarget(ctx context.Context, t *testing.T) {
	connStr := tutils.ConnStr(t)
	originalID := insertBlueprint(ctx, t, ORGID1, ANR1, "multi", multiTargetBody)

	err := SplitMultiTargetBlueprints(ctx, connStr, false)
	require.NoError(t, err)
	require.Equal(t, 2, blueprintCount(ctx, t, ORGID1))

	d, closePool := testPool(ctx, t)
	defer closePool()
	_, err = d.GetBlueprint(ctx, originalID, ORGID1, nil)
	require.ErrorIs(t, err, db.ErrBlueprintNotFound)
	require.Equal(t, 3, blueprintRowCountIncludingDeleted(ctx, t, ORGID1))

	awsBody := blueprintBodyByName(ctx, t, ORGID1, "multi - aws")
	awsRequests, err := extractImageRequests(awsBody)
	require.NoError(t, err)
	require.Len(t, awsRequests, 1)
	meta, err := parseImageRequestMeta(awsRequests[0])
	require.NoError(t, err)
	require.Equal(t, "aws", meta.ImageType)

	var awsObj map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(awsBody, &awsObj))
	require.JSONEq(t, `{"packages": ["vim"]}`, string(awsObj["customizations"]))

	gcpBody := blueprintBodyByName(ctx, t, ORGID1, "multi - gcp")
	gcpRequests, err := extractImageRequests(gcpBody)
	require.NoError(t, err)
	require.Len(t, gcpRequests, 1)
	meta, err = parseImageRequestMeta(gcpRequests[0])
	require.NoError(t, err)
	require.Equal(t, "gcp", meta.ImageType)
}

// Second run does not create duplicates
func testSplitIdempotent(ctx context.Context, t *testing.T) {
	connStr := tutils.ConnStr(t)
	insertBlueprint(ctx, t, ORGID1, ANR1, "multi", multiTargetBody)

	err := SplitMultiTargetBlueprints(ctx, connStr, false)
	require.NoError(t, err)
	require.Equal(t, 2, blueprintCount(ctx, t, ORGID1))

	err = SplitMultiTargetBlueprints(ctx, connStr, false)
	require.NoError(t, err)
	require.Equal(t, 2, blueprintCount(ctx, t, ORGID1))
}

func testSplitSkipsSingleTarget(ctx context.Context, t *testing.T) {
	connStr := tutils.ConnStr(t)
	insertBlueprint(ctx, t, ORGID1, ANR1, "single", singleTargetBody)

	err := SplitMultiTargetBlueprints(ctx, connStr, false)
	require.NoError(t, err)
	require.Equal(t, 1, blueprintCount(ctx, t, ORGID1))
}

// if a blueprint with a given name exists, use the architecture suffix
func testSplitUsesArchitectureWhenNameTaken(ctx context.Context, t *testing.T) {
	connStr := tutils.ConnStr(t)
	insertBlueprint(ctx, t, ORGID1, ANR1, "multi", `{
		"image_requests": [
			{"image_type": "aws", "architecture": "x86_64"},
			{"image_type": "aws", "architecture": "aarch64"}
		]
	}`)

	err := SplitMultiTargetBlueprints(ctx, connStr, false)
	require.NoError(t, err)
	require.Equal(t, 2, blueprintCount(ctx, t, ORGID1))

	d, closePool := testPool(ctx, t)
	defer closePool()
	primary, err := d.FindBlueprintByName(ctx, ORGID1, "multi - aws")
	require.NoError(t, err)
	require.NotNil(t, primary)
	secondary, err := d.FindBlueprintByName(ctx, ORGID1, "multi - aws-aarch64")
	require.NoError(t, err)
	require.NotNil(t, secondary)
}

// Deleted blueprints are not split, even next to a live multi-target.
func testSplitIgnoresDeleted(ctx context.Context, t *testing.T) {
	connStr := tutils.ConnStr(t)
	d, closePool := testPool(ctx, t)
	defer closePool()

	deletedOnly := insertBlueprint(ctx, t, ORGID1, ANR1, "gone", multiTargetBody)
	require.NoError(t, d.DeleteBlueprint(ctx, deletedOnly, ORGID1))

	deletedAmongLive := insertBlueprint(ctx, t, ORGID2, ANR2, "gone", multiTargetBody)
	require.NoError(t, d.DeleteBlueprint(ctx, deletedAmongLive, ORGID2))
	insertBlueprint(ctx, t, ORGID2, ANR2, "alive", multiTargetBody)

	err := SplitMultiTargetBlueprints(ctx, connStr, false)
	require.NoError(t, err)

	require.Equal(t, 0, blueprintCount(ctx, t, ORGID1))
	require.Equal(t, 1, blueprintRowCountIncludingDeleted(ctx, t, ORGID1))
	requireNoBlueprintNamed(ctx, t, ORGID1, deletedOnly.String()+" - aws")
	requireNoBlueprintNamed(ctx, t, ORGID1, deletedOnly.String()+" - gcp")

	require.ElementsMatch(t, []string{"alive - aws", "alive - gcp"}, blueprintNames(ctx, t, ORGID2))
	require.Equal(t, 4, blueprintRowCountIncludingDeleted(ctx, t, ORGID2))
	requireNoBlueprintNamed(ctx, t, ORGID2, deletedAmongLive.String()+" - aws")
	requireNoBlueprintNamed(ctx, t, ORGID2, deletedAmongLive.String()+" - gcp")
}

// If both preferred names for a target are taken, that blueprint is skipped and left unchanged.
func testSplitSkipsWhenPreferredNamesTaken(ctx context.Context, t *testing.T) {
	connStr := tutils.ConnStr(t)
	insertBlueprint(ctx, t, ORGID1, ANR1, "multi - aws", guestImageBody)
	insertBlueprint(ctx, t, ORGID1, ANR1, "multi - aws-x86_64", guestImageBody)
	insertBlueprint(ctx, t, ORGID1, ANR1, "multi", multiTargetBody)

	err := SplitMultiTargetBlueprints(ctx, connStr, false)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{
		"multi",
		"multi - aws",
		"multi - aws-x86_64",
	}, blueprintNames(ctx, t, ORGID1))
}

// Only the type suffix taken → use {name} - {type}-{arch}.
func testSplitUsesArchWhenOnlyPrimaryTaken(ctx context.Context, t *testing.T) {
	connStr := tutils.ConnStr(t)
	insertBlueprint(ctx, t, ORGID1, ANR1, "multi - aws", guestImageBody)
	insertBlueprint(ctx, t, ORGID1, ANR1, "multi", multiTargetBody)

	err := SplitMultiTargetBlueprints(ctx, connStr, false)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{
		"multi - aws",
		"multi - aws-x86_64",
		"multi - gcp",
	}, blueprintNames(ctx, t, ORGID1))
	require.Equal(t, "aws", imageTypeByName(ctx, t, ORGID1, "multi - aws-x86_64"))
	require.Equal(t, "guest-image", imageTypeByName(ctx, t, ORGID1, "multi - aws"))
}

// Unique names are per org; another org's "multi - aws" does not block this one.
func testSplitSameNameOtherOrg(ctx context.Context, t *testing.T) {
	connStr := tutils.ConnStr(t)
	insertBlueprint(ctx, t, ORGID2, ANR2, "multi - aws", guestImageBody)
	insertBlueprint(ctx, t, ORGID1, ANR1, "multi", multiTargetBody)

	err := SplitMultiTargetBlueprints(ctx, connStr, false)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"multi - aws", "multi - gcp"}, blueprintNames(ctx, t, ORGID1))
	require.ElementsMatch(t, []string{"multi - aws"}, blueprintNames(ctx, t, ORGID2))
	require.Equal(t, "aws", imageTypeByName(ctx, t, ORGID1, "multi - aws"))
	require.Equal(t, "guest-image", imageTypeByName(ctx, t, ORGID2, "multi - aws"))
}

// Latest version is single-target (older version was multi) → do not split.
func testSplitLatestVersionNotMulti(ctx context.Context, t *testing.T) {
	connStr := tutils.ConnStr(t)
	d, closePool := testPool(ctx, t)
	defer closePool()

	id := insertBlueprint(ctx, t, ORGID1, ANR1, "multi", multiTargetBody)
	err := d.UpdateBlueprint(ctx, uuid.New(), id, ORGID1, "multi", "blueprint desc", json.RawMessage(singleTargetBody), nil)
	require.NoError(t, err)

	err = SplitMultiTargetBlueprints(ctx, connStr, false)
	require.NoError(t, err)
	require.Equal(t, 1, blueprintCount(ctx, t, ORGID1))
	require.ElementsMatch(t, []string{"multi"}, blueprintNames(ctx, t, ORGID1))
}

// One new blueprint per image_requests entry (aws, gcp, azure).
func testSplitThreeTargets(ctx context.Context, t *testing.T) {
	connStr := tutils.ConnStr(t)
	insertBlueprint(ctx, t, ORGID1, ANR1, "multi", threeTargetBody)

	err := SplitMultiTargetBlueprints(ctx, connStr, false)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"multi - aws", "multi - gcp", "multi - azure"}, blueprintNames(ctx, t, ORGID1))
}

// Names stay within VARCHAR(200).
func testSplitLongName(ctx context.Context, t *testing.T) {
	connStr := tutils.ConnStr(t)
	longName := strings.Repeat("a", blueprintNameMaxLen)
	insertBlueprint(ctx, t, ORGID1, ANR1, longName, multiTargetBody)

	err := SplitMultiTargetBlueprints(ctx, connStr, false)
	require.NoError(t, err)
	require.Equal(t, 2, blueprintCount(ctx, t, ORGID1))

	names := blueprintNames(ctx, t, ORGID1)
	require.NotContains(t, names, longName)
	seen := map[string]struct{}{}
	for _, name := range names {
		require.LessOrEqual(t, utf8.RuneCountInString(name), blueprintNameMaxLen)
		_, dup := seen[name]
		require.False(t, dup, "duplicate name %q", name)
		seen[name] = struct{}{}
	}
}

func TestAll(t *testing.T) {
	ctx := t.Context()
	fns := []func(context.Context, *testing.T){
		testExpireCompose,
		testExpireByCallingDBCleanup,
		testDryRun,
		testVacuum,
		testSplitDryRun,
		testSplitLiveCreatesOnePerTarget,
		testSplitIdempotent,
		testSplitSkipsSingleTarget,
		testSplitUsesArchitectureWhenNameTaken,
		testSplitIgnoresDeleted,
		testSplitSkipsWhenPreferredNamesTaken,
		testSplitUsesArchWhenOnlyPrimaryTaken,
		testSplitSameNameOtherOrg,
		testSplitLatestVersionNotMulti,
		testSplitThreeTargets,
		testSplitLongName,
	}

	for _, f := range fns {
		select {
		case <-ctx.Done():
			require.NoError(t, ctx.Err())
			return
		default:
			tutils.RunTest(ctx, t, f)
		}
	}
}
