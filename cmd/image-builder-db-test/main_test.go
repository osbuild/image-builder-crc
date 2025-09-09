//go:build dbtests

package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/osbuild/image-builder-crc/internal/common"
	"github.com/osbuild/image-builder-crc/internal/db"
	v1 "github.com/osbuild/image-builder-crc/internal/v1"

	"github.com/osbuild/image-builder-crc/internal/tutils"
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

func testInsertCompose(ctx context.Context, t *testing.T) {
	d, err := db.InitDBConnectionPool(ctx, tutils.ConnStr(t))
	require.NoError(t, err)

	imageName := "MyImageName"
	clientId := "ui"
	blueprintId := uuid.New()
	versionId := uuid.New()

	tutils.MigrateTern(ctx, t)

	err = d.InsertBlueprint(ctx, blueprintId, versionId, ORGID1, ANR1, "blueprint", "blueprint desc", []byte("{}"), []byte("{}"), nil)
	require.NoError(t, err)

	// test
	err = d.InsertCompose(ctx, uuid.New(), "", "", ORGID1, &imageName, []byte("{}"), &clientId, &versionId)
	require.NoError(t, err)
	err = d.InsertCompose(ctx, uuid.New(), ANR1, EMAIL1, ORGID1, &imageName, []byte("{}"), &clientId, nil)
	require.NoError(t, err)
	err = d.InsertCompose(ctx, uuid.New(), "", "", ORGID1, &imageName, []byte("{}"), &clientId, nil)
	require.NoError(t, err)
}

func testGetCompose(ctx context.Context, t *testing.T) {
	d, err := db.InitDBConnectionPool(ctx, tutils.ConnStr(t))
	require.NoError(t, err)

	imageName := "MyImageName"
	clientId := "ui"

	err = d.InsertCompose(ctx, uuid.New(), ANR1, EMAIL1, ORGID1, &imageName, []byte("{}"), &clientId, nil)
	require.NoError(t, err)
	err = d.InsertCompose(ctx, uuid.New(), ANR1, EMAIL1, ORGID1, &imageName, []byte("{}"), &clientId, nil)
	require.NoError(t, err)
	err = d.InsertCompose(ctx, uuid.New(), ANR1, EMAIL1, ORGID1, &imageName, []byte("{}"), &clientId, nil)
	require.NoError(t, err)
	err = d.InsertCompose(ctx, uuid.New(), ANR1, EMAIL1, ORGID1, &imageName, []byte("{}"), &clientId, nil)
	require.NoError(t, err)

	// test
	// GetComposes works as expected
	composes, count, err := d.GetComposes(ctx, ORGID1, fortnight, 100, 0, []string{})
	require.NoError(t, err)
	require.Equal(t, 4, count)
	require.Equal(t, 4, len(composes))

	// count returns total in db, ignoring limits
	composes, count, err = d.GetComposes(ctx, ORGID1, fortnight, 1, 2, []string{})
	require.NoError(t, err)
	require.Equal(t, 4, count)
	require.Equal(t, 1, len(composes))

	// GetCompose works as expected
	compose, err := d.GetCompose(ctx, composes[0].Id, ORGID1)
	require.NoError(t, err)
	require.Equal(t, composes[0].Id, compose.Id)

	// cross-account compose access not allowed
	compose, err = d.GetCompose(ctx, composes[0].Id, ORGID2)
	require.Equal(t, db.ErrComposeEntryNotFound, err)
	require.Nil(t, compose)

}

func testCountComposesSince(ctx context.Context, t *testing.T) {
	d, err := db.InitDBConnectionPool(ctx, tutils.ConnStr(t))
	require.NoError(t, err)

	imageName := "MyImageName"

	conn := tutils.Connect(t)
	defer conn.Close(ctx)
	insert := "INSERT INTO composes(job_id, request, created_at, account_number, org_id, image_name) VALUES ($1, $2, CURRENT_TIMESTAMP - interval '2 days', $3, $4, $5)"
	_, err = conn.Exec(ctx, insert, uuid.New().String(), "{}", ANR3, ORGID3, &imageName)
	insert = "INSERT INTO composes(job_id, request, created_at, account_number, org_id, image_name) VALUES ($1, $2, CURRENT_TIMESTAMP - interval '3 days', $3, $4, $5)"
	_, err = conn.Exec(ctx, insert, uuid.New().String(), "{}", ANR3, ORGID3, &imageName)
	insert = "INSERT INTO composes(job_id, request, created_at, account_number, org_id, image_name) VALUES ($1, $2, CURRENT_TIMESTAMP - interval '4 days', $3, $4, $5)"
	_, err = conn.Exec(ctx, insert, uuid.New().String(), "{}", ANR3, ORGID3, &imageName)

	// Verify quering since an interval
	count, err := d.CountComposesSince(ctx, ORGID3, 24*time.Hour)
	require.NoError(t, err)
	require.Equal(t, 0, count)

	count, err = d.CountComposesSince(ctx, ORGID3, 48*time.Hour+time.Second)
	require.NoError(t, err)
	require.Equal(t, 1, count)

	count, err = d.CountComposesSince(ctx, ORGID3, 72*time.Hour+time.Second)
	require.NoError(t, err)
	require.Equal(t, 2, count)

	count, err = d.CountComposesSince(ctx, ORGID3, 96*time.Hour+time.Second)
	require.NoError(t, err)
	require.Equal(t, 3, count)
}

func testCountGetComposesSince(ctx context.Context, t *testing.T) {
	d, err := db.InitDBConnectionPool(ctx, tutils.ConnStr(t))
	require.NoError(t, err)

	conn := tutils.Connect(t)
	defer conn.Close(ctx)

	job1 := uuid.New()
	insert := "INSERT INTO composes(job_id, request, created_at, account_number, org_id) VALUES ($1, $2, CURRENT_TIMESTAMP - interval '2 days', $3, $4)"
	_, err = conn.Exec(ctx, insert, job1, "{}", ANR3, ORGID3)

	composes, count, err := d.GetComposes(ctx, ORGID3, fortnight, 100, 0, []string{})
	require.Equal(t, 1, count)
	require.NoError(t, err)
	require.Equal(t, job1, composes[0].Id)

	job2 := uuid.New()
	insert = "INSERT INTO composes(job_id, request, created_at, account_number, org_id) VALUES ($1, $2, CURRENT_TIMESTAMP - interval '20 days', $3, $4)"
	_, err = conn.Exec(ctx, insert, job2, "{}", ANR3, ORGID3)

	// job2 is outside of time range
	composes, count, err = d.GetComposes(ctx, ORGID3, fortnight, 100, 0, []string{})
	require.Equal(t, 1, count)
	require.NoError(t, err)
	require.Equal(t, job1, composes[0].Id)

	// correct ordering (recent first)
	composes, count, err = d.GetComposes(ctx, ORGID3, fortnight*2, 100, 0, []string{})
	require.Equal(t, 2, count)
	require.NoError(t, err)
	require.Equal(t, job1, composes[0].Id)
}

func testGetComposeImageType(ctx context.Context, t *testing.T) {
	d, err := db.InitDBConnectionPool(ctx, tutils.ConnStr(t))
	require.NoError(t, err)
	conn := tutils.Connect(t)
	defer conn.Close(ctx)

	composeId := uuid.New()
	insert := "INSERT INTO composes(job_id, request, created_at, account_number, org_id) VALUES ($1, $2, CURRENT_TIMESTAMP, $3, $4)"
	_, err = conn.Exec(ctx, insert, composeId, `
{
  "customizations": {
  },
  "distribution": "rhel-8",
  "image_requests": [
    {
      "architecture": "x86_64",
      "image_type": "guest-image",
      "upload_request": {
        "type": "aws.s3",
        "options": {
        }
      }
    }
  ]
}
`, ANR1, ORGID1)
	require.NoError(t, err)

	it, err := d.GetComposeImageType(ctx, composeId, ORGID1)
	require.NoError(t, err)
	require.Equal(t, "guest-image", it)

	_, err = d.GetComposeImageType(ctx, composeId, ORGID2)
	require.Error(t, err)
}

func testDeleteCompose(ctx context.Context, t *testing.T) {
	d, err := db.InitDBConnectionPool(ctx, tutils.ConnStr(t))
	require.NoError(t, err)
	conn := tutils.Connect(t)
	defer conn.Close(ctx)

	composeId := uuid.New()
	insert := "INSERT INTO composes(job_id, request, created_at, account_number, org_id) VALUES ($1, $2, CURRENT_TIMESTAMP, $3, $4)"
	_, err = conn.Exec(ctx, insert, composeId, "{}", ANR1, ORGID1)

	err = d.DeleteCompose(ctx, composeId, ORGID2)
	require.Equal(t, db.ErrComposeEntryNotFound, err)

	err = d.DeleteCompose(ctx, uuid.New(), ORGID1)
	require.Equal(t, db.ErrComposeEntryNotFound, err)

	err = d.DeleteCompose(ctx, composeId, ORGID1)
	require.NoError(t, err)

	_, count, err := d.GetComposes(ctx, ORGID1, fortnight, 100, 0, []string{})
	require.NoError(t, err)
	require.Equal(t, 0, count)

	// delete composes still counts towards quota
	count, err = d.CountComposesSince(ctx, ORGID1, fortnight)
	require.NoError(t, err)
	require.Equal(t, 1, count)
}

func testClones(ctx context.Context, t *testing.T) {
	d, err := db.InitDBConnectionPool(ctx, tutils.ConnStr(t))
	require.NoError(t, err)
	conn := tutils.Connect(t)
	defer conn.Close(ctx)

	composeId := uuid.New()
	cloneId := uuid.New()
	cloneId2 := uuid.New()

	// fkey constraint on compose id
	require.Error(t, d.InsertClone(ctx, composeId, cloneId, []byte(`
{
  "region": "us-east-2"
}
`)))

	require.NoError(t, d.InsertCompose(ctx, composeId, ANR1, EMAIL1, ORGID1, nil, []byte(`
{
  "customizations": {
  },
  "distribution": "rhel-8",
  "image_requests": [
    {
      "architecture": "x86_64",
      "image_type": "guest-image",
      "upload_request": {
        "type": "aws.s3",
        "options": {
        }
      }
    }
  ]
}`), nil, nil))

	require.NoError(t, d.InsertClone(ctx, composeId, cloneId, []byte(`
{
  "region": "us-east-2"
}
`)))
	require.NoError(t, d.InsertClone(ctx, composeId, cloneId2, []byte(`
{
  "region": "eu-central-1"
}
`)))

	clones, count, err := d.GetClonesForCompose(ctx, composeId, ORGID2, 100, 0)
	require.NoError(t, err)
	require.Empty(t, clones)
	require.Equal(t, 0, count)

	clones, count, err = d.GetClonesForCompose(ctx, composeId, ORGID1, 1, 0)
	require.NoError(t, err)
	require.Len(t, clones, 1)
	require.Equal(t, 2, count)
	require.Equal(t, cloneId2, clones[0].Id)

	clones, count, err = d.GetClonesForCompose(ctx, composeId, ORGID1, 100, 0)
	require.NoError(t, err)
	require.Len(t, clones, 2)
	require.Equal(t, 2, count)
	require.Equal(t, cloneId2, clones[0].Id)
	require.Equal(t, cloneId, clones[1].Id)

	entry, err := d.GetClone(ctx, cloneId, ORGID2)
	require.ErrorIs(t, err, db.ErrCloneNotFound)
	require.Nil(t, entry)

	entry, err = d.GetClone(ctx, cloneId, ORGID1)
	require.NoError(t, err)
	require.Equal(t, clones[1], *entry)
}

func testBlueprints(ctx context.Context, t *testing.T) {
	d, err := db.InitDBConnectionPool(ctx, tutils.ConnStr(t))
	require.NoError(t, err)
	conn := tutils.Connect(t)
	defer conn.Close(ctx)

	name1 := "name"
	description1 := "desc"
	body1 := v1.BlueprintBody{
		Customizations: v1.Customizations{},
		Distribution:   "distribution",
		ImageRequests:  []v1.ImageRequest{},
	}
	bodyJson1, err := json.Marshal(body1)
	require.NoError(t, err)

	id := uuid.New()
	versionId := uuid.New()
	err = d.InsertBlueprint(ctx, id, versionId, ORGID1, ANR1, name1, description1, bodyJson1, []byte("{}"), nil)
	require.NoError(t, err)

	entry, err := d.GetBlueprint(ctx, id, ORGID1, nil)
	require.NoError(t, err)
	fromEntry, err := v1.BlueprintFromEntry(entry)
	require.NoError(t, err)
	require.Equal(t, body1, fromEntry)
	require.Equal(t, name1, entry.Name)
	require.Equal(t, description1, entry.Description)
	require.Equal(t, 1, entry.Version)

	entry, err = d.GetBlueprint(ctx, id, ORGID1, common.ToPtr(1))
	require.NoError(t, err)
	fromEntry, err = v1.BlueprintFromEntry(entry)
	require.NoError(t, err)
	require.Equal(t, body1, fromEntry)

	entryByName, err := d.FindBlueprintByName(ctx, ORGID1, name1)
	require.NoError(t, err)
	require.NotNil(t, entryByName)
	require.Equal(t, id, entryByName.Id)

	name2 := "new name"
	description2 := "new desc"
	body2 := v1.BlueprintBody{
		Customizations: v1.Customizations{},
		Distribution:   "distribution of updated body",
		ImageRequests:  []v1.ImageRequest{},
	}
	bodyJson2, err := json.Marshal(body2)
	require.NoError(t, err)

	newVersionId := uuid.New()
	err = d.UpdateBlueprint(ctx, newVersionId, id, ORGID1, name2, description2, bodyJson2, nil)
	require.NoError(t, err)
	entryUpdated, err := d.GetBlueprint(ctx, id, ORGID1, nil)
	require.NoError(t, err)
	bodyFromEntry2, err := v1.BlueprintFromEntry(entryUpdated)
	require.NoError(t, err)
	require.Equal(t, body2, bodyFromEntry2)
	require.Equal(t, 2, entryUpdated.Version)
	require.Equal(t, name2, entryUpdated.Name)
	require.Equal(t, description2, entryUpdated.Description)

	require.NotEqual(t, body1, bodyFromEntry2)

	// Fetch by version = 1
	entryByVersion, err := d.GetBlueprint(ctx, id, ORGID1, common.ToPtr(1))
	require.NoError(t, err)
	bodyFromVersionEntry, err := v1.BlueprintFromEntry(entryByVersion)
	require.NoError(t, err)
	require.Equal(t, body1, bodyFromVersionEntry)
	require.Equal(t, 1, entryByVersion.Version)
	// Fetch by version = 2 (latest)
	entryByVersion, err = d.GetBlueprint(ctx, id, ORGID1, common.ToPtr(2))
	require.NoError(t, err)
	bodyFromVersionEntry, err = v1.BlueprintFromEntry(entryByVersion)
	require.NoError(t, err)
	require.Equal(t, body2, bodyFromVersionEntry)
	require.Equal(t, 2, entryByVersion.Version)

	name3 := "name should not be changed"
	description3 := "desc should not be changed"
	body3 := v1.BlueprintBody{
		Customizations: v1.Customizations{},
		Distribution:   "distribution of third body version",
		ImageRequests:  []v1.ImageRequest{},
	}
	bodyJson3, err := json.Marshal(body3)
	require.NoError(t, err)
	newBlueprintId := uuid.New()
	err = d.UpdateBlueprint(ctx, newBlueprintId, id, ORGID2, name3, description3, bodyJson3, nil)
	require.Error(t, err)
	entryAfterInvalidUpdate, err := d.GetBlueprint(ctx, id, ORGID1, nil)
	require.NoError(t, err)
	bodyFromEntry3, err := v1.BlueprintFromEntry(entryAfterInvalidUpdate)
	require.NoError(t, err)
	require.NotEqual(t, body1, bodyFromEntry3)
	require.Equal(t, body2, bodyFromEntry3)
	require.Equal(t, 2, entryAfterInvalidUpdate.Version)
	require.Equal(t, name2, entryAfterInvalidUpdate.Name)
	require.Equal(t, description2, entryAfterInvalidUpdate.Description)

	newestBlueprintVersionId := uuid.New()
	newestBlueprintId := uuid.New()
	newestBlueprintName := "new name"

	// Fail to insert blueprint with the same name
	err = d.InsertBlueprint(ctx, newestBlueprintId, newestBlueprintVersionId, ORGID1, ANR1, newestBlueprintName, "desc", bodyJson1, []byte("{}"), nil)
	require.Error(t, err)

	newestBlueprintName = "New name 2"
	err = d.InsertBlueprint(ctx, newestBlueprintId, newestBlueprintVersionId, ORGID1, ANR1, newestBlueprintName, "desc", bodyJson1, []byte("{}"), nil)
	require.NoError(t, err)
	entries, bpCount, err := d.GetBlueprints(ctx, ORGID1, 100, 0)
	require.NoError(t, err)
	require.Equal(t, 2, bpCount)
	require.Equal(t, entries[0].Name, newestBlueprintName)
	require.Equal(t, entries[1].Version, 2)

	err = d.InsertBlueprint(ctx, uuid.New(), uuid.New(), ORGID1, ANR1, "unique name", "unique desc", bodyJson1, []byte("{}"), nil)
	entries, count, err := d.FindBlueprints(ctx, ORGID1, "", 100, 0)
	require.NoError(t, err)
	require.Equal(t, 3, count)
	entries, count, err = d.FindBlueprints(ctx, ORGID1, "unique", 100, 0)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.Equal(t, "unique name", entries[0].Name)

	entries, count, err = d.FindBlueprints(ctx, ORGID1, "unique desc", 100, 0)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.Equal(t, "unique desc", entries[0].Description)

	// Insert composes for a blueprint
	clientId := "ui"
	err = d.InsertCompose(ctx, uuid.New(), ANR1, EMAIL1, ORGID1, common.ToPtr("image1"), []byte("{}"), &clientId, &versionId)
	require.NoError(t, err)
	err = d.InsertCompose(ctx, uuid.New(), ANR1, EMAIL1, ORGID1, common.ToPtr("image2"), []byte("{}"), &clientId, &versionId)
	require.NoError(t, err)

	count, err = d.CountBlueprintComposesSince(ctx, ORGID1, id, nil, (time.Hour * 24 * 14), nil)
	require.NoError(t, err)
	require.Equal(t, 2, count)

	err = d.DeleteBlueprint(ctx, id, ORGID1)
	require.NoError(t, err)

	_, count, err = d.GetComposes(ctx, ORGID1, (time.Hour * 24 * 14), 100, 0, nil)
	require.NoError(t, err)
	require.Equal(t, 0, count)
}

func testGetBlueprintComposes(ctx context.Context, t *testing.T) {
	d, err := db.InitDBConnectionPool(ctx, tutils.ConnStr(t))
	require.NoError(t, err)
	conn := tutils.Connect(t)
	defer conn.Close(ctx)

	id := uuid.New()
	versionId := uuid.New()
	body1 := v1.BlueprintBody{
		Distribution: "rhel-8",
		ImageRequests: []v1.ImageRequest{
			{
				Architecture: "x86_64",
				ImageType:    "guest-image",
			},
		},
		Customizations: v1.Customizations{
			Packages: common.ToPtr([]string{"vim", "git"}),
		},
	}
	bodyJson1, err := json.Marshal(body1)
	require.NoError(t, err)

	policyCustomizations1 := &v1.Customizations{
		Packages: &[]string{"vim", "git", "curl", "admin"},
		Hostname: common.ToPtr("rhel8-server"),
	}

	policyCustomizations1JSON, err := json.Marshal(policyCustomizations1)
	require.NoError(t, err)

	serviceSnapshots1 := db.ServiceSnapshots{
		Compliance: &db.ComplianceSnapshot{
			PolicyId:             uuid.New(),
			PolicyCustomizations: policyCustomizations1JSON,
		},
	}
	serviceSnapshotsJson1, err := json.Marshal(serviceSnapshots1)
	require.NoError(t, err)

	err = d.InsertBlueprint(ctx, id, versionId, ORGID1, ANR1, "name", "desc", bodyJson1, []byte("{}"), serviceSnapshotsJson1)
	require.NoError(t, err)

	// get latest version
	version, err := d.GetLatestBlueprintVersionNumber(ctx, ORGID1, id)
	require.NoError(t, err)
	require.Equal(t, 1, version)

	version2Id := uuid.New()

	body2 := v1.BlueprintBody{
		Distribution: "rhel-9",
		ImageRequests: []v1.ImageRequest{
			{
				Architecture: "x86_64",
				ImageType:    "ami",
			},
		},
		Customizations: v1.Customizations{
			Packages: common.ToPtr([]string{"httpd", "vim", "git", "curl"}),
		},
	}
	bodyJson2, err := json.Marshal(body2)
	require.NoError(t, err)

	policyCustomizations2 := &v1.Customizations{
		Packages: &[]string{"httpd", "vim", "git", "curl", "nginx", "firewalld", "webadmin"},
		Hostname: common.ToPtr("rhel9-webserver"),
		Services: &v1.Services{
			Enabled: &[]string{"httpd", "nginx", "firewalld"},
		},
		Timezone: &v1.Timezone{
			Timezone: common.ToPtr("UTC"),
		},
	}

	policyCustomizations2JSON, err := json.Marshal(policyCustomizations2)
	require.NoError(t, err)

	serviceSnapshots2 := db.ServiceSnapshots{
		Compliance: &db.ComplianceSnapshot{
			PolicyId:             uuid.New(),
			PolicyCustomizations: policyCustomizations2JSON,
		},
	}
	serviceSnapshotsJson2, err := json.Marshal(serviceSnapshots2)
	require.NoError(t, err)

	err = d.UpdateBlueprint(ctx, version2Id, id, ORGID1, "name", "desc2", bodyJson2, serviceSnapshotsJson2)
	require.NoError(t, err)

	clientId := "ui"
	composeRequest1 := []byte(`{
		"distribution": "rhel-8",
		"image_requests": [{
			"architecture": "x86_64",
			"image_type": "guest-image",
			"upload_request": {
				"type": "aws.s3",
				"options": {
					"region": "us-east-1"
				}
			}
		}],
		"customizations": {
			"packages": ["vim", "git"],
			"users": [{"name": "testuser", "key": "ssh-rsa AAAAB3..."}]
		}
	}`)

	composeRequest2 := []byte(`{
		"distribution": "rhel-9",
		"image_requests": [{
			"architecture": "aarch64",
			"image_type": "edge-installer",
			"upload_request": {
				"type": "azure.storage",
				"options": {
					"resource_group": "test-rg"
				}
			}
		}],
		"customizations": {
			"services": {"enabled": ["httpd", "nginx"]}
		}
	}`)

	composeRequest3 := []byte(`{
		"distribution": "fedora-38",
		"image_requests": [{
			"architecture": "x86_64",
			"image_type": "qcow2"
		}],
		"customizations": {
			"hostname": "test-host"
		}
	}`)

	composeRequest4 := []byte(`{
		"distribution": "rhel-8",
		"image_requests": [{
			"architecture": "x86_64",
			"image_type": "ami",
			"upload_request": {
				"type": "aws.ec2",
				"options": {
					"region": "us-west-2",
					"instance_type": "t3.micro"
				}
			}
		}]
	}`)

	compose1Id := uuid.New()
	err = d.InsertCompose(ctx, compose1Id, ANR1, EMAIL1, ORGID1, common.ToPtr("rhel8-guest-image"), composeRequest1, &clientId, &versionId)
	require.NoError(t, err)

	compose2Id := uuid.New()
	err = d.InsertCompose(ctx, compose2Id, ANR1, EMAIL1, ORGID1, common.ToPtr("rhel9-edge-installer"), composeRequest2, &clientId, &versionId)
	require.NoError(t, err)

	compose3Id := uuid.New()
	err = d.InsertCompose(ctx, compose3Id, ANR1, EMAIL1, ORGID1, common.ToPtr("fedora38-qcow2"), composeRequest3, &clientId, nil)
	require.NoError(t, err)

	compose4Id := uuid.New()
	err = d.InsertCompose(ctx, compose4Id, ANR1, EMAIL1, ORGID1, common.ToPtr("rhel8-ami"), composeRequest4, &clientId, &version2Id)
	require.NoError(t, err)

	count, err := d.CountBlueprintComposesSince(ctx, ORGID1, id, nil, (time.Hour * 24 * 14), nil)
	require.NoError(t, err)
	require.Equal(t, 3, count)
	entries, err := d.GetBlueprintComposes(ctx, ORGID1, id, nil, (time.Hour * 24 * 14), 10, 0, nil)
	require.NoError(t, err)
	require.Len(t, entries, 3)
	require.Equal(t, "rhel8-ami", *entries[0].ImageName)
	require.Equal(t, "rhel9-edge-installer", *entries[1].ImageName)
	require.Equal(t, "rhel8-guest-image", *entries[2].ImageName)

	var requestData map[string]any
	err = json.Unmarshal(entries[0].Request, &requestData)
	require.NoError(t, err)
	require.Equal(t, "rhel-8", requestData["distribution"])

	// get composes for specific version
	count, err = d.CountBlueprintComposesSince(ctx, ORGID1, id, common.ToPtr(2), (time.Hour * 24 * 14), nil)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	entries, err = d.GetBlueprintComposes(ctx, ORGID1, id, common.ToPtr(2), (time.Hour * 24 * 14), 10, 0, nil)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "rhel8-ami", *entries[0].ImageName)
	require.Equal(t, 2, entries[0].BlueprintVersion)

	// get latest version
	version, err = d.GetLatestBlueprintVersionNumber(ctx, ORGID1, id)
	require.NoError(t, err)
	require.Equal(t, 2, version)

	blueprintEntry, err := d.GetBlueprint(ctx, id, ORGID1, common.ToPtr(2))
	require.NoError(t, err)
	retrievedBlueprint, err := v1.BlueprintFromEntry(blueprintEntry)
	require.NoError(t, err)
	require.Equal(t, v1.Distributions("rhel-9"), retrievedBlueprint.Distribution)

	var retrievedServiceSnapshots db.ServiceSnapshots
	err = json.Unmarshal(blueprintEntry.ServiceSnapshots, &retrievedServiceSnapshots)
	require.NoError(t, err)
	require.NotNil(t, retrievedServiceSnapshots.Compliance)

	var customizations map[string]any
	err = json.Unmarshal(retrievedServiceSnapshots.Compliance.PolicyCustomizations, &customizations)
	require.NoError(t, err)
	require.Contains(t, customizations["hostname"], "rhel9-webserver")
	require.Contains(t, customizations["packages"], "httpd")
	require.Contains(t, customizations["packages"], "webadmin")

	blueprintEntry1, err := d.GetBlueprint(ctx, id, ORGID1, common.ToPtr(1))
	require.NoError(t, err)

	var retrievedServiceSnapshots1 db.ServiceSnapshots
	err = json.Unmarshal(blueprintEntry1.ServiceSnapshots, &retrievedServiceSnapshots1)
	require.NoError(t, err)
	require.NotNil(t, retrievedServiceSnapshots1.Compliance)
	var customizations1 map[string]any
	err = json.Unmarshal(retrievedServiceSnapshots1.Compliance.PolicyCustomizations, &customizations1)
	require.NoError(t, err)
	require.Contains(t, customizations1["hostname"], "rhel8-server")
	require.Contains(t, customizations1["packages"], "admin")
	require.Contains(t, customizations1["packages"], "vim")
}

func TestAll(t *testing.T) {
	ctx := context.Background()
	fns := []func(context.Context, *testing.T){
		testInsertCompose,
		testGetCompose,
		testCountComposesSince,
		testGetComposeImageType,
		testDeleteCompose,
		testClones,
		testBlueprints,
		testGetBlueprintComposes,
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
