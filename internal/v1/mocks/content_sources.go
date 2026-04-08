package mocks

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/osbuild/image-builder-crc/internal/clients/content_sources"
	"github.com/osbuild/image-builder-crc/internal/common"
	"github.com/osbuild/image-builder-crc/internal/tutils"
)

const (
	CentosGPG = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v2.0.22 (GNU/Linux)\n\nmQINBFzMWxkBEADHrskpBgN9OphmhRkc7P/YrsAGSvvl7kfu+e9KAaU6f5MeAVyn\nrIoM43syyGkgFyWgjZM8/rur7EMPY2yt+2q/1ZfLVCRn9856JqTIq0XRpDUe4nKQ\n8BlA7wDVZoSDxUZkSuTIyExbDf0cpw89Tcf62Mxmi8jh74vRlPy1PgjWL5494b3X\n5fxDidH4bqPZyxTBqPrUFuo+EfUVEqiGF94Ppq6ZUvrBGOVo1V1+Ifm9CGEK597c\naevcGc1RFlgxIgN84UpuDjPR9/zSndwJ7XsXYvZ6HXcKGagRKsfYDWGPkA5cOL/e\nf+yObOnC43yPUvpggQ4KaNJ6+SMTZOKikM8yciyBwLqwrjo8FlJgkv8Vfag/2UR7\nJINbyqHHoLUhQ2m6HXSwK4YjtwidF9EUkaBZWrrskYR3IRZLXlWqeOi/+ezYOW0m\nvufrkcvsh+TKlVVnuwmEPjJ8mwUSpsLdfPJo1DHsd8FS03SCKPaXFdD7ePfEjiYk\nnHpQaKE01aWVSLUiygn7F7rYemGqV9Vt7tBw5pz0vqSC72a5E3zFzIIuHx6aANry\nGat3aqU3qtBXOrA/dPkX9cWE+UR5wo/A2UdKJZLlGhM2WRJ3ltmGT48V9CeS6N9Y\nm4CKdzvg7EWjlTlFrd/8WJ2KoqOE9leDPeXRPncubJfJ6LLIHyG09h9kKQARAQAB\ntDpDZW50T1MgKENlbnRPUyBPZmZpY2lhbCBTaWduaW5nIEtleSkgPHNlY3VyaXR5\nQGNlbnRvcy5vcmc+iQI3BBMBCAAhAhsDBgsJCAcDAgYVCAIJCgsDFgIBAh4BAheA\nBQJczFsaAAoJEAW1VbOEg8ZdvOgQAMFTGIQokADy5+CynFKjfO7R0VVpJxmYGVr1\nTjnKaHmjxnJaYqoha9ukGgmLu0r+lJ42Kk6nREk1vlxfRAfiWd00Zkm+K3IMq1/D\nE0heC2vX8qqjsLJs3jzq0hgNvo9X0uHDaA4J1BHsD8sE5in/f4SivjbngvFovRGU\n1XLNCgoqpFNcROP18LqKUw8WtqgWdnYBa5i6D5qx+WMRX0NHNwcCMy1lz+sTFxIU\n9mW6cLsMaacPGD8pUXIVli8P9Vlv3jBk1wFIqRgQPW01ph/3bM7pf9hyM9FAfU4X\nAFcyb1oYI4/82EkICUe6jeuZrz67dPeLVAlYrGW4hp/825g0fqJHxPDp25GS4rAa\n4RqyibLzNjSGdXYeLj2NcB/8OqaP+T1hv3JDaqe70QoYa/GIC4rh15NyXVbUP+LG\nV4vUiL7mb9ynzvF5zYHJbcg4R7dOsiZHrMFwy7FZesQaVrXeJlxRcEj65rpm1ZtZ\nmwAE1k2LsRkvLyr9hpZkXnMeOKYIPwpdmBjXNVNVbq7097OxZOYPPos+iZKMWfl4\nUQnMsCVxonZtamdI4qEc3jMkSZPJKgOplGOms5jdY+EdSvsFWEQ0Snd3dChfU7DV\no4Rbcy5klwHrvuZIOLaovhyxuRPhP6gV9+gzpTK/7vrvDlFbbZE6s212mDZ13RWB\nmTfAxz4h\n=agO/\n-----END PGP PUBLIC KEY BLOCK-----\n"
	RhelGPG   = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v2.0.22 (GNU/Linux)\n\nmQINBErgSTsBEACh2A4b0O9t+vzC9VrVtL1AKvUWi9OPCjkvR7Xd8DtJxeeMZ5eF\n0HtzIG58qDRybwUe89FZprB1ffuUKzdE+HcL3FbNWSSOXVjZIersdXyH3NvnLLLF\n0DNRB2ix3bXG9Rh/RXpFsNxDp2CEMdUvbYCzE79K1EnUTVh1L0Of023FtPSZXX0c\nu7Pb5DI5lX5YeoXO6RoodrIGYJsVBQWnrWw4xNTconUfNPk0EGZtEnzvH2zyPoJh\nXGF+Ncu9XwbalnYde10OCvSWAZ5zTCpoLMTvQjWpbCdWXJzCm6G+/hx9upke546H\n5IjtYm4dTIVTnc3wvDiODgBKRzOl9rEOCIgOuGtDxRxcQkjrC+xvg5Vkqn7vBUyW\n9pHedOU+PoF3DGOM+dqv+eNKBvh9YF9ugFAQBkcG7viZgvGEMGGUpzNgN7XnS1gj\n/DPo9mZESOYnKceve2tIC87p2hqjrxOHuI7fkZYeNIcAoa83rBltFXaBDYhWAKS1\nPcXS1/7JzP0ky7d0L6Xbu/If5kqWQpKwUInXtySRkuraVfuK3Bpa+X1XecWi24JY\nHVtlNX025xx1ewVzGNCTlWn1skQN2OOoQTV4C8/qFpTW6DTWYurd4+fE0OJFJZQF\nbuhfXYwmRlVOgN5i77NTIJZJQfYFj38c/Iv5vZBPokO6mffrOTv3MHWVgQARAQAB\ntDNSZWQgSGF0LCBJbmMuIChyZWxlYXNlIGtleSAyKSA8c2VjdXJpdHlAcmVkaGF0\nLmNvbT6JAjYEEwEIACACGwMGCwkIBwMCBBUCCAMEFgIDAQIeAQIXgAUCSuBJPAAK\nCRAZni+R/UMdUfIkD/9m3HWv07uJG26R3KBexTo2FFu3rmZs+m2nfW8R3dBX+k0o\nAOFpgJCsNgKwU81LOPrkMN19G0+Yn/ZTCDD7cIQ7dhYuDyEX97xh4une/EhnnRuh\nASzR+1xYbj/HcYZIL9kbslgpebMn+AhxbUTQF/mziug3hLidR9Bzvygq0Q09E11c\nOZL4BU6J2HqxL+9m2F+tnLdfhL7MsAq9nbmWAOpkbGefc5SXBSq0sWfwoes3X3yD\nQ8B5Xqr9AxABU7oUB+wRqvY69ZCxi/BhuuJCUxY89ZmwXfkVxeHl1tYfROUwOnJO\nGYSbI/o41KBK4DkIiDcT7QqvqvCyudnxZdBjL2QU6OrIJvWmKs319qSF9m3mXRSt\nZzWtB89Pj5LZ6cdtuHvW9GO4qSoBLmAfB313pGkbgi1DE6tqCLHlA0yQ8zv99OWV\ncMDGmS7tVTZqfX1xQJ0N3bNORQNtikJC3G+zBCJzIeZleeDlMDQcww00yWU1oE7/\nTo2UmykMGc7o9iggFWR2g0PIcKsA/SXdRKWPqCHG2uKHBvdRTQGupdXQ1sbV+AHw\nycyA/9H/mp/NUSNM2cqnBDcZ6GhlHt59zWtEveiuU5fpTbp4GVcFXbW8jStj8j8z\n1HI3cywZO8+YNPzqyx0JWsidXGkfzkPHyS4jTG84lfu2JG8m/nqLnRSeKpl20Q==\n=79bX\n-----END PGP PUBLIC KEY BLOCK-----"
)

const (
	RepoBaseID       = "2531793b-c607-4e1c-80b2-fbbaf9d12790"
	RepoAppstrID     = "dbd21dfc-1733-4877-b1c8-8fb5a98beeb4"
	RepoCodeReadyID  = "e2d9e12f-5658-408f-8bfd-5d218919d57e"
	RepoPLID         = "a7ec8864-0e3c-4af2-8c06-567891280af5"
	RepoPLID2        = "c01c2d9c-4624-4558-9ca9-8abcc5eb4437"
	RepoPLID3        = "d064585d-5d25-4e10-88d0-9ab4d192b21d"
	RepoUplID        = "7fa07d5a-3df4-4c83-bfe3-79633a0ad27d"
	RepoSharedEpelID = "5d63ec94-6c45-4e1b-a2e9-9979c1a9d4aa"
	TemplateID       = "267232b1-d5af-467f-b6c0-2b502fa02d3d"
	TemplateID2      = "f3203472-e8ed-4d52-8a98-0e9905e91953"
	TemplateID3      = "71c14af2-2970-4c0d-a60c-a2ab1247cec6"
	SnapshotID       = "6161fd44-ade8-4300-882b-ede6d65ee56e"
	SnapshotID2      = "470f9dfa-10dd-4d70-aacb-96ba9a3d9f06"
	SnapshotBaseID   = "fb1551cc-706d-4fb5-bd14-4a29e7aeef3a"
	SnapshotAppstrID = "f00957e0-0d1d-4777-81a6-9ff072452fb1"
)

func rhRepos(ids []string, urls []string) (res []content_sources.ApiRepositoryResponse) {
	if slices.Contains(urls, "https://cdn.redhat.com/content/dist/rhel9/9/x86_64/baseos/os") || slices.Contains(ids, RepoBaseID) {
		res = append(res, content_sources.ApiRepositoryResponse{
			GpgKey:            common.ToPtr(RhelGPG),
			Uuid:              common.ToPtr(RepoBaseID),
			Url:               common.ToPtr("https://cdn.redhat.com/content/dist/rhel9/9/x86_64/baseos/os"),
			LatestSnapshotUrl: common.ToPtr("http://snappy-url/snappy/baseos"),
			Snapshot:          common.ToPtr(true),
			Name:              common.ToPtr("baseos"),
		})
	}

	if slices.Contains(urls, "https://cdn.redhat.com/content/dist/rhel9/9/x86_64/appstream/os") || slices.Contains(ids, RepoAppstrID) {
		res = append(res, content_sources.ApiRepositoryResponse{
			GpgKey:            common.ToPtr(RhelGPG),
			Uuid:              common.ToPtr(RepoAppstrID),
			Url:               common.ToPtr("https://cdn.redhat.com/content/dist/rhel9/9/x86_64/appstream/os"),
			LatestSnapshotUrl: common.ToPtr("http://snappy-url/snappy/appstream"),
			Snapshot:          common.ToPtr(true),
			Name:              common.ToPtr("appstream"),
		})
	}

	if slices.Contains(urls, "https://cdn.redhat.com/content/dist/rhel8/8/x86_64/baseos/os") {
		res = append(res, content_sources.ApiRepositoryResponse{
			GpgKey:   common.ToPtr(RhelGPG),
			Uuid:     common.ToPtr(RepoBaseID),
			Url:      common.ToPtr("https://cdn.redhat.com/content/dist/rhel8/8/x86_64/baseos/os"),
			Snapshot: common.ToPtr(true),
			Name:     common.ToPtr("baseos"),
		})
	}

	if slices.Contains(urls, "https://cdn.redhat.com/content/dist/rhel8/8/x86_64/appstream/os") {
		res = append(res, content_sources.ApiRepositoryResponse{
			GpgKey:   common.ToPtr(RhelGPG),
			Uuid:     common.ToPtr(RepoAppstrID),
			Url:      common.ToPtr("https://cdn.redhat.com/content/dist/rhel8/8/x86_64/appstream/os"),
			Snapshot: common.ToPtr(true),
			Name:     common.ToPtr("appstream"),
		})
	}

	if slices.Contains(urls, "https://cdn.redhat.com/content/dist/rhel9/9/x86_64/codeready-builder/os/") || slices.Contains(ids, RepoCodeReadyID) {
		res = append(res, content_sources.ApiRepositoryResponse{
			GpgKey:   common.ToPtr(RhelGPG),
			Uuid:     common.ToPtr(RepoCodeReadyID),
			Url:      common.ToPtr("https://cdn.redhat.com/content/dist/rhel9/9/x86_64/codeready-builder/os/"),
			Snapshot: common.ToPtr(true),
			Name:     common.ToPtr("codeready"),
		})
	}

	return res
}

func extRepos(ids []string, urls []string) (res []content_sources.ApiRepositoryResponse) {
	if slices.Contains(urls, "https://some-repo-base-url.org") || slices.Contains(ids, RepoPLID) {
		res = append(res, content_sources.ApiRepositoryResponse{
			GpgKey:   common.ToPtr("some-gpg-key"),
			Uuid:     common.ToPtr(RepoPLID),
			Url:      common.ToPtr("https://some-repo-base-url.org"),
			Snapshot: common.ToPtr(true),
			Name:     common.ToPtr("payload"),
			Origin:   common.ToPtr("external"),
		})
	}

	if slices.Contains(urls, "https://some-repo-base-url2.org") || slices.Contains(ids, RepoPLID2) {
		res = append(res, content_sources.ApiRepositoryResponse{
			Uuid:     common.ToPtr(RepoPLID2),
			Url:      common.ToPtr("https://some-repo-base-url2.org"),
			Snapshot: common.ToPtr(true),
			Name:     common.ToPtr("payload2"),
			Origin:   common.ToPtr("external"),
		})
	}

	if slices.Contains(urls, "https://some-repo-base-url3.org") || slices.Contains(ids, RepoPLID3) {
		res = append(res, content_sources.ApiRepositoryResponse{
			GpgKey:   common.ToPtr(""),
			Uuid:     common.ToPtr(RepoPLID3),
			Url:      common.ToPtr("https://some-repo-base-url3.org"),
			Snapshot: common.ToPtr(true),
			Name:     common.ToPtr("payload3"),
			Origin:   common.ToPtr("external"),
		})
	}

	return res
}

func uploadRepos(ids []string, urls []string) (res []content_sources.ApiRepositoryResponse) {
	if slices.Contains(urls, "https://upload-latest-snapshot-url.org") || slices.Contains(ids, RepoUplID) {
		// upload repositories have an empty URL
		res = append(res, content_sources.ApiRepositoryResponse{
			GpgKey:            common.ToPtr("some-gpg-key"),
			Uuid:              common.ToPtr(RepoUplID),
			Url:               common.ToPtr(""),
			LatestSnapshotUrl: common.ToPtr("https://upload-latest-snapshot-url.org"),
			Snapshot:          common.ToPtr(true),
			Name:              common.ToPtr("upload"),
			Origin:            common.ToPtr("upload"),
		})
	}
	return res
}

func communityRepos(ids []string, urls []string) (res []content_sources.ApiRepositoryResponse) {
	if slices.Contains(urls, "https://dl.fedoraproject.org/pub/epel/10/Everything/x86_64/") || slices.Contains(ids, RepoSharedEpelID) {
		res = append(res, content_sources.ApiRepositoryResponse{
			GpgKey:   common.ToPtr("some-epel-gpg-key"),
			Uuid:     common.ToPtr(RepoSharedEpelID),
			Url:      common.ToPtr("https://dl.fedoraproject.org/pub/epel/10/Everything/x86_64/"),
			Snapshot: common.ToPtr(true),
			Name:     common.ToPtr("epel10"),
			Origin:   common.ToPtr("community"),
		})
	}
	return res
}

func snapsWithOsVersion(uuids []string, detectedOsVersion *string) (res []content_sources.ApiSnapshotForDate) {
	if slices.Contains(uuids, RepoBaseID) {
		snap := content_sources.ApiSnapshotForDate{
			IsAfter: common.ToPtr(false),
			Match: &content_sources.ApiSnapshotResponse{
				CreatedAt:         common.ToPtr("1998-01-30T00:00:00Z"),
				RepositoryPath:    common.ToPtr("/snappy/baseos"),
				Url:               common.ToPtr("http://snappy-url/snappy/baseos"),
				DetectedOsVersion: detectedOsVersion,
			},
			RepositoryUuid: common.ToPtr(RepoBaseID),
		}
		res = append(res, snap)
	}

	if slices.Contains(uuids, RepoAppstrID) {
		res = append(res, content_sources.ApiSnapshotForDate{
			IsAfter: common.ToPtr(false),
			Match: &content_sources.ApiSnapshotResponse{
				CreatedAt:      common.ToPtr("1998-01-30T00:00:00Z"),
				RepositoryPath: common.ToPtr("/snappy/appstream"),
				Url:            common.ToPtr("http://snappy-url/snappy/appstream"),
			},
			RepositoryUuid: common.ToPtr(RepoAppstrID),
		})
	}

	if slices.Contains(uuids, RepoPLID) {
		res = append(res, content_sources.ApiSnapshotForDate{
			IsAfter: common.ToPtr(false),
			Match: &content_sources.ApiSnapshotResponse{
				CreatedAt:      common.ToPtr("1998-01-30T00:00:00Z"),
				RepositoryPath: common.ToPtr("/snappy/payload"),
				Url:            common.ToPtr("http://snappy-url/snappy/payload"),
			},
			RepositoryUuid: common.ToPtr(RepoPLID),
		})
	}

	if slices.Contains(uuids, RepoPLID2) {
		res = append(res, content_sources.ApiSnapshotForDate{
			IsAfter: common.ToPtr(false),
			Match: &content_sources.ApiSnapshotResponse{
				CreatedAt:      common.ToPtr("1998-01-30T00:00:00Z"),
				RepositoryPath: common.ToPtr("/snappy/payload2"),
				Url:            common.ToPtr("http://snappy-url/snappy/payload2"),
			},
			RepositoryUuid: common.ToPtr(RepoPLID2),
		})
	}

	if slices.Contains(uuids, RepoPLID3) {
		res = append(res, content_sources.ApiSnapshotForDate{
			IsAfter: common.ToPtr(false),
			Match: &content_sources.ApiSnapshotResponse{
				CreatedAt:      common.ToPtr("1998-01-30T00:00:00Z"),
				RepositoryPath: common.ToPtr("/snappy/payload3"),
				Url:            common.ToPtr("http://snappy-url/snappy/payload3"),
			},
			RepositoryUuid: common.ToPtr(RepoPLID3),
		})
	}

	if slices.Contains(uuids, RepoSharedEpelID) {
		res = append(res, content_sources.ApiSnapshotForDate{
			IsAfter: common.ToPtr(false),
			Match: &content_sources.ApiSnapshotResponse{
				CreatedAt:      common.ToPtr("1998-01-30T00:00:00Z"),
				RepositoryPath: common.ToPtr("/snappy/epel10"),
				Url:            common.ToPtr("http://snappy-url/snappy/epel10"),
			},
			RepositoryUuid: common.ToPtr(RepoSharedEpelID),
		})
	}

	if slices.Contains(uuids, RepoCodeReadyID) {
		res = append(res, content_sources.ApiSnapshotForDate{
			IsAfter: common.ToPtr(false),
			Match: &content_sources.ApiSnapshotResponse{
				CreatedAt:      common.ToPtr("1998-01-30T00:00:00Z"),
				RepositoryPath: common.ToPtr("/snappy/codeready"),
				Url:            common.ToPtr("http://snappy-url/snappy/codeready"),
			},
			RepositoryUuid: common.ToPtr(RepoCodeReadyID),
		})
	}
	return res
}

func exports(uuids []string) (res []content_sources.ApiRepositoryExportResponse) {
	if slices.Contains(uuids, RepoBaseID) {
		res = append(res, content_sources.ApiRepositoryExportResponse{
			GpgKey: common.ToPtr(RhelGPG),
			Name:   common.ToPtr("baseos"),
			Url:    common.ToPtr("http://snappy-url/snappy/baseos"),
		})
	}
	if slices.Contains(uuids, RepoAppstrID) {
		res = append(res, content_sources.ApiRepositoryExportResponse{
			GpgKey: common.ToPtr(RhelGPG),
			Name:   common.ToPtr("appstream"),
			Url:    common.ToPtr("http://snappy-url/snappy/appstream"),
		})
	}
	if slices.Contains(uuids, RepoPLID) {
		res = append(res, content_sources.ApiRepositoryExportResponse{
			GpgKey: common.ToPtr("some-gpg-key"),
			Name:   common.ToPtr("payload"),
			Url:    common.ToPtr("http://snappy-url/snappy/payload"),
		})
	}
	if slices.Contains(uuids, RepoPLID2) {
		res = append(res, content_sources.ApiRepositoryExportResponse{
			GpgKey: common.ToPtr("some-gpg-key"),
			Name:   common.ToPtr("payload2"),
			Url:    common.ToPtr("http://snappy-url/snappy/payload2"),
		})
	}
	if slices.Contains(uuids, RepoPLID3) {
		res = append(res, content_sources.ApiRepositoryExportResponse{
			GpgKey: common.ToPtr(""),
			Name:   common.ToPtr("payload3"),
			Url:    common.ToPtr("http://snappy-url/snappy/payload3"),
		})
	}
	if slices.Contains(uuids, RepoSharedEpelID) {
		res = append(res, content_sources.ApiRepositoryExportResponse{
			GpgKey: common.ToPtr("some-epel-gpg-key"),
			Name:   common.ToPtr("epel10"),
			Url:    common.ToPtr("https://dl.fedoraproject.org/pub/epel/10/Everything/x86_64/"),
		})
	}
	return res
}

func templateByID(uuid string) (res content_sources.ApiTemplateResponse) {
	if uuid == TemplateID {
		res = content_sources.ApiTemplateResponse{
			Uuid:            common.ToPtr(uuid),
			Name:            common.ToPtr("template1"),
			RepositoryUuids: common.ToPtr([]string{RepoBaseID, RepoAppstrID, RepoPLID}),
			Date:            common.ToPtr("2000-01-30T00:00:00Z"),
			Snapshots: &[]content_sources.ApiSnapshotResponse{
				{
					Uuid:           common.ToPtr(SnapshotID),
					RepositoryUuid: common.ToPtr(RepoPLID),
					RepositoryPath: common.ToPtr("/template/snapshot1"),
					Url:            common.ToPtr("http://snappy-url/template/snapshot1"),
				},
				{
					Uuid:           common.ToPtr(SnapshotBaseID),
					RepositoryUuid: common.ToPtr(RepoBaseID),
					RepositoryPath: common.ToPtr("/template/snapshot1/base"),
					Url:            common.ToPtr("http://snappy-url/snappy/baseos"),
				},
				{
					Uuid:           common.ToPtr(SnapshotAppstrID),
					RepositoryUuid: common.ToPtr(RepoAppstrID),
					RepositoryPath: common.ToPtr("/template/snapshot1/appstream"),
					Url:            common.ToPtr("http://snappy-url/snappy/appstream"),
				},
			},
		}
	} else if uuid == TemplateID2 {
		res = content_sources.ApiTemplateResponse{
			Uuid:            common.ToPtr(uuid),
			Name:            common.ToPtr("template2"),
			RepositoryUuids: common.ToPtr([]string{RepoBaseID, RepoAppstrID, RepoPLID, RepoPLID2}),
			Date:            common.ToPtr("2000-01-30T00:00:00Z"),
			Snapshots: &[]content_sources.ApiSnapshotResponse{
				{
					Uuid:           common.ToPtr(SnapshotID),
					RepositoryUuid: common.ToPtr(RepoPLID),
					RepositoryPath: common.ToPtr("/template/snapshot1"),
					Url:            common.ToPtr("http://snappy-url/template/snapshot1"),
				},
				{
					Uuid:           common.ToPtr(SnapshotID2),
					RepositoryUuid: common.ToPtr(RepoPLID2),
					RepositoryPath: common.ToPtr("/template/snapshot2"),
					Url:            common.ToPtr("http://snappy-url/template/snapshot2"),
				},
				{
					Uuid:           common.ToPtr(SnapshotBaseID),
					RepositoryUuid: common.ToPtr(RepoBaseID),
					RepositoryPath: common.ToPtr("/template/snapshot2/base"),
					Url:            common.ToPtr("http://snappy-url/snappy/baseos"),
				},
				{
					Uuid:           common.ToPtr(SnapshotAppstrID),
					RepositoryUuid: common.ToPtr(RepoAppstrID),
					RepositoryPath: common.ToPtr("/template/snapshot2/appstream"),
					Url:            common.ToPtr("http://snappy-url/snappy/appstream"),
				},
			},
		}
	} else if uuid == TemplateID3 {
		res = content_sources.ApiTemplateResponse{
			Uuid:            common.ToPtr(uuid),
			Name:            common.ToPtr("template3"),
			RepositoryUuids: common.ToPtr([]string{RepoBaseID, RepoAppstrID}),
			Date:            common.ToPtr("2000-01-30T00:00:00Z"),
			Snapshots: &[]content_sources.ApiSnapshotResponse{
				{
					Uuid:           common.ToPtr(SnapshotBaseID),
					RepositoryUuid: common.ToPtr(RepoBaseID),
					RepositoryPath: common.ToPtr("/template/snapshot2/base"),
					Url:            common.ToPtr("http://snappy-url/snappy/baseos"),
				},
				{
					Uuid:           common.ToPtr(SnapshotAppstrID),
					RepositoryUuid: common.ToPtr(RepoAppstrID),
					RepositoryPath: common.ToPtr("/template/snapshot2/appstream"),
					Url:            common.ToPtr("http://snappy-url/snappy/appstream"),
				},
			},
		}
	}

	return res
}

func ContentSources(w http.ResponseWriter, r *http.Request) {
	contentSourcesHandler(nil)(w, r)
}

// ContentSourcesWithOsVersion returns a handler identical to ContentSources but
// embeds the given detectedOsVersion in every snapshot-for-date response.
// Pass a non-nil string to simulate content-sources reporting a specific OS
// minor version (e.g. "9.4") for an older snapshot date.
func ContentSourcesWithOsVersion(detectedOsVersion *string) http.HandlerFunc {
	return contentSourcesHandler(detectedOsVersion)
}

func contentSourcesHandler(detectedOsVersion *string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if tutils.AuthString0 != r.Header.Get("x-rh-identity") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repositories/":
			urlForm := r.URL.Query().Get("url")
			urls := strings.Split(urlForm, ",")

			idForm := r.URL.Query().Get("uuid")
			ids := strings.Split(idForm, ",")

			repos := []content_sources.ApiRepositoryResponse{}
			switch r.URL.Query().Get("origin") {
			case "red_hat":
				repos = append(repos, rhRepos(ids, urls)...)
			case "external,upload,community":
				repos = append(repos, extRepos(ids, urls)...)
				repos = append(repos, uploadRepos(ids, urls)...)
				repos = append(repos, communityRepos(ids, urls)...)
			}
			err := json.NewEncoder(w).Encode(content_sources.ApiRepositoryCollectionResponse{
				Data: &repos,
			})
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		case "/snapshots/for_date/":
			var body content_sources.ApiListSnapshotByDateRequest
			err := json.NewDecoder(r.Body).Decode(&body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if body.Date != "1999-01-30T00:00:00Z" {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			err = json.NewEncoder(w).Encode(content_sources.ApiListSnapshotByDateResponse{
				Data: common.ToPtr(snapsWithOsVersion(body.RepositoryUuids, detectedOsVersion)),
			})
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		case "/repositories/bulk_export/":
			var body content_sources.ApiRepositoryExportRequest
			err := json.NewDecoder(r.Body).Decode(&body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			err = json.NewEncoder(w).Encode(exports(body.RepositoryUuids))
			if err != nil {
				w.WriteHeader(http.StatusInsufficientStorage)
				return
			}
		}

		if strings.HasPrefix(r.URL.Path, "/templates/") {
			pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/templates/"), "/")
			if len(pathParts) == 1 {
				uuid := pathParts[0]
				err := json.NewEncoder(w).Encode(templateByID(uuid))
				if err != nil {
					w.WriteHeader(http.StatusInsufficientStorage)
				}
				return
			}
		}
	}
}
