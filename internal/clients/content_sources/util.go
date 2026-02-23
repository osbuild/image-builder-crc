package content_sources

import (
	"context"
	"fmt"
	"net/url"
)

const (
	ExternalOrigin  = "external"
	RedHatOrigin    = "red_hat"
	UploadOrigin    = "upload"
	CommunityOrigin = "community"
)

func EpelURLs() []string {
	return []string{
		"https://dl.fedoraproject.org/pub/epel/10/Everything/x86_64/",
		"https://dl.fedoraproject.org/pub/epel/9/Everything/x86_64/",
		"https://dl.fedoraproject.org/pub/epel/8/Everything/x86_64/",
	}
}

func GetBaseURL(repo ApiRepositoryResponse, csReposURL *url.URL) (string, error) {
	if repo.Origin == nil {
		return "", fmt.Errorf("unable to read origin from repository %s", *repo.Uuid)
	}
	switch *repo.Origin {
	case "upload":
		if csReposURL == nil {
			return "", fmt.Errorf("upload repositories require a content sources URL")
		}
		// Snapshot URLs need to be replaced with the internal mtls URL
		repoURL, err := url.Parse(*repo.LatestSnapshotUrl)
		if err != nil {
			return "", err
		}
		return csReposURL.JoinPath(repoURL.Path).String(), nil
	case "external", "red_hat", "community":
		return *repo.Url, nil
	}
	return "", fmt.Errorf("unknown origin on content sources repository %s, origin: %s", *repo.Uuid, *repo.Origin)
}

func GetCommunityReposByURL(ctx context.Context, csClient ContentSourcesClient) (map[string]ApiRepositoryResponse, error) {
	communityReposByURL := map[string]ApiRepositoryResponse{}
	repos, err := csClient.GetRepositories(ctx, EpelURLs(), []string{}, true)
	if err != nil {
		return map[string]ApiRepositoryResponse{}, err
	}

	for _, v := range repos {
		if v.Url != nil && v.Origin != nil && *v.Origin == CommunityOrigin {
			communityReposByURL[*v.Url] = v
		}
	}

	return communityReposByURL, nil
}
