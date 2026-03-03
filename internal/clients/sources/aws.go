package sources

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// AWSAccountIDResolver resolves an IAM role ARN to a 12-digit AWS account ID
// using STS AssumeRole followed by GetCallerIdentity.
type AWSAccountIDResolver struct {
	accessKeyID string
	secretKey   string
	region      string
}

func NewAWSAccountIDResolver(accessKeyID, secretKey, region string) (*AWSAccountIDResolver, error) {
	if region == "" {
		region = "us-east-1"
	}
	return &AWSAccountIDResolver{
		accessKeyID: accessKeyID,
		secretKey:   secretKey,
		region:      region,
	}, nil
}

// ResolveAccountID assumes the given IAM role ARN using the service account credentials,
// then calls GetCallerIdentity with the assumed credentials to retrieve the account ID.
func (r *AWSAccountIDResolver) ResolveAccountID(ctx context.Context, arn string) (string, error) {
	serviceCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(r.region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(r.accessKeyID, r.secretKey, "")),
	)
	if err != nil {
		return "", fmt.Errorf("unable to load AWS config: %w", err)
	}

	stsClient := sts.NewFromConfig(serviceCfg)
	assumeOutput, err := stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(arn),
		RoleSessionName: aws.String("image-builder-sources"),
	})
	if err != nil {
		return "", fmt.Errorf("unable to assume role %s: %w", arn, err)
	}

	assumedCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(r.region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			*assumeOutput.Credentials.AccessKeyId,
			*assumeOutput.Credentials.SecretAccessKey,
			*assumeOutput.Credentials.SessionToken,
		)),
	)
	if err != nil {
		return "", fmt.Errorf("unable to load assumed AWS config: %w", err)
	}

	assumedStsClient := sts.NewFromConfig(assumedCfg)
	identityOutput, err := assumedStsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("unable to get caller identity: %w", err)
	}

	return *identityOutput.Account, nil
}
