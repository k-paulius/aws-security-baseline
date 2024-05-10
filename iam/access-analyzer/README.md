# Organizational AWS IAM Access Analyzer Deployment

## Description

This solution deploys AWS IAM Access Analyzer in all existing and future AWS Organization member accounts.

## Deployment

### Step 1: Enable AWS IAM Access Analyzer as a Trusted Service in Organizations

Enable AWS IAM Access Analyzer as a Trusted Service in Organizations.

```bash
./../../bin/enable_trusted_access_for_access_analyzer.sh
```

### Step 2: Register a Delegated Administrator Account

Register the security tooling account as a delegated administrator for AWS IAM Access Analyzer.

```bash
./../../bin/enable_delegated_admin_for_access_analyzer.sh 222222222222
```

### Step 3: Deploy `iam-access-analyzer-deployment.yaml`

Deploy `iam-access-analyzer-deployment.yaml` CloudFormation template. This template deploys all required resources via nested stacks and stacksets. It deploys:
- `iam-access-analyzer-external-access-account.yaml` in every provided region of every organization member account via stackset and organization management account via stackset
- `iam-access-analyzer-external-access-org.yaml` in every provided region of the security tooling account via stackset

#### Step 3a: Create IAM Roles Required for Deploying CloudFormation StackSets with Self-Managed Permissions

In order to deploy CloudFormation StackSets with self-managed permissions, you need to create admin and execution IAM roles.
You can deploy them using `cloudformation/stackset-roles` solution from this project. See [Readme](../../cloudformation/README.md) for more details.

#### Step 3b: Upload Templates to S3 Bucket

Upload all necessary templates to the S3 bucket used for storing CloudFormation templates.

```bash
aws s3 cp . s3://BUCKETNAME \
    --recursive \
    --exclude "*" \
    --include "iam-access-analyzer-*" \
    --exclude "*deployment.yaml"
```

#### Step 3c: Deploy `iam-access-analyzer-deployment.yaml`

```bash
aws cloudformation deploy \
    --template-file iam-access-analyzer-deployment.yaml \
    --stack-name iam-access-analyzer-deployment \
    --parameter-overrides \
        pArtifactBucketName="BUCKETNAME" \
        pDeployTargetOrgUnitId=r-abcd \
        pStackSetAdminRoleName="AWSCloudFormationStackSetAdministrationRole" \
        pStackExecutionRoleName="AWSCloudFormationStackSetExecutionRole" \
        pEnabledRegions="us-east-1,us-west-2" \
        pManagementAccountId=111111111111 \
        pSecurityToolingAccountId=222222222222 \
        pWorkloadIdTag=access-analyzer \
        pEnvironmentIdTag=prod \
        pOwnerNameTag=secops
```

## Deployed Resources

- `iam-access-analyzer-external-access-account.yaml` deploys:
    - `external-access-analyzer-account-${AWS::AccountId}-${AWS::Region}` - External access AWS IAM Access Analyzer (account trust)
- `iam-access-analyzer-external-access-org.yaml` deploys:
    - `external-access-analyzer-org-${AWS::Region}` - External access AWS IAM Access Analyzer (organization trust)
