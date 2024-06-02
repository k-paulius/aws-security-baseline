# Organizational AWS Security Hub Deployment

## Description

This solution deploys AWS Security Hub using central configuration feature of the Security Hub in all existing and future AWS Organization member accounts.
A Security Hub configuration policy attached to the organization root enables Security Hub solely for aggregating findings, without activating any security standards or controls, and does not require AWS Config to be enabled.

## Notes

- When a configuration policy is associated with an account or organizational unit (OU), it becomes effective in the home region as well as in all linked regions (finding aggregation regions). However, the association of the configuration policy will **fail** if finding aggregation is enabled in an opt-in region that hasn't been enabled or in a region restricted by Service Control Policies (SCPs). In such cases, the policy association status will remain in a `PENDING` state, and CloudFormation will roll back the deployment after the resource creation times out in two hours.

- Associating a configuration policy with the organization management account, either directly or through inheritance, requires Security Hub to be enabled in that account. If Security Hub is not enabled in the management account, the configuration policy association will fail. This solution enables Security Hub in the management account during the deployment.

- Designating a Security Hub administrator account automatically enables Security Hub in that account, which prevents its deployment via CloudFormation due to existing resource limitations. To address this issue, the deployment process involves the following steps:
    - (Explicitly) Enable Security Hub in the Security Hub administrator account.
    - Enable Security Hub in the Security Hub management account.
    - Designate the Security Hub administrator account from the management account.
    - Deploy the Security Hub configuration in the Security Hub administrator account.

- See [Viewing Security Hub configuration policies | AWS Security Hub](https://docs.aws.amazon.com/securityhub/latest/userguide/view-policy.html) for common reasons configuration policy association fails.

## Deployment

### Step 1: Deploy `aws-security-hub-org-deployment.yaml`

Deploy `aws-security-hub-org-deployment.yaml` CloudFormation template in the security tooling account. This template deploys all required resources via nested stacks and StackSets. It deploys:
- `aws-security-hub-org-admin-account-hub.yaml` in the current account and region using a nested stack.
- `aws-security-hub-org-mgmt-account.yaml` in the current region of the organization's management account using StackSet.
- `aws-security-hub-org-admin-account-config.yaml` in the current account and region using a nested stack.
- `aws-security-hub-org-automation-rules.yaml` in all specified regions of the the current account

Parameters:
- `pManagementAccountId`
    - Organization Management Account ID
- `pDelegatedAdminAccountId`
    - Account ID of the account to designate as the Security Hub administrator account
- `pEnabledRegions`
    - Comma-separated list of regions aggregating findings to the home region, excluding the home region (e.g., us-east-1,us-west-2)
- `pRootId`
    - The organization root (e.g., r-abcd)
- `pWorkloadIdTag`
    - Workload Id (value used in the "workload-id" tag)
- `pEnvironmentIdTag`
    - Environment Id (value used in the "environment-id" tag)
- `pOwnerNameTag`
    - Owner Name (value used in the "owner" tag)

#### Step 1a: Upload Templates to an S3 Bucket

Upload all necessary templates to the S3 bucket used for storing CloudFormation templates.

```bash
aws s3 cp . s3://BUCKETNAME \
    --recursive \
    --exclude "*" \
    --include "aws-security-hub-org-*" \
    --exclude "*deployment.yaml"
```

#### Step 1b:  Deploy `aws-security-hub-org-deployment.yaml`

```bash
aws cloudformation deploy \
    --template-file aws-security-hub-org-deployment.yaml \
    --stack-name aws-security-hub-org-deployment \
    --parameter-overrides \
        pArtifactBucketName="BUCKETNAME" \
        pStackSetAdminRoleName="AWSCloudFormationStackSetAdministrationRole" \
        pStackExecutionRoleName="AWSCloudFormationStackSetExecutionRole" \
        pManagementAccountId=111111111111 \
        pDelegatedAdminAccountId=222222222222 \
        pEnabledRegions="us-west-2" \
        pRootId=r-abcd \
        pWorkloadIdTag=aws-security-hub-org \
        pEnvironmentIdTag=prod \
        pOwnerNameTag=secops
```

## Deployed Resources

- `aws-security-hub-org-mgmt-account.yaml`
    - `rSecurityHub`                                           - Security Hub
    - `rDelegatedAdmin`                                        - Security Hub administrator account for an organization
- `aws-security-hub-org-admin-account-hub.yaml`
    - `rSecurityHub`                                           - Security Hub
- `aws-security-hub-org-admin-account-config.yaml`
    - `rFindingAggregator`                                     - Security Hub findings aggregator
    - `rOrganizationConfiguration`                             - Security Hub central configuration
    - `rConfigurationPolicyAggregation`                        - Security Hub configuration policy
    - `rConfigurationPolicyBaseline`                           - Security Hub configuration policy
    - `rConfigurationPolicyDisabled`                           - Security Hub configuration policy
    - `rPolicyAssociation`                                     - Security Hub configuration policy association
- `aws-security-hub-org-automation-rules.yaml`
    - `rAutomationRuleSuppressConfig1`                         - Security Hub automation rule
- `aws-security-hub-org-deployment.yaml` deploys:
    - `aws-security-hub-org-mgmt-account`                      - StackSet for `aws-security-hub-org-mgmt-account.yaml`
    - `rSecurityHubOrgAdminAccountHubStack`                    - Stack for `aws-security-hub-org-admin-account-hub.yaml`
    - `rSecurityHubOrgAdminAccountConfigStack`                 - Stack for `aws-security-hub-org-admin-account-config.yaml`
