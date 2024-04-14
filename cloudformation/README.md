# StackSet Roles

## Description

Creates admin and execution IAM roles required for deploying CloudFormation StackSets with self-managed permissions.
The admin role is only assumable by a CloudFormation principal when the request originates from the designated organization ID, and the resource initiating the request is a StackSet within the same account as the admin role. Additionally, the admin role can only assume execution roles from within the same organization as the source of the request.

## Deployment

This solution can be implemented "manually" by deploying the `cfn-stackset-roles-admin-role.yaml` in the chosen admin account (preferably the Security Tooling (audit) account), and deploying the `cfn-stackset-execution-role.yaml` in each account where StackSet stack instances are intended to be deployed.

Another way to implement this is by utilizing the provided template `cfn-stackset-roles-main.yaml`, which generates a stack for the admin account and a StackSet responsible for deploying the execution role in each account within the organization.
Note: If you intend to create the execution role in the organization's management account, it will need to be deployed separately.

```bash
# deploy admin role
aws cloudformation deploy \
    --template-file cfn-stackset-roles-admin-role.yaml \
    --stack-name cfn-stackset-roles-admin-role \
    --capabilities "CAPABILITY_NAMED_IAM" \
    --parameter-overrides \
        pOrgID="o-abc123def4" \
        pAdminRoleName="AWSCloudFormationStackSetAdministrationRole" \
        pExecutionRoleName="AWSCloudFormationStackSetExecutionRole" \
        pWorkloadIdTag=deployment \
        pEnvironmentIdTag=prod \
        pOwnerNameTag=secops

# deploy execution role
aws cloudformation deploy \
    --template-file cfn-stackset-roles-execution-role.yaml \
    --stack-name cfn-stackset-roles-execution-role \
    --capabilities "CAPABILITY_NAMED_IAM" \
    --parameter-overrides \
        pAdminRoleArn="arn:aws:iam::123456789012:role/AWSCloudFormationStackSetAdministrationRole" \
        pExecutionRoleName="AWSCloudFormationStackSetExecutionRole" \
        pWorkloadIdTag=deployment \
        pEnvironmentIdTag=prod \
        pOwnerNameTag=secops

# deploy admin role stack and execution role StackSet
aws cloudformation deploy \
    --template-file cfn-stackset-roles-main.yaml \
    --stack-name cfn-stackset-roles-main \
    --capabilities "CAPABILITY_NAMED_IAM" \
    --parameter-overrides \
        pArtifactBucketURL="https://BUCKETNAME.s3.amazonaws.com" \
        pDeployTargetOrgUnitId="r-abcd" \
        pOrgID="o-abc123def4" \
        pAdminRoleName="AWSCloudFormationStackSetAdministrationRole" \
        pExecutionRoleName="AWSCloudFormationStackSetExecutionRole" \
        pWorkloadIdTag=deployment \
        pEnvironmentIdTag=prod \
        pOwnerNameTag=secops
```
