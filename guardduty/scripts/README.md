# Amazon GuardDuty Related Scripts

## `enable_guardduty_org.py`

### Overview

This script automates the process of enabling Amazon GuardDuty across all accounts and regions within an AWS organization. It supports configuring various GuardDuty protection features and exporting GuardDuty findings to an S3 bucket.

### Script Operation

This script will perform the specified actions in every region enabled in the organization **management account** unless you specify a list of regions using the `--regions` parameter.

- Enable GuardDuty in the organization management account, in case it is not enabled.
- Delegate GuardDuty administration to the account specified in the `--delegated-admin-account` parameter.
- Enable the integration of Malware Protection service with AWS Organizations (Trusted Access for service principal `malware-protection.guardduty.amazonaws.com`).
- Update GuardDuty detector configuration in the delegated GuardDuty administrator account.
- Update GuardDuty organization configuration (auto-enable settings) in the delegated GuardDuty administrator account.
- Configure findings export options (publishing destination) if `--export-s3-arn` and `--export-kms-key-arn` are specified.
- Add every existing organization account as a GuardDuty member account. To override this, specify a custom list of accounts using the `--accounts` parameter.

Notes:
- This script will not remove existing publishing destinations if export options are not provided.
- This script is idempotent.


### Usage

This script must be executed using organization management account credentials. You can optionally specify a profile from your credential file with `--profile` parameter.

---
Enable GuardDuty in every enabled region, delegate administration to account 111111111111 and add all organization accounts as GuardDuty members. This is not going to enable protection plans or configure findings export options.
```bash
./enable_guardduty_org.py \
    --role-name OrganizationAccountAccessRole \
    --delegated-admin-account 111111111111
```

---
Enable GuardDuty in 'us-west-2' region only, delegate administration to account 111111111111 and add accounts 222222222222 and 333333333333 as GuardDuty members. This is not going to enable protection plans or configure findings export options.
```bash
./enable_guardduty_org.py \
    --role-name OrganizationAccountAccessRole \
    --delegated-admin-account 111111111111 \
    --regions us-west-2 \
    --accounts 222222222222 333333333333
```

---
Enable GuardDuty in every enabled region, delegate administration to account 111111111111 and add all organization accounts as GuardDuty members. Enable all protection plans and automated runtime agent configuration. Configure findings export options.
```bash
./enable_guardduty_org.py \
    --role-name OrganizationAccountAccessRole \
    --delegated-admin-account 111111111111 \
    --enable-s3-protection \
    --enable-eks-protection \
    --enable-ec2-malware-protection \
    --enable-rds-protection \
    --enable-lambda-protection \
    --enable-runtime-monitoring \
    --enable-eks-addon-management \
    --enable-ecs-fargate-agent-management \
    --enable-ec2-agent-management \
    --export-frequency ONE_HOUR \
    --export-s3-arn arn:aws:s3:::guardduty-findings \
    --export-kms-key-arn arn:aws:kms:us-east-1:222222222222:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

---
Usage:
```
usage: enable_guardduty_org.py [-h] --role-name ROLE_NAME [--accounts [ACCOUNTS ...]] [--regions [REGIONS ...]] --delegated-admin-account
                               DELEGATED_ADMIN_ACCOUNT [--profile PROFILE] [--debug] [--version] [--auto-enable {ALL,NEW}] [--enable-s3-protection]
                               [--enable-eks-protection] [--enable-ec2-malware-protection] [--enable-rds-protection] [--enable-lambda-protection]
                               [--enable-runtime-monitoring] [--enable-eks-addon-management] [--enable-ecs-fargate-agent-management]
                               [--enable-ec2-agent-management] [--export-frequency {FIFTEEN_MINUTES,ONE_HOUR,SIX_HOURS}] [--export-s3-arn EXPORT_S3_ARN]
                               [--export-kms-key-arn EXPORT_KMS_KEY_ARN]

Enable Amazon GuardDuty for all organization accounts and regions.

options:
  -h, --help            show this help message and exit
  --role-name ROLE_NAME
                        IAM role to assume in every account.
  --accounts [ACCOUNTS ...]
                        List of accounts that will be added as GuardDuty members. By default, all organization accounts are added.
  --regions [REGIONS ...]
                        List of regions to modify. All enabled regions are modified by default.
  --delegated-admin-account DELEGATED_ADMIN_ACCOUNT
                        Account within the organization you want to designate as your GuardDuty delegated administrator.
  --profile PROFILE     Use a specific profile from your credential file. If not given, then the default profile is used.
  --debug               Enable debug logging.
  --version             Print version information and exit.

Protection Plans:
  --auto-enable {ALL,NEW}
                        Auto-enable setting to apply to all protection plans you activate. Defaults to "NEW".
  --enable-s3-protection
                        Enable S3 Protection. Disabled by default.
  --enable-eks-protection
                        Enable EKS Protection. Disabled by default.
  --enable-ec2-malware-protection
                        Enable Malware Protection for EC2. Disabled by default.
  --enable-rds-protection
                        Enable RDS Protection. Disabled by default.
  --enable-lambda-protection
                        Enable Lambda Protection. Disabled by default.
  --enable-runtime-monitoring
                        Enable Runtime Monitoring. Disabled by default.
  --enable-eks-addon-management
                        Enable automated agent configuration for Amazon EKS. Disabled by default.
  --enable-ecs-fargate-agent-management
                        Enable automated agent configuration for AWS Fargate (ECS only). Disabled by default.
  --enable-ec2-agent-management
                        Enable automated agent configuration for Amazon EC2. Disabled by default.

Findings Export Options:
  --export-frequency {FIFTEEN_MINUTES,ONE_HOUR,SIX_HOURS}
                        Frequency to publish updated findings
  --export-s3-arn EXPORT_S3_ARN
                        S3 bucket ARN
  --export-kms-key-arn EXPORT_KMS_KEY_ARN
                        KMS key ARN
```


## `disable_guardduty_org.py`

### Overview

This script disables Amazon GuardDuty across all accounts and regions within an AWS Organization.

### Script Operation

This script will perform the specified actions in every region enabled in the organization **management account** unless you specify a list of regions using the `--regions` parameter.

- Remove a delegated GuardDuty administration account.
- Disable GuardDuty in the organization management account.
- Disable GuardDuty in **all remaining** organization accounts. To override this, specify a custom list of accounts using the `--accounts` parameter.
- Remove a delegated administrator for the GuardDuty service (organization wide `organizations:DeregisterDelegatedAdministrator`).
- Disable GuardDuty integration with AWS Organizations (Trusted Access for service principal `guardduty.amazonaws.com`).
- Disable Malware Protection service integration with AWS Organizations (Trusted Access for service principal `malware-protection.guardduty.amazonaws.com`).

### Usage

This script must be executed using organization management account credentials. You can optionally specify a profile from your credential file with `--profile` parameter.

---
Disable GuardDuty in all enabled regions and organization accounts.
```bash
./disable_guardduty_org.py \
    --role-name OrganizationAccountAccessRole
```

---
Disable GuardDuty only in the specified regions and organization accounts.
```bash
./disable_guardduty_org.py \
    --role-name OrganizationAccountAccessRole \
    --regions us-east-1 us-west-2 \
    --accounts 222222222222 333333333333
```

---
Usage:
```
usage: disable_guardduty_org.py [-h] --role-name ROLE_NAME [--accounts [ACCOUNTS ...]] [--regions [REGIONS ...]] [--profile PROFILE] [--debug] [--version]

Disable Amazon GuardDuty across all organization accounts and regions.

options:
  -h, --help            show this help message and exit
  --role-name ROLE_NAME
                        IAM role to assume in every account.
  --accounts [ACCOUNTS ...]
                        List of account IDs to modify. All organization accounts are modified by default.
  --regions [REGIONS ...]
                        List of regions to modify. All enabled regions are modified by default.
  --profile PROFILE     Use a specific profile from your credential file. If not given, then the default profile is used.
  --debug               Enable debug logging.
  --version             Print version information and exit.
```