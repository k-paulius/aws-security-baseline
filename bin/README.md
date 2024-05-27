# Scripts

- `enable_delegated_admin_for_access_analyzer.sh`
    - Register a delegated administrator account for AWS IAM Access Analyzer.
    - Usage: `./enable_delegated_admin_for_access_analyzer.sh 123456789012`

- `enable_delegated_admin_for_account_management.sh`
    - Register a delegated administrator account for AWS Account Management.
    - Usage: `./enable_delegated_admin_for_account_management.sh 123456789012`

- `enable_delegated_admin_for_cloudtrail.sh`
    - Register a delegated administrator account for AWS CloudTrail.
    - Usage: `./enable_delegated_admin_for_cloudtrail.sh 123456789012`

- `enable_delegated_admin_for_config.sh`
    - Register a delegated administrator account for AWS Config and/or AWS Config Multi-Account Setup.
    - Usage: `./enable_delegated_admin_for_config.sh 123456789012`

- `enable_delegated_admin_for_security_hub.sh`
    - Designate the Security Hub administrator account for an organization.
        - Also enables AWS Security Hub as a Trusted Service in Organizations.
    - Usage: `./enable_delegated_admin_for_security_hub.sh 123456789012`

- `enable_trusted_access_for_access_analyzer.sh`
    - Enables AWS IAM Access Analyzer as a Trusted Service in Organizations.
    - Usage: `./enable_trusted_access_for_access_analyzer.sh`

- `enable_trusted_access_for_account_management.sh`
    - Enables AWS Account Management as a Trusted Service in Organizations.
    - Usage: `./enable_trusted_access_for_account_management.sh`

- `enable_trusted_access_for_cloudtrail.sh`
    - Enables AWS CloudTrail as a Trusted Service in Organizations.
    - Usage: `./enable_trusted_access_for_cloudtrail.sh`

- `enable_trusted_access_for_config.sh`
    - Enables AWS Config and/or AWS Config Multi-Account Setup as a Trusted Service in Organizations.
    - Usage: `./enable_trusted_access_for_config.sh`

# Secure Defaults Scripts

- `ec2_block_ami_public_access.py`
    - Enable block public access for AMIs across organization accounts and regions.
    - See help for usage information: `./ec2_block_ami_public_access.py --help`

- `ec2_block_ebs_snapshots_public_access.py`
    - Enable block public access for EBS snapshots across organization accounts and regions.
    - See help for usage information: `./ec2_block_ebs_snapshots_public_access.py --help`

- `ec2_default_ebs_encryption.py`
    - Enables default EBS encryption across organization accounts and regions.
    - See help for usage information: `./ec2_default_ebs_encryption.py --help`

- `s3_block_account_public_access.py`
    - Enable account-wide S3 Public Access Block across organization accounts.
    - See help for usage information: `./s3_block_account_public_access.py --help`
