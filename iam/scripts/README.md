# AWS IAM Related Scripts

- `enable_delegated_admin_for_iam.sh`
    - Register a delegated administrator account for AWS IAM.
    - a.k.a.: Delegate administrator for centralized root access
    - Usage: `./enable_delegated_admin_for_iam.sh 123456789012`

- `enable_trusted_access_for_iam.sh`
    - Enables AWS IAM as a Trusted Service in Organizations.
    - a.k.a.: Enable centralized root access for member accounts.
    - Usage: `./enable_trusted_access_for_iam.sh`
