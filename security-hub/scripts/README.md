# AWS Security Hub Related Scripts

## `enable_delegated_admin_for_security_hub.sh`

- Designate the Security Hub administrator account for an organization.
    - Also enables AWS Security Hub as a Trusted Service in Organizations.
- Usage: `./enable_delegated_admin_for_security_hub.sh 123456789012`

## `disable_securityhub_org.py`

### Overview

This script disables AWS Security Hub across **ALL** accounts and regions within an AWS Organization. It is a **"nuclear"** option, use it at your own discretion.

### Script Operation

Security Hub can be enabled in an account through various methods. This script will attempt to identify and disable Security Hub across all organization accounts and regions, regardless of how it was initially enabled.

If you encounter the error `Member account cannot disable Security Hub. PLEASE RERUN THIS SCRIPT ONCE IT COMPLETES.` for any account, you will need to run this script a second time.

### Usage

This script must be executed using organization management account credentials. You can optionally specify a profile from your credential file with `--profile` parameter.

---
Disable Security Hub in all enabled regions and organization accounts.
```bash
 ./disable_securityhub_org.py \
    --role-name OrganizationAccountAccessRole
```

---
Usage:
```
usage: disable_securityhub_org.py [-h] --role-name ROLE_NAME [--profile PROFILE] [--debug] [--version]

Disable AWS Security Hub across all organization accounts and regions.

options:
  -h, --help            show this help message and exit
  --role-name ROLE_NAME IAM role to assume in every account.
  --profile PROFILE     Use a specific profile from your credential file. If not given, then the default profile is used.
  --debug               Enable debug logging.
  --version             Print version information and exit.
```
