# AWS Security Baseline

- `alerting`
    - `org-sec-alerts`
        - Centralized security alerting solution.
        - [Readme](alerting/org-sec-alerts/README.md)
- `billing`
    - `monthly-cost-budget.yaml`
        - Monthly cost budget with alerts. Receive an alert when costs reach your set limit, either actual or forecasted.
- `bin`
    - Shell scripts.
    - [Readme](bin/README.md)
- `cloudformation`
    - `stackset-roles`
        - IAM roles required for deploying CloudFormation StackSets with self-managed permissions
    - `cfn-template-bucket.yaml`
        - S3 bucket for CloudFormation template storage
    - [Readme](cloudformation/README.md)
- `config`
    - `org-config`
        - Organizational AWS Config deployment solution.
        - [Readme](config/org-config/README.md)
    - `org-config-conforms-packs`
        - Organizational AWS Config conformance pack deployment solution
    - `org-config-rules`
        - Organizational AWS Config rule deployment solution
    - [Readme](config/README.md)
- `logging`
    - `org-cloudtrail`
        - AWS CloudTrail organization trail solution.
        - [Readme](logging/org-cloudtrail/README.md)
- `policies`
    - [Readme](policies/README.md)
