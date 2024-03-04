# AWS Policies

- `ai-opt-out`
    - `ai-opt-out.yaml`
        - AI services opt-out policy that opt-outs of all AI services
- `scp`
    - `deny-leave-organization.yaml`
        - Prevent member accounts from leaving the organization
    - `deny-root-user-actions.yaml`
        - Prevent the root user from performing any actions. Note: this does not apply to AWS Organization management account root user.
    - `restrict-region-to-us-east-1.yaml`
        - deny access to all AWS regions except 'us-east-1'

    - `prevent-resource-tampering`
        - `prevent-cloudtrail-trail-tampering.yaml`
            - Prevent specified CloudTrail trail tampering
        - `prevent-cloudwatch-log-group-tampering.yaml`
            - Prevent specified CloudWatch Logs Log Group tampering
        - `prevent-kms-key-tampering.yaml`
            - Prevent specified KMS key and alias tampering
        - `prevent-s3-bucket-tampering.yaml`
            - Prevent specified S3 bucket and object tampering
        - `prevent-sns-topic-tampering.yaml`
            - Prevent specified SNS Topic tampering
