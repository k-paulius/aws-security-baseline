# AWS Policies

## AI services opt-out policies

- `ai-opt-out.yaml`
    - AI services opt-out policy that opt-outs of all AI services

## Chatbot policies

- `chatbot-disable-all-clients.yaml`
    - Chatbot policy that disables all Chatbot clients

## Service control policies (SCPs)

- `deny-iam-user-creation.yaml`
    - Prevent creation of IAM users, access keys or login profiles
- `deny-leave-organization.yaml`
    - Prevent AWS organization member accounts from leaving the organization
- `deny-root-user-actions.yaml`
    - Prevent the root user from performing any actions
    - **Note**: this does not apply to AWS Organization management account root user
- `deny-sts-get-federation-token.yaml`
    - Deny `sts:GetFederationToken` Operation
- `restrict-region-to-us-east-1.yaml`
    - Deny access to all AWS regions except 'us-east-1'

### Prevent resource tampering SCPs

- `prevent-amazon-guardduty-tampering.yaml`
    - Prevent Amazon GuardDuty tampering
- `prevent-aws-access-analyzer-tampering.yaml`
    - Prevent AWS IAM Access Analyzer tampering
- `prevent-aws-config-tampering.yaml`
    - Prevent AWS Config tampering
- `prevent-aws-iam-identity-center-tampering.yaml`
    - Prevent AWS IAM Identity Center tampering
- `prevent-aws-security-hub-tampering.yaml`
    - Prevent AWS Security Hub tampering
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

### AWS IAM Identity Center SCPs

- `prevent-account-instance-creation.yaml`
    - Prevent AWS IAM Identity Center instance level creation
- `prevent-identity-store-access.yaml`
    - Prevent users in member accounts from using API operations in the identity store
