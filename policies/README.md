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
