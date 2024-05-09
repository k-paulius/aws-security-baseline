#!/usr/bin/env bash

ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)

if [ -z $ACCOUNT_ID ]; then
    exit
fi
ACCOUNT_ALIAS=$(aws iam list-account-aliases --query 'AccountAliases' --output text)
echo "- Operating on account $ACCOUNT_ID | $ACCOUNT_ALIAS."

echo "- Checking if Trusted Access for IAM Access Analyzer is enabled..."
DATE_ENABLED=$(aws organizations list-aws-service-access-for-organization \
                   --query "EnabledServicePrincipals[?ServicePrincipal == 'access-analyzer.amazonaws.com'].DateEnabled" \
                    --output text)

if [ -n "$DATE_ENABLED" ]; then
    echo "- Trusted Access for IAM Access Analyzer was enabled on $DATE_ENABLED."
else
    echo "- Trusted Access for IAM Access Analyzer is not enabled."

    read -p "Do you want to enable Trusted Access for IAM Access Analyzer? [y/N]" -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "- Enabling Trusted Access for IAM Access Analyzer..."
        aws organizations enable-aws-service-access --service-principal access-analyzer.amazonaws.com
        echo "- Done."
    else
        echo "- Exiting."
    fi
fi
