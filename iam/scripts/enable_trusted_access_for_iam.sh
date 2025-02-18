#!/usr/bin/env bash

SERVICE_NAME='AWS IAM'
SERVICE_PRINCIPAL='iam.amazonaws.com'
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)

if [ -z $ACCOUNT_ID ]; then
    exit
fi
ACCOUNT_ALIAS=$(aws iam list-account-aliases --query 'AccountAliases' --output text)
echo "- Operating on account $ACCOUNT_ID | $ACCOUNT_ALIAS."

echo "- Checking if Trusted Access for $SERVICE_NAME is enabled..."
DATE_ENABLED=$(aws organizations list-aws-service-access-for-organization \
                   --query "EnabledServicePrincipals[?ServicePrincipal == '$SERVICE_PRINCIPAL'].DateEnabled" \
                    --output text)

if [ -n "$DATE_ENABLED" ]; then
    echo "- Trusted Access for $SERVICE_NAME was enabled on $DATE_ENABLED."
else
    echo "- Trusted Access for $SERVICE_NAME is not enabled."

    read -p "Do you want to enable Trusted Access for $SERVICE_NAME? [y/N]" -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "- Enabling Trusted Access for $SERVICE_NAME..."
        aws organizations enable-aws-service-access --service-principal $SERVICE_PRINCIPAL
        echo "- Done."
    else
        echo "- Exiting."
    fi
fi
