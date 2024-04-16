#!/usr/bin/env bash

ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)

if [ -z $ACCOUNT_ID ]; then
    exit
fi
ACCOUNT_ALIAS=$(aws iam list-account-aliases --query 'AccountAliases' --output text)
echo "- Operating on account $ACCOUNT_ID | $ACCOUNT_ALIAS."

echo "- Checking if Trusted Access for AWS Config (config.amazonaws.com) is enabled..."
DATE_ENABLED=$(aws organizations list-aws-service-access-for-organization \
                   --query "EnabledServicePrincipals[?ServicePrincipal == 'config.amazonaws.com'].DateEnabled" \
                    --output text)

if [ -n "$DATE_ENABLED" ]; then
    echo "- Trusted Access for AWS Config (config.amazonaws.com) was enabled on $DATE_ENABLED."
else
    echo "- Trusted Access for AWS Config (config.amazonaws.com) is not enabled."

    read -p "Do you want to enable Trusted Access for AWS Config (config.amazonaws.com)? [y/N]" -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "- Enabling Trusted Access for AWS Config..."
        aws organizations enable-aws-service-access --service-principal config.amazonaws.com
        echo "- Done."
    fi
fi

echo "- Checking if Trusted Access for AWS Config Multi-Account Setup (config-multiaccountsetup.amazonaws.com) is enabled..."
DATE_ENABLED=$(aws organizations list-aws-service-access-for-organization \
                   --query "EnabledServicePrincipals[?ServicePrincipal == 'config-multiaccountsetup.amazonaws.com'].DateEnabled" \
                    --output text)

if [ -n "$DATE_ENABLED" ]; then
    echo "- Trusted Access for AWS Config Multi-Account Setup (config-multiaccountsetup.amazonaws.com) was enabled on $DATE_ENABLED."
else
    echo "- Trusted Access for AWS Config Multi-Account Setup (config-multiaccountsetup.amazonaws.com) is not enabled."

    read -p "Do you want to enable Trusted Access for AWS Config Multi-Account Setup (config-multiaccountsetup.amazonaws.com)? [y/N]" -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "- Enabling Trusted Access for AWS Config Multi-Account Setup..."
        aws organizations enable-aws-service-access --service-principal config-multiaccountsetup.amazonaws.com
        echo "- Done."
    else
        echo "- Exiting."
    fi
fi