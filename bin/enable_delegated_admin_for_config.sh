#!/usr/bin/env bash

DEL_ADMIN_ACCOUNT_ID=$1

if [ -z $DEL_ADMIN_ACCOUNT_ID ]; then
    echo "ERROR: No delegated administrator account ID argument supplied."
	echo "Usage: $0 <delegated_admin_account_id>"
	exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)

if [ -z $ACCOUNT_ID ]; then
    exit
fi
ACCOUNT_ALIAS=$(aws iam list-account-aliases --query 'AccountAliases' --output text)
echo "- Operating on account $ACCOUNT_ID | $ACCOUNT_ALIAS."

echo "- Checking if account $DEL_ADMIN_ACCOUNT_ID is already registered as a delegated administrator for AWS Config..."
DELEGATION_DATE=$(aws organizations list-delegated-administrators \
                      --service-principal 'config.amazonaws.com' \
                      --query "DelegatedAdministrators[?Id == '$DEL_ADMIN_ACCOUNT_ID'].DelegationEnabledDate" \
                      --output text)

if [ -n "$DELEGATION_DATE" ]; then
    echo "- Account $DEL_ADMIN_ACCOUNT_ID is already registered as a delegated administrator since $DELEGATION_DATE."
else
    echo "- Account $DEL_ADMIN_ACCOUNT_ID is not registered as a delegated administrator."

    read -p "Do you want to register account $DEL_ADMIN_ACCOUNT_ID as a delegated administrator for AWS Config? [y/N]" -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "- Registering account $DEL_ADMIN_ACCOUNT_ID as a delegated administrator for AWS Config..."
        aws organizations register-delegated-administrator \
            --account-id $DEL_ADMIN_ACCOUNT_ID \
            --service-principal 'config.amazonaws.com'
        echo "- Done."
    fi
fi

echo "- Checking if account $DEL_ADMIN_ACCOUNT_ID is already registered as a delegated administrator for AWS Config Multi-Account Setup..."
DELEGATION_DATE=$(aws organizations list-delegated-administrators \
                      --service-principal 'config-multiaccountsetup.amazonaws.com' \
                      --query "DelegatedAdministrators[?Id == '$DEL_ADMIN_ACCOUNT_ID'].DelegationEnabledDate" \
                      --output text)

if [ -n "$DELEGATION_DATE" ]; then
    echo "- Account $DEL_ADMIN_ACCOUNT_ID is already registered as a delegated administrator since $DELEGATION_DATE."
else
    echo "- Account $DEL_ADMIN_ACCOUNT_ID is not registered as a delegated administrator."

    read -p "Do you want to register account $DEL_ADMIN_ACCOUNT_ID as a delegated administrator for AWS Config Multi-Account Setup? [y/N]" -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "- Registering account $DEL_ADMIN_ACCOUNT_ID as a delegated administrator for AWS Config Multi-Account Setup..."
        aws organizations register-delegated-administrator \
            --account-id $DEL_ADMIN_ACCOUNT_ID \
            --service-principal 'config-multiaccountsetup.amazonaws.com'
        echo "- Done."
    else
        echo "- Exiting."
    fi
fi