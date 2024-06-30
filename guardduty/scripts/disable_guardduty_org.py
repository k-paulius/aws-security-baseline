#!/usr/bin/env python3

# Copyright (c) 2024 k-paulius
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import argparse
import logging
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

__version__ = '1.0.0'

logger = logging.getLogger(__name__)

GUARDDUTY_SERVICE_PRINCIPAL = 'guardduty.amazonaws.com'
GD_MALWARE_PROTECTION_SERVICE_PRINCIPAL = 'malware-protection.guardduty.amazonaws.com'


def get_active_accounts(session=None, filters=None):
    """
    Retrieves all active AWS organization accounts, optionally filtering by IDs.

    Args:
        session (boto3.Session, optional): A boto3 session object. Defaults to None.
        filters (list[int], optional): A list of account IDs to include. Defaults to None (all active accounts).

    Returns:
        list: A list of dictionaries containing account information.
            Each dictionary has the following format:

            ```
            {
                'Id': 'string',
                'Arn': 'string',
                'Email': 'string',
                'Name': 'string',
                'Status': 'ACTIVE'|'SUSPENDED'|'PENDING_CLOSURE',
                'JoinedMethod': 'INVITED' | 'CREATED',
                'JoinedTimestamp': datetime(year, month, day)
            }
            ```
    """
    if not session:
        session = boto3._get_default_session()
    client = session.client('organizations')
    active_accounts = []
    try:
        paginator = client.get_paginator('list_accounts')

        for page in paginator.paginate():
            for account in page['Accounts']:
                if account['Status'] != 'ACTIVE':
                    continue
                if not filters or int(account['Id']) in filters:
                    active_accounts.append(account)
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            logger.error('ListAccounts operation must be called from an organization management or delegated admin account')
        logger.error(f"{e}")
    return active_accounts


def get_enabled_regions(session=None, filters=None):
    """
    Retrieves all enabled AWS regions in the current account, optionally filtering by region names.

    Args:
        session (boto3.Session, optional): A boto3 session object. Defaults to None.
        filters (list[str], optional): A list of region names to include. Defaults to None (all enabled regions).

    Returns:
        list: A list of enabled region names (strings).
    """
    if not session:
        session = boto3._get_default_session()
    client = session.client('ec2')
    regions = []
    try:
        response = client.describe_regions()

        for region in response['Regions']:
            if not filters or region['RegionName'] in filters:
                regions.append(region['RegionName'])
    except ClientError as e:
        logger.error(f"{e}")
    return regions


def assume_role(account_id, role_name, session_name, session=None):
    """
    Assumes an IAM role and returns a boto3 session object with the temporary credentials.

    Args:
        account_id (str): The ID of the AWS account containing the role.
        role_name (str): The name of the IAM role to assume.
        session_name (str): The desired name for the assumed role session.
        session (boto3.Session, optional): An existing boto3 session object. Defaults to None.

    Returns:
        boto3.Session: A boto3 session object configured with the temporary credentials from the assumed role.
        None: If an error occurs during the assume role operation.
    """
    if not session:
        session = boto3._get_default_session()
    client = session.client('sts')
    try:
        response = client.assume_role(
            RoleArn=f'arn:aws:iam::{account_id}:role/{role_name}',
            RoleSessionName=session_name,
            DurationSeconds=900
        )
        credentials = response['Credentials']
        return boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
    except ClientError as e:
        logger.error(f"{e}")
        return None


def is_org_management_account(session=None):
    """
    Determines if the effective AWS credentials belong to the Organization Management account.

    Args:
        session (boto3.Session, optional): An existing boto3 session object. Defaults to None.

    Returns:
        bool: True if the credentials belong to the Organization Management account, False otherwise.
    """
    if not session:
        session = boto3._get_default_session()
    current_account_id = session.client('sts').get_caller_identity()['Account']
    org_client = session.client('organizations')
    try:
        master_account_id = org_client.describe_organization()['Organization']['MasterAccountId']
        return master_account_id == current_account_id
    except ClientError as e:
        if e.response['Error']['Code'] == 'AWSOrganizationsNotInUseException':
            return False
        raise


def disable_guardduty_delegated_administrator(
    account_id,
    region,
    session=None
):
    if not session:
        session = boto3._get_default_session()
    client = session.client('guardduty', region_name=region)
    try:
        delegated_admins = client.list_organization_admin_accounts()

        if not delegated_admins['AdminAccounts']:
            logger.info(f'{account_id} / {region}: Delegated GuardDuty administrator account was not found')
            return
        admin_account_id = delegated_admins['AdminAccounts'][0]['AdminAccountId']
        client.disable_organization_admin_account(AdminAccountId=admin_account_id)
        logger.info(f'{account_id} / {region}: Delegated GuardDuty administrator account "{admin_account_id}" has been successfully removed')
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            logger.error(f'{account_id} / {region}: (AccessDeniedException) You do not have permission to perform operation "{e.operation_name}"')
        else:
            logger.error(f"{e}")
    return


def disable_guardduty(
    account_id,
    region,
    session=None
):
    if not session:
        session = boto3._get_default_session()
    client = session.client('guardduty', region_name=region)
    try:
        # remove detector
        detectors = client.list_detectors()
        if not detectors['DetectorIds']:
            logger.info(f'{account_id} / {region}: GuardDuty detector was not found')
            return
        detector_id = detectors['DetectorIds'][0]
        client.delete_detector(DetectorId=detector_id)
        logger.info(f'{account_id} / {region}: GuardDuty detector "{detector_id}" has been successfully removed')
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            logger.error(f'{account_id} / {region}: (AccessDeniedException) You do not have permission to perform operation "{e.operation_name}"')
        else:
            logger.error(f"{e}")
    return


def disable_aws_service_access(
    account_id,
    service_principal,
    session=None
):
    if not session:
        session = boto3._get_default_session()
    client = session.client('organizations')
    try:
        client.disable_aws_service_access(ServicePrincipal=service_principal)
        logger.info(f'{account_id}: Trusted organization access for "{service_principal}" has been successfully removed')
    except ClientError as e:
        logger.error(f"{e}")


def parse_args():
    parser = argparse.ArgumentParser(description='Disable Amazon GuardDuty across all organization accounts and regions.')
    parser.add_argument('--role-name', required=True, help='IAM role to assume in every account.')
    parser.add_argument('--accounts', nargs='*', type=int, help='List of account IDs to modify. All organization accounts are modified by default.')
    parser.add_argument('--regions', nargs='*', help='List of regions to modify. All enabled regions are modified by default.')
    parser.add_argument('--profile', help='Use a specific profile from your credential file. If not given, then the default profile is used.')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging.')
    parser.add_argument('--version', action='version', version=f'v{__version__}', help='Print version information and exit.')
    return parser.parse_args()


def main():
    args = parse_args()
    # configure logging
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(levelname)-8s: %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)

    try:
        management_session = boto3.Session(profile_name=args.profile)

        if not is_org_management_account(management_session):
            logger.error('This script requires Organization Management account credentials')
            sys.exit()
        management_account_id = management_session.client('sts').get_caller_identity()['Account']
        regions = get_enabled_regions(management_session, args.regions)

        # GuardDuty is a regional service and needs to be explicitly disabled in every region
        for region in regions:
            logger.info(region.center(40, '-'))

            # disable GuardDuty delegated administrator in the management account
            disable_guardduty_delegated_administrator(
                management_account_id,
                region,
                management_session
            )
            # disable GuardDuty in the management account
            disable_guardduty(
                management_account_id,
                region,
                management_session
            )

            # disable GuardDuty in the remaining organization accounts
            accounts = get_active_accounts(management_session, args.accounts)
            for account in accounts:
                account_id = account["Id"]
                if account_id == management_account_id:
                    continue
                assumed_role_session = assume_role(
                    account_id,
                    args.role_name,
                    'DisableGuardDuty',
                    management_session
                )
                if assumed_role_session is None:
                    logger.error(f'{account_id} / {region}: Failed to assume role. This account will be skipped.')
                    continue
                disable_guardduty(
                    account_id,
                    region,
                    assumed_role_session
                )

        management_org_client = management_session.client('organizations')
        # disable delegated GuardDUty administrators
        delegated_admin = management_org_client.list_delegated_administrators(ServicePrincipal=GUARDDUTY_SERVICE_PRINCIPAL)

        if delegated_admin['DelegatedAdministrators']:
            delegated_admin_id = delegated_admin['DelegatedAdministrators'][0]['Id']
            management_org_client.deregister_delegated_administrator(
                AccountId=delegated_admin_id,
                ServicePrincipal=GUARDDUTY_SERVICE_PRINCIPAL
            )
            logger.info(f'{management_account_id}: Delegated administrator account "{delegated_admin_id}" for service principal "{GUARDDUTY_SERVICE_PRINCIPAL}" has been successfully removed')
        else:
            logger.info(f'{management_account_id}: Delegated administrator account for service principal "{GUARDDUTY_SERVICE_PRINCIPAL}" was not found')

        # disable trusted organization access
        aws_services = management_org_client.list_aws_service_access_for_organization()
        if aws_services['EnabledServicePrincipals']:
            for aws_service in aws_services['EnabledServicePrincipals']:
                if (aws_service['ServicePrincipal'] == GUARDDUTY_SERVICE_PRINCIPAL or
                    aws_service['ServicePrincipal'] == GD_MALWARE_PROTECTION_SERVICE_PRINCIPAL
                ):
                    disable_aws_service_access(
                        management_account_id,
                        aws_service['ServicePrincipal'],
                        management_session
                    )

    except (NoCredentialsError, ProfileNotFound) as e:
        logger.error(e)
    except Exception as e:
        logger.error(e, exc_info=True)
        sys.exit()
    except KeyboardInterrupt as e:
        logger.info('Keyboard Interrupt Received. Exiting...')
        sys.exit(1)
    return

if __name__ == '__main__':
    main()
