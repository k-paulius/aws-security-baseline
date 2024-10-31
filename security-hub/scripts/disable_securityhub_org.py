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

SECURITY_HUB_SERVICE_PRINCIPAL = 'securityhub.amazonaws.com'


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


def disable_security_hub_administrator_account(
    account_id,
    region,
    session=None
):
    if not session:
        session = boto3._get_default_session()

    client = session.client('securityhub', region_name=region)

    try:
        #
        # Disassociate Configuration Policies
        #
        try:
            policy_associations = client.list_configuration_policy_associations(
                Filters={'AssociationType': 'APPLIED'}
            )
            if policy_associations['ConfigurationPolicyAssociationSummaries']:
                for policy_association in policy_associations['ConfigurationPolicyAssociationSummaries']:
                    target_type = policy_association['TargetType']
                    target_keys = {
                        'ACCOUNT': 'AccountId',
                        'ORGANIZATIONAL_UNIT': 'OrganizationalUnitId',
                        'ROOT': 'RootId'
                    }
                    target_key = target_keys.get(target_type)

                    if target_key:
                        client.start_configuration_policy_disassociation(
                            Target = {target_key: policy_association['TargetId']},
                            ConfigurationPolicyIdentifier = policy_association['ConfigurationPolicyId']
                        )
                        logger.info(f'{account_id} / {region}: Started configuration policy disassociation. Target: {policy_association['TargetId']}, PolicyId: {policy_association['ConfigurationPolicyId']}')
                    else:
                        logger.error(f'{account_id} / {region}: Unknown TargetType: {target_type}')
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDeniedException':
                pass
            else:
                raise

        #
        # Delete Configuration Policies
        #
        try:
            policies = client.list_configuration_policies()

            if policies['ConfigurationPolicySummaries']:
                for policy in policies['ConfigurationPolicySummaries']:
                    client.delete_configuration_policy(Identifier=policy['Id'])
                    logger.info(f'{account_id} / {region}: Configuration policy "{policy['Name']}" has been successfully removed')
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDeniedException':
                pass
            else:
                raise

        #
        # Switch from Central Configuration to Local Configuration
        #
        org_config = client.describe_organization_configuration()

        if org_config['OrganizationConfiguration']['ConfigurationType'] == 'CENTRAL':
            client.update_organization_configuration(
                AutoEnable = False,
                AutoEnableStandards = 'NONE',
                OrganizationConfiguration = {'ConfigurationType': 'LOCAL'}
            )
            logger.info(f'{account_id} / {region}: Central configuration has been successfully switched to local configuration')

        #
        # Delete Member Accounts
        #
        members = client.list_members(OnlyAssociated=True)

        if members['Members']:
            member_list = [member['AccountId'] for member in members['Members']]
            client.disassociate_members(AccountIds=member_list)
            logger.info(f'{account_id} / {region}: Member accounts have been successfully disassociated: {member_list}')

        #
        # Disable Cross-Region aggregation
        #
        aggregators = client.list_finding_aggregators()
        if aggregators['FindingAggregators']:
            client.delete_finding_aggregator(FindingAggregatorArn=aggregators['FindingAggregators'][0]['FindingAggregatorArn'])
            logger.info(f'{account_id} / {region}: Finding Aggregator has been successfully removed')

        logger.info(f'{account_id} / {region}: Security Hub Administrator Account Configuration has been successfully removed')
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            logger.error(f'{account_id} / {region}: (AccessDeniedException) You do not have permission to perform operation "{e.operation_name}"')
        else:
            logger.error(f"{e}")
    return


def disable_security_hub(
    account_id,
    region,
    session=None
):
    if not session:
        session = boto3._get_default_session()

    client = session.client('securityhub', region_name=region)

    try:
        hub = client.describe_hub()
        if not hub['HubArn']:
            logger.info(f'{account_id} / {region}: Security Hub is not enabled')
            return

        # Delete Member Accounts
        members = client.list_members(OnlyAssociated=True)

        if members['Members']:
            member_list = [member['AccountId'] for member in members['Members']]
            client.disassociate_members(AccountIds=member_list)
            logger.info(f'{account_id} / {region}: Member accounts have been successfully disassociated: {member_list}')

        # Disable Security Hub
        client.disable_security_hub()
        logger.info(f'{account_id} / {region}: Security Hub has been successfully disabled')

    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            logger.error(f'{account_id} / {region}: (AccessDeniedException) You do not have permission to perform operation "{e.operation_name}"')
        elif e.response['Error']['Code'] == 'InvalidAccessException':
            # Account 123456789012 is not subscribed to AWS Security Hub
            logger.info(f'{account_id} / {region}: {e.response['Error']['Message']}')
        elif e.response['Error']['Code'] == 'InvalidInputException':
            # Member account cannot disable Security Hub
            logger.error(f'{account_id} / {region}: {e.response['Error']['Message']}. PLEASE RERUN THIS SCRIPT ONCE IT COMPLETES.')
        else:
            logger.error(f"{e}")
    return


def parse_args():
    parser = argparse.ArgumentParser(description='Disable AWS Security Hub across all organization accounts and regions.')
    parser.add_argument('--role-name', required=True, help='IAM role to assume in every account.')
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
        regions = get_enabled_regions(management_session)

        # When a delegated Security Hub administrator account is enabled, it's important to identify the home region,
        # as configuration policies are enforced there and automatically apply to all linked regions
        for region in regions:
            admin_account_id = 0
            home_region = ''
            management_sec_hub_client = management_session.client('securityhub', region_name=region)
            admin_accounts = management_sec_hub_client.list_organization_admin_accounts()

            if not admin_accounts['AdminAccounts']:
                logger.info(f'{management_account_id} / {region}: Security Hub administrator account was not found')
            else:
                admin_account_id = admin_accounts['AdminAccounts'][0]['AccountId']
                logger.info(f'{management_account_id} / {region}: Found Security Hub administrator account: {admin_account_id}')

                aggregators = management_sec_hub_client.list_finding_aggregators()
                if aggregators['FindingAggregators']:
                    aggregator_arn = aggregators['FindingAggregators'][0]['FindingAggregatorArn']
                    logger.debug(f'{management_account_id} / {region}: "Finding Aggregator" ARN: {aggregator_arn}')
                    home_region = aggregator_arn.split(':')[3]
                    logger.info(f'{management_account_id} / {region}: Security Hub home region: {home_region}')

                # disable Security Hub in the administrator account
                assumed_role_session = assume_role(
                    admin_account_id,
                    args.role_name,
                    'DisableSecurityHub',
                    management_session
                )
                disable_security_hub_administrator_account(
                    admin_account_id,
                    home_region or region,     # home_region will be set if Security Hub finding aggregator was found
                    assumed_role_session
                )
                # disable organization admin account
                management_sec_hub_client.disable_organization_admin_account(AdminAccountId=admin_account_id)
                logger.info(f'{management_account_id} / {region}: Security Hub Administrator Account "{admin_account_id}" has been successfully disabled')


        # At this point Security Hub Administrator Account(s) and Home Regions have been disabled
        # Security Hub is self-managed in every organization account and region and can be disabled individually
        for region in regions:
            logger.info(region.center(40, '-'))
            accounts = get_active_accounts(management_session)

            for account in accounts:
                account_id = account["Id"]

                if account_id == management_account_id:
                    disable_security_hub(account_id, region, management_session)
                else:
                    assumed_role_session = assume_role(
                        account_id,
                        args.role_name,
                        'DisableSecurityHub',
                        management_session
                    )
                    if assumed_role_session is None:
                        logger.error(f'{account_id} / {region}: Failed to assume role. This account will be skipped.')
                        continue
                    disable_security_hub(account_id, region, assumed_role_session)


        management_org_client = management_session.client('organizations')
        # disable delegated Security Hub administrators
        delegated_admin = management_org_client.list_delegated_administrators(ServicePrincipal=SECURITY_HUB_SERVICE_PRINCIPAL)

        if delegated_admin['DelegatedAdministrators']:
            delegated_admin_id = delegated_admin['DelegatedAdministrators'][0]['Id']
            management_org_client.deregister_delegated_administrator(
                AccountId=delegated_admin_id,
                ServicePrincipal=SECURITY_HUB_SERVICE_PRINCIPAL
            )
            logger.info(f'{management_account_id}: Delegated administrator account "{delegated_admin_id}" for service principal "{SECURITY_HUB_SERVICE_PRINCIPAL}" has been successfully removed')
        else:
            logger.info(f'{management_account_id}: Delegated administrator account for service principal "{SECURITY_HUB_SERVICE_PRINCIPAL}" was not found')

        # disable trusted organization access
        aws_services = management_org_client.list_aws_service_access_for_organization()
        if aws_services['EnabledServicePrincipals']:
            for aws_service in aws_services['EnabledServicePrincipals']:
                if (aws_service['ServicePrincipal'] == SECURITY_HUB_SERVICE_PRINCIPAL):
                    management_org_client.disable_aws_service_access(ServicePrincipal=SECURITY_HUB_SERVICE_PRINCIPAL)
                    logger.info(f'{management_account_id}: Trusted organization access for "{SECURITY_HUB_SERVICE_PRINCIPAL}" has been successfully removed')

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
