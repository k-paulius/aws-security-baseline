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

__version__ = '0.1.0'

logger = logging.getLogger(__name__)

# desired block public access for EBS snapshots configuration
EBS_SNAPSHOT_BLOCK_PUBLIC_ACCESS_STATE = 'block-all-sharing'


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


def main():
    # command line arguments
    parser = argparse.ArgumentParser(description='Enable block public access for EBS snapshots across organization accounts and regions.')

    parser.add_argument('--role-name', required=True, help='IAM role to assume in every account.')
    parser.add_argument('--accounts', nargs='*', type=int, help='List of account IDs to modify. All organization accounts are modified by default.')
    parser.add_argument('--regions', nargs='*', help='List of regions to modify. All enabled regions are modified by default.')
    parser.add_argument('--profile', help='Use a specific profile from your credential file. If not given, then the default profile is used.')
    parser.add_argument('--dry-run', action='store_true', help='Print current block public access for EBS snapshots status without making changes.')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging.')
    parser.add_argument('--version', action='version', version=f'v{__version__}', help='Print version information and exit.')

    args = parser.parse_args()

    # configure logging
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(levelname)-8s: %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)

    try:
        session = boto3.Session(profile_name=args.profile)

        accounts = get_active_accounts(session, args.accounts)
        if not accounts:
            logger.info('No AWS accounts were found')
            return

        for account in accounts:
            logger.info(f'{account["Id"]}: Operating on account {account["Id"]} ({account["Name"]})')

            assumed_role_session = assume_role(
                account["Id"],
                args.role_name,
                'EnableEBSSnapshotBlockPublicAccess',
                session
            )
            if assumed_role_session is None:
                logger.error(f'{account["Id"]}: Skipping account')
                continue
            regions = get_enabled_regions(assumed_role_session, args.regions)

            for region in regions:
                try:
                    ec2_client = assumed_role_session.client('ec2', region_name=region)
                    response = ec2_client.get_snapshot_block_public_access_state()
                    current_config = response['State']
                    config_changed = True

                    if current_config == EBS_SNAPSHOT_BLOCK_PUBLIC_ACCESS_STATE:
                        config_changed = False

                    if args.dry_run:
                        logger.info(f'{account["Id"]} / {region}: Block public access for EBS snapshots {"does not match" if config_changed else "matches"} the desired state. Current configuration - {current_config}')
                    else:
                        if not config_changed:
                            logger.info(f'{account["Id"]} / {region}: Block public access for EBS snapshots already matches the desired state')
                        else:
                            ec2_client.enable_snapshot_block_public_access(
                                State=EBS_SNAPSHOT_BLOCK_PUBLIC_ACCESS_STATE
                            )
                            logger.info(f'{account["Id"]} / {region}: Enabled block public access for EBS snapshots')
                except ClientError as e:
                    if e.response['Error']['Code'] == 'UnauthorizedOperation':
                        logger.warning(f'{account["Id"]} / {region}: Skipping this region. You are not authorized to perform {e.operation_name} operation in this region')
                    else:
                        raise

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
