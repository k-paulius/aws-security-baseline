#!/usr/bin/env python3

# Copyright (c) 2023 k-paulius
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

# desired S3 Block Public Access configuration
PUBLIC_ACCESS_BLOCK_CONFIG = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True
}


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
    parser = argparse.ArgumentParser(description='Enable account-wide S3 Public Access Block across organization accounts.')

    parser.add_argument('--role-name', required=True, help='IAM role to assume in every account.')
    parser.add_argument('--accounts', nargs='*', type=int, help='List of account IDs to modify. All organization accounts are modified by default.')
    parser.add_argument('--profile', help='Use a specific profile from your credential file. If not given, then the default profile is used.')
    parser.add_argument('--dry-run', action='store_true', help='Print current S3 Block Public Access configuration without making changes.')
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
                'EnableS3BlockAccountPublicAccess',
                session
            )
            if assumed_role_session is None:
                logger.error(f'{account["Id"]}: Skipping account')
                continue

            try:
                s3_client = assumed_role_session.client('s3control')
                current_public_access_block = {}
                config_changed = True

                try:
                    response = s3_client.get_public_access_block(AccountId=account["Id"])
                    current_public_access_block = response['PublicAccessBlockConfiguration']

                    if current_public_access_block == PUBLIC_ACCESS_BLOCK_CONFIG:
                        config_changed = False
                except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration as e:
                    pass

                if args.dry_run:
                    logger.info(f'{account["Id"]}: S3 Block Public Access configuration {"does not match" if config_changed else "matches"} the desired state')
                    logger.info(f'{account["Id"]}: Current configuration - {current_public_access_block}')
                else:
                    if not config_changed:
                        logger.info(f'{account["Id"]}: S3 Block Public Access configuration already matches the desired state')
                    else:
                        s3_client.put_public_access_block(
                            PublicAccessBlockConfiguration=PUBLIC_ACCESS_BLOCK_CONFIG,
                            AccountId=account["Id"]
                        )
                        logger.info(f'{account["Id"]}: Enabled S3 Block Public Access')
            except ClientError as e:
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
