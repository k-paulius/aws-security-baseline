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


def get_guardduty_detector_id(
    account_id,
    region,
    session=None
):
    if not session:
        session = boto3._get_default_session()
    client = session.client('guardduty', region_name=region)
    detectors = client.list_detectors()

    if detectors['DetectorIds']:
        logger.info(f'{account_id} / {region}: GuardDuty detector "{detectors["DetectorIds"][0]}" is already enabled')
        return detectors["DetectorIds"][0]
    logger.info(f'{account_id} / {region}: GuardDuty detector was not found')
    return None


def update_guardduty_detector(
    account_id,
    detector_id,
    region,
    finding_publishing_frequency,
    gd_features,
    session=None
):
    def get_status(feature):
        return 'ENABLED' if gd_features.get(feature) else 'DISABLED'

    if not session:
        session = boto3._get_default_session()
    client = session.client('guardduty', region_name=region)
    runtime_additional_config = [
        {'Name': 'EKS_ADDON_MANAGEMENT', 'Status': get_status('enable_eks_addon_management')},
        {'Name': 'ECS_FARGATE_AGENT_MANAGEMENT', 'Status': get_status('enable_ecs_fargate_agent_management')},
        {'Name': 'EC2_AGENT_MANAGEMENT', 'Status': get_status('enable_ec2_agent_management')}
    ] if gd_features['enable_runtime_monitoring'] else []
    features = [
        {'Name': 'S3_DATA_EVENTS', 'Status': get_status('enable_s3_protection')},
        {'Name': 'EKS_AUDIT_LOGS', 'Status': get_status('enable_eks_protection')},
        {'Name': 'EBS_MALWARE_PROTECTION', 'Status': get_status('enable_ec2_malware_protection')},
        {'Name': 'RDS_LOGIN_EVENTS', 'Status': get_status('enable_rds_protection')},
        {'Name': 'LAMBDA_NETWORK_LOGS', 'Status': get_status('enable_lambda_protection')},
        {'Name': 'RUNTIME_MONITORING', 'Status': get_status('enable_runtime_monitoring'), 'AdditionalConfiguration': runtime_additional_config}
    ]

    if detector_id:
        response = client.update_detector(
            DetectorId=detector_id,
            Enable=True,
            FindingPublishingFrequency='SIX_HOURS' if not finding_publishing_frequency else finding_publishing_frequency,
            Features=features
        )
        logger.info(f'{account_id} / {region}: GuardDuty detector "{detector_id}" has been successfully updated')
    else:
        response = client.create_detector(
            Enable=True,
            FindingPublishingFrequency='SIX_HOURS' if not finding_publishing_frequency else finding_publishing_frequency,
            Features=features
        )
        detector_id = response["DetectorId"]
        logger.info(f'{account_id} / {region}: GuardDuty detector "{detector_id}" has been successfully created')
    return detector_id


def update_guardduty_organization_configuration(
    account_id,
    detector_id,
    region,
    gd_features,
    auto_enable,
    session=None
):
    def get_auto_enable(feature):
        return auto_enable if gd_features.get(feature) else 'NONE'

    if not session:
        session = boto3._get_default_session()
    client = session.client('guardduty', region_name=region)
    runtime_additional_config = [
        {'Name': 'EKS_ADDON_MANAGEMENT', 'AutoEnable': get_auto_enable('enable_eks_addon_management')},
        {'Name': 'ECS_FARGATE_AGENT_MANAGEMENT', 'AutoEnable': get_auto_enable('enable_ecs_fargate_agent_management')},
        {'Name': 'EC2_AGENT_MANAGEMENT', 'AutoEnable': get_auto_enable('enable_ec2_agent_management')}
    ] if gd_features['enable_runtime_monitoring'] else []
    features = [
        {'Name': 'S3_DATA_EVENTS', 'AutoEnable': get_auto_enable('enable_s3_protection')},
        {'Name': 'EKS_AUDIT_LOGS', 'AutoEnable': get_auto_enable('enable_eks_protection')},
        {'Name': 'EBS_MALWARE_PROTECTION', 'AutoEnable': get_auto_enable('enable_ec2_malware_protection')},
        {'Name': 'RDS_LOGIN_EVENTS', 'AutoEnable': get_auto_enable('enable_rds_protection')},
        {'Name': 'LAMBDA_NETWORK_LOGS', 'AutoEnable': get_auto_enable('enable_lambda_protection')},
        {'Name': 'RUNTIME_MONITORING', 'AutoEnable': get_auto_enable('enable_runtime_monitoring'), 'AdditionalConfiguration': runtime_additional_config}
    ]
    response = client.update_organization_configuration(
        DetectorId=detector_id,
        Features=features,
        AutoEnableOrganizationMembers='ALL'
    )
    logger.info(f'{account_id} / {region}: Delegated administrator account organization configuration has been successfully updated')
    return


def update_guardduty_publishing_destinations(
    account_id,
    detector_id,
    region,
    destination_arn,
    kms_key_arn,
    session=None
):
    if not session:
        session = boto3._get_default_session()
    client = session.client('guardduty', region_name=region)
    destinations = client.list_publishing_destinations(DetectorId=detector_id)

    if destinations['Destinations']:
        destination_id = destinations['Destinations'][0]['DestinationId']
        logger.info(f'{account_id} / {region}: GuardDuty publishing destination "{destination_id}" is already enabled')

        response = client.update_publishing_destination(
            DetectorId=detector_id,
            DestinationId=destination_id,
            DestinationProperties={
                'DestinationArn': destination_arn,
                'KmsKeyArn': kms_key_arn
            }
        )
        logger.info(f'{account_id} / {region}: GuardDuty publishing destination "{destination_id}" has been successfully updated')
    else:
        response = client.create_publishing_destination(
            DetectorId=detector_id,
            DestinationType='S3',
            DestinationProperties={
                'DestinationArn': destination_arn,
                'KmsKeyArn': kms_key_arn
            }
        )
        destination_id = response['DestinationId']
        logger.info(f'{account_id} / {region}: GuardDuty publishing destination "{destination_id}" has been successfully created')
    return destination_id


def delegated_guardduty_administration(
    account_id,
    region,
    delegated_admin_account_id,
    session=None
):
    if not session:
        session = boto3._get_default_session()
    client = session.client('guardduty', region_name=region)
    delegated_admins = client.list_organization_admin_accounts()

    if delegated_admins['AdminAccounts']:
        current_delegated_admin_account_id = delegated_admins['AdminAccounts'][0]['AdminAccountId']
        logger.info(f'{account_id} / {region}: Account "{current_delegated_admin_account_id}" is already a delegated GuardDuty administrator')

        if current_delegated_admin_account_id != delegated_admin_account_id:
            logger.error(f'{account_id} / {region}: Current Delegated GuardDuty administrator account "{current_delegated_admin_account_id}" does not match desired account "{delegated_admin_account_id}"')
            logger.error(f'{account_id} / {region}: Please remove the current delegated administrator account and re-run the script in this region')
            return False
    else:
        logger.info(f'{account_id} / {region}: Delegated GuardDuty administrator account was not found')
        client.enable_organization_admin_account(AdminAccountId=delegated_admin_account_id)
        logger.info(f'{account_id} / {region}: Delegated GuardDuty administrator account "{delegated_admin_account_id}" has been successfully enabled')
    return True


def enable_guardduty_malware_protection_org_integration(
    account_id,
    region,
    service_principal,
    session=None
):
    if not session:
        session = boto3._get_default_session()
    client = session.client('organizations', region_name=region)
    services = client.list_aws_service_access_for_organization()

    if services['EnabledServicePrincipals']:
        for service in services['EnabledServicePrincipals']:
            if service['ServicePrincipal'] == service_principal:
                logger.info(f'{account_id} / {region}: Trusted organization access for "{service_principal}" is already enabled')
                return True
    client.enable_aws_service_access(ServicePrincipal=service_principal)
    logger.info(f'{account_id} / {region}: Trusted organization access for "{service_principal}" has been successfully enabled')
    return True


def get_guardduty_member_accounts(
    detector_id,
    region,
    session=None
):
    if not session:
        session = boto3._get_default_session()
    client = session.client('guardduty', region_name=region)
    account_ids = []
    paginator = client.get_paginator('list_members')

    for page in paginator.paginate(DetectorId=detector_id):
        for member in page["Members"]:
            account_ids.append(member["AccountId"])
    return account_ids


def create_guardduty_member_accounts(
    delegated_admin_account_id,
    delegated_admin_detector_id,
    accounts,
    region,
    session=None
):
    if not session:
        session = boto3._get_default_session()
    client = session.client('guardduty', region_name=region)
    members = get_guardduty_member_accounts(delegated_admin_detector_id, region, session)

    for account in accounts:
        account_id = account['Id']
        if account_id == delegated_admin_account_id:
            continue

        if account_id in members:
            logger.info(f'{delegated_admin_account_id} / {region}: Organization account "{account["Id"]}" is already a GuardDuty member account')
        else:
            response = client.create_members(
                DetectorId=delegated_admin_detector_id,
                AccountDetails=[
                    {'AccountId': account['Id'], 'Email': account['Email'] },
                ]
            )
            logger.info(f'{delegated_admin_account_id} / {region}: Organization account "{account["Id"]}" was successfully added as a GuardDuty member account')
    return


def parse_args():
    parser = argparse.ArgumentParser(description='Enable Amazon GuardDuty for all organization accounts and regions.')
    parser.add_argument('--role-name', required=True, help='IAM role to assume in every account.')
    parser.add_argument('--accounts', nargs='*', type=int, help='List of accounts that will be added as GuardDuty members. By default, all organization accounts are added.')
    parser.add_argument('--regions', nargs='*', help='List of regions to modify. All enabled regions are modified by default.')
    parser.add_argument('--delegated-admin-account', required=True, help='Account within the organization you want to designate as your GuardDuty delegated administrator.')
    parser.add_argument('--profile', help='Use a specific profile from your credential file. If not given, then the default profile is used.')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging.')
    parser.add_argument('--version', action='version', version=f'v{__version__}', help='Print version information and exit.')

    features = parser.add_argument_group('Protection Plans')
    features.add_argument('--auto-enable', action='store', choices=['ALL', 'NEW'], default='NEW', help='Auto-enable setting to apply to all protection plans you activate. Defaults to "NEW".')
    features.add_argument('--enable-s3-protection', action='store_true', help='Enable S3 Protection. Disabled by default.')
    features.add_argument('--enable-eks-protection', action='store_true', help='Enable EKS Protection. Disabled by default.')
    features.add_argument('--enable-ec2-malware-protection', action='store_true', help='Enable Malware Protection for EC2. Disabled by default.')
    features.add_argument('--enable-rds-protection', action='store_true', help='Enable RDS Protection. Disabled by default.')
    features.add_argument('--enable-lambda-protection', action='store_true', help='Enable Lambda Protection. Disabled by default.')
    features.add_argument('--enable-runtime-monitoring', action='store_true', help='Enable Runtime Monitoring. Disabled by default.')
    features.add_argument('--enable-eks-addon-management', action='store_true', help='Enable automated agent configuration for Amazon EKS. Disabled by default.')
    features.add_argument('--enable-ecs-fargate-agent-management', action='store_true', help='Enable automated agent configuration for AWS Fargate (ECS only). Disabled by default.')
    features.add_argument('--enable-ec2-agent-management', action='store_true', help='Enable automated agent configuration for Amazon EC2. Disabled by default.')

    exports = parser.add_argument_group('Findings Export Options')
    exports.add_argument('--export-frequency', action='store', choices=['FIFTEEN_MINUTES', 'ONE_HOUR', 'SIX_HOURS'], help='Frequency to publish updated findings')
    exports.add_argument('--export-s3-arn', action='store', help='S3 bucket ARN')
    exports.add_argument('--export-kms-key-arn', action='store', help='KMS key ARN')
    args = parser.parse_args()

    if (
        (args.export_s3_arn is not None and args.export_kms_key_arn is None) or
        (args.export_s3_arn is None and args.export_kms_key_arn is not None)
    ):
        print('ERROR: Both --export-s3-arn and --export-kms-key-arn must be specified together')
        sys.exit()
    return args


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
        gd_features = vars(args)
        gd_malware_protection_org_integration_enabled = False

        # GuardDuty is a regional service and needs to be explicitly enabled in every region
        for region in regions:
            logger.info(region.center(40, '-'))

            # configure GuardDuty in the management account
            management_detector_id = get_guardduty_detector_id(
                management_account_id,
                region,
                management_session
            )
            # detector cannot be updated directly if it is a member in the delegated admin account
            if not management_detector_id:
                management_detector_id = update_guardduty_detector(
                    management_account_id,
                    management_detector_id,
                    region,
                    args.export_frequency,
                    gd_features,
                    management_session
                )
            response = delegated_guardduty_administration(
                management_account_id,
                region,
                args.delegated_admin_account,
                management_session
            )
            if not response:
                continue

            if not gd_malware_protection_org_integration_enabled:
                # enable the integration of Malware Protection service with Organizations (global setting)
                # AWS Console setting: Allow delegated administrator to attach relevant permissions to enable Malware Protection for member accounts.
                enable_guardduty_malware_protection_org_integration(
                    management_account_id,
                    region,
                    GD_MALWARE_PROTECTION_SERVICE_PRINCIPAL,
                    management_session
                )
                gd_malware_protection_org_integration_enabled = True

            # configure GuardDuty in the delegated administrator account
            delegated_admin_account_id = args.delegated_admin_account
            delegated_admin_session = assume_role(
                delegated_admin_account_id,
                args.role_name,
                'EnableGuardDuty',
                management_session
            )
            if delegated_admin_session is None:
                logger.error(f'{delegated_admin_account_id} / {region}: Failed to assume role in the GuardDuty delegated administrator account')
                continue

            delegated_admin_detector_id = get_guardduty_detector_id(
                delegated_admin_account_id,
                region,
                delegated_admin_session
            )
            delegated_admin_detector_id = update_guardduty_detector(
                delegated_admin_account_id,
                delegated_admin_detector_id,
                region,
                args.export_frequency,
                gd_features,
                delegated_admin_session
            )
            if not delegated_admin_detector_id:
                continue

            update_guardduty_organization_configuration(
                delegated_admin_account_id,
                delegated_admin_detector_id,
                region,
                gd_features,
                args.auto_enable,
                delegated_admin_session
            )

            if args.export_s3_arn and args.export_kms_key_arn:
                update_guardduty_publishing_destinations(
                    delegated_admin_account_id,
                    delegated_admin_detector_id,
                    region,
                    args.export_s3_arn,
                    args.export_kms_key_arn,
                    delegated_admin_session
                )
            accounts = get_active_accounts(management_session, args.accounts)
            create_guardduty_member_accounts(
                delegated_admin_account_id,
                delegated_admin_detector_id,
                accounts,
                region,
                delegated_admin_session
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
