#!/usr/bin/env bash

#
# Notes:
#  - following resources cannot be explicitly deleted, but will be removed when "delete-vpc" is called:
#    - security group
#    - route table
#    - NACL
#  - if modifying this script to delete non-default VPCs, additional resources need to be deleted:
#    - VPC endpoints
#    - egress only internet gateways
#    - carrier gateways
#    - network interfaces
#

if [ -z "$1" ]; then
    echo "ERROR: No REGION argument provided."
  exit 1
fi
REGION=$1

region_exists=$(aws ec2 describe-regions --filters "Name=region-name,Values=$REGION" --query "Regions[0].RegionName || ''" --output text)

if [ -z "$region_exists" ]; then
    echo "ERROR: Supplied region $REGION is either invalid or not enabled for this account"
    exit 1
fi

# Retrieve the default VPC ID
echo "Looking for a default VPC in the region $REGION"
vpc_id=$(aws ec2 describe-vpcs --filters "Name=isDefault,Values=true" --query "Vpcs[0].VpcId || ''" --output text --region $REGION)

if [ -z "$vpc_id" ]; then
    echo -e "\tDefault VPC was not found"
    exit 1
fi
echo -e "\tDefault VPC found: $vpc_id"

# Detach and delete internet gateway attached to the VPC
echo "Looking for an Internet Gateway"
internet_gateway_id=$(aws ec2 describe-internet-gateways \
                        --filters "Name=attachment.vpc-id,Values=$vpc_id" \
                        --query "InternetGateways[0].InternetGatewayId || ''" \
                        --output text \
                        --region $REGION)

if [ -n "$internet_gateway_id" ]; then
    echo -e "\tDetaching and deleting Internet Gateway: $internet_gateway_id"
    aws ec2 detach-internet-gateway --internet-gateway-id "$internet_gateway_id" --vpc-id "$vpc_id" --region $REGION
    aws ec2 delete-internet-gateway --internet-gateway-id "$internet_gateway_id" --region $REGION
else
    echo -e "\tInternet Gateway was not found"
fi

# Delete all subnets within the default VPC
echo "Looking for subnets"
subnet_ids=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc_id" --query "Subnets[].SubnetId" --output text --region $REGION)

if [ -z "$subnet_ids" ]; then
    echo -e "\tNo subnets were found"
fi

for subnet_id in $subnet_ids; do
    echo -e "\tDeleting subnet: $subnet_id"
    aws ec2 delete-subnet --subnet-id "$subnet_id" --region $REGION
done

dhcp_options_id=$(aws ec2 describe-vpcs --filters "Name=isDefault,Values=true" --query "Vpcs[0].DhcpOptionsId" --output text --region $REGION)

echo "Deleting default VPC: $vpc_id"
aws ec2 delete-vpc --vpc-id "$vpc_id" --region $REGION

if [ -n "$dhcp_options_id" ]; then
    echo -e "Deleting DHCP option set: $dhcp_options_id"
    aws ec2 delete-dhcp-options --dhcp-options-id $dhcp_options_id --region $REGION
fi
echo -e "\tDefault VPC deletion complete."
