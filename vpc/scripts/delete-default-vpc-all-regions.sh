#!/usr/bin/env bash

regions=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)

for region in $regions; do
    echo "Deleting default VPC in region: $region"
    ./delete-default-vpc.sh $region
    echo ""
done
