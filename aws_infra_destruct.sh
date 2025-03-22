#!/bin/bash
set -e

# Usage: ./aws_infra_destruct.sh [aws_profile]
PROFILE="${1:-default}"
REGION="ap-southeast-2"
VPC_CIDR="10.0.0.0/16"
KEY_NAME="veefix-key-pair"
KEY_PATH="./keys/$KEY_NAME.pem"
DB_INSTANCE_IDENTIFIER="veefix-db-instance"
DB_SUBNET_GROUP_NAME="veefix-db-subnet-group"
SECRET_NAME="veefix-rds-secret"
DOMAIN_NAME="app.veefix.com.au"
HOSTED_ZONE_ID="Z07232442XJB7AU1FMWIA"
IAM_ROLE="EC2SecretsManagerRole"
INSTANCE_PROFILE="EC2SecretsManagerProfile"
POLICY_NAME="SecretsManagerAccessPolicy"
LOAD_BALANCER_NAME="veefix-lb"

echo "Starting AWS Infrastructure Removal for profile: $PROFILE in region: $REGION"

########################################
# Step 1: Remove Route 53 Record
########################################
echo "Step 1: Removing Route 53 Record for $DOMAIN_NAME..."
LB_ARN=$(aws elbv2 describe-load-balancers --names $LOAD_BALANCER_NAME --profile $PROFILE --region $REGION --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null || echo "None")
if [ "$LB_ARN" != "None" ]; then
    LB_DNS_NAME=$(aws elbv2 describe-load-balancers --load-balancer-arns $LB_ARN --profile $PROFILE --region $REGION --query 'LoadBalancers[0].DNSName' --output text)
    LB_HOSTED_ZONE_ID=$(aws elbv2 describe-load-balancers --load-balancer-arns $LB_ARN --profile $PROFILE --region $REGION --query 'LoadBalancers[0].CanonicalHostedZoneId' --output text)
    aws route53 change-resource-record-sets --hosted-zone-id $HOSTED_ZONE_ID --change-batch "{
      \"Changes\": [{
        \"Action\": \"DELETE\",
        \"ResourceRecordSet\": {
          \"Name\": \"$DOMAIN_NAME\",
          \"Type\": \"A\",
          \"AliasTarget\": {
            \"HostedZoneId\": \"$LB_HOSTED_ZONE_ID\",
            \"DNSName\": \"$LB_DNS_NAME\",
            \"EvaluateTargetHealth\": false
          }
        }
      }]
    }" --profile $PROFILE --region $REGION
    echo "Route 53 record for $DOMAIN_NAME removed."
else
    echo "Load Balancer $LOAD_BALANCER_NAME not found. Skipping Route 53 record removal."
fi
read -p "Press Enter to continue..."

########################################
# Step 2: Delete Load Balancer
########################################
echo "Step 2: Deleting Load Balancer: $LOAD_BALANCER_NAME..."
if [ "$LB_ARN" != "None" ]; then
    aws elbv2 delete-load-balancer --load-balancer-arn $LB_ARN --profile $PROFILE --region $REGION
    echo "Load Balancer deletion initiated. Waiting for deletion..."
    sleep 60  # Wait to ensure LB deletion starts
else
    echo "Load Balancer $LOAD_BALANCER_NAME not found. Skipping deletion."
fi
read -p "Press Enter to continue..."

########################################
# Step 3: Delete Target Group
########################################
echo "Step 3: Deleting Target Group..."
TARGET_GROUP_ARN=$(aws elbv2 describe-target-groups --names "${LOAD_BALANCER_NAME}-target-group" --profile $PROFILE --region $REGION --query 'TargetGroups[0].TargetGroupArn' --output text 2>/dev/null || echo "None")
if [ "$TARGET_GROUP_ARN" != "None" ]; then
    aws elbv2 delete-target-group --target-group-arn $TARGET_GROUP_ARN --profile $PROFILE --region $REGION
    echo "Target Group deleted."
else
    echo "Target Group not found. Skipping."
fi
read -p "Press Enter to continue..."

########################################
# Step 4: Terminate EC2 Instance
########################################
echo "Step 4: Terminating EC2 Instance associated with key $KEY_NAME..."
EC2_ID=$(aws ec2 describe-instances --filters "Name=key-name,Values=$KEY_NAME" "Name=instance-state-name,Values=pending,running,stopping,stopped" --profile $PROFILE --region $REGION --query "Reservations[0].Instances[0].InstanceId" --output text 2>/dev/null || echo "None")
if [ "$EC2_ID" != "None" ]; then
    aws ec2 terminate-instances --instance-ids $EC2_ID --profile $PROFILE --region $REGION
    echo "EC2 Instance $EC2_ID termination initiated."
else
    echo "No EC2 Instance found with key $KEY_NAME. Skipping termination."
fi
read -p "Press Enter to continue..."

########################################
# Step 5: Delete RDS Instance
########################################
echo "Step 5: Deleting RDS Instance: $DB_INSTANCE_IDENTIFIER..."
DB_INSTANCE_STATUS=$(aws rds describe-db-instances --db-instance-identifier $DB_INSTANCE_IDENTIFIER --profile $PROFILE --region $REGION --query 'DBInstances[0].DBInstanceStatus' --output text 2>/dev/null || echo "NotFound")
if [ "$DB_INSTANCE_STATUS" != "NotFound" ]; then
    aws rds delete-db-instance --db-instance-identifier $DB_INSTANCE_IDENTIFIER --skip-final-snapshot --delete-automated-backups --profile $PROFILE --region $REGION
    echo "RDS instance deletion initiated."
else
    echo "RDS instance $DB_INSTANCE_IDENTIFIER not found. Skipping deletion."
fi

########################################
# Step 6: Delete DB Subnet Group
########################################
echo "Step 6: Deleting DB Subnet Group: $DB_SUBNET_GROUP_NAME..."
DB_SUBNET_GROUP_EXISTS=$(aws rds describe-db-subnet-groups --db-subnet-group-name $DB_SUBNET_GROUP_NAME --profile $PROFILE --region $REGION --query 'DBSubnetGroups[0].DBSubnetGroupName' --output text 2>/dev/null || echo "NotFound")
if [ "$DB_SUBNET_GROUP_EXISTS" != "NotFound" ]; then
    aws rds delete-db-subnet-group --db-subnet-group-name $DB_SUBNET_GROUP_NAME --profile $PROFILE --region $REGION
    echo "DB Subnet Group deleted."
else
    echo "DB Subnet Group $DB_SUBNET_GROUP_NAME not found. Skipping deletion."
fi

########################################
# Step 7: Delete Secrets Manager Secret
########################################
echo "Step 7: Deleting Secrets Manager secret: $SECRET_NAME..."
aws secretsmanager delete-secret --secret-id $SECRET_NAME --force-delete-without-recovery --profile $PROFILE --region $REGION
echo "Secret deletion initiated."
read -p "Press Enter to continue..."

########################################
# Step 8: Remove IAM Role, Instance Profile, and Policy
########################################
echo "Step 8: Removing IAM resources..."
POLICY_ARN=$(aws iam list-policies --scope Local --query "Policies[?PolicyName=='$POLICY_NAME'].Arn" --output text --profile $PROFILE --region $REGION)

if [ -n "$POLICY_ARN" ]; then
    aws iam detach-role-policy --role-name $IAM_ROLE --policy-arn "$POLICY_ARN" --profile $PROFILE --region $REGION || echo "Policy not attached or already detached."
else
    echo "Policy $POLICY_NAME not found, skipping detachment."
fi

aws iam remove-role-from-instance-profile --instance-profile-name $INSTANCE_PROFILE --role-name $IAM_ROLE --profile $PROFILE --region $REGION || echo "Role not attached to instance profile."
aws iam delete-instance-profile --instance-profile-name $INSTANCE_PROFILE --profile $PROFILE --region $REGION || echo "Instance profile deletion skipped."
aws iam delete-role --role-name $IAM_ROLE --profile $PROFILE --region $REGION || echo "Role deletion skipped."

if [ -n "$POLICY_ARN" ]; then
    aws iam delete-policy --policy-arn "$POLICY_ARN" --profile $PROFILE --region $REGION || echo "Policy deletion skipped."
fi

echo "IAM resources removed."

########################################
# Step 9: Detach and Delete Internet Gateway
########################################
echo "Step 9: Detaching and Deleting Internet Gateway..."
VPC_ID=$(aws ec2 describe-vpcs --filters "Name=cidr,Values=$VPC_CIDR" --profile $PROFILE --region $REGION --query 'Vpcs[0].VpcId' --output text 2>/dev/null || echo "None")
if [ "$VPC_ID" != "None" ]; then
    IGW_ID=$(aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$VPC_ID" --profile $PROFILE --region $REGION --query 'InternetGateways[0].InternetGatewayId' --output text 2>/dev/null || echo "None")
    if [ "$IGW_ID" != "None" ]; then
        aws ec2 detach-internet-gateway --internet-gateway-id $IGW_ID --vpc-id $VPC_ID --profile $PROFILE --region $REGION
        aws ec2 delete-internet-gateway --internet-gateway-id $IGW_ID --profile $PROFILE --region $REGION
        echo "Internet Gateway detached and deleted."
    else
        echo "No Internet Gateway found for VPC $VPC_ID."
    fi
else
    echo "VPC not found. Skipping Internet Gateway deletion."
fi
read -p "Press Enter to continue..."

########################################
# Step 10: Delete Route Table
########################################
echo "Step 10: Deleting non-main Route Table(s) in VPC $VPC_ID..."
if [ "$VPC_ID" != "None" ]; then
    # Retrieve all non-main route table IDs in the VPC
    ROUTE_TABLE_IDS=$(aws ec2 describe-route-tables --filters "Name=vpc-id,Values=$VPC_ID" --profile $PROFILE --region $REGION --query "RouteTables[?Associations[?Main==\`false\`]].RouteTableId" --output text)
    
    for RT_ID in $ROUTE_TABLE_IDS; do
        echo "Processing Route Table $RT_ID..."
        # Retrieve all non-main associations for the route table
        ASSOCIATION_IDS=$(aws ec2 describe-route-tables --route-table-ids $RT_ID --profile $PROFILE --region $REGION --query "RouteTables[0].Associations[?Main==\`false\`].RouteTableAssociationId" --output text)
        for ASSOC_ID in $ASSOCIATION_IDS; do
            echo "Disassociating association $ASSOC_ID from route table $RT_ID..."
            aws ec2 disassociate-route-table --association-id $ASSOC_ID --profile $PROFILE --region $REGION
        done
        echo "Deleting Route Table $RT_ID..."
        aws ec2 delete-route-table --route-table-id $RT_ID --profile $PROFILE --region $REGION
        echo "Route Table $RT_ID deleted."
    done
else
    echo "VPC not found. Skipping Route Table deletion."
fi
read -p "Press Enter to continue..."

########################################
# Step 11: Delete Subnets
########################################
echo "Step 11: Deleting Subnets in VPC $VPC_ID..."
if [ "$VPC_ID" != "None" ]; then
    SUBNET_IDS=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" --profile $PROFILE --region $REGION --query 'Subnets[].SubnetId' --output text)
    for SUBNET_ID in $SUBNET_IDS; do
        aws ec2 delete-subnet --subnet-id $SUBNET_ID --profile $PROFILE --region $REGION
        echo "Deleted Subnet: $SUBNET_ID"
    done
else
    echo "VPC not found. Skipping Subnet deletion."
fi
read -p "Press Enter to continue..."

########################################
# Step 12: Delete VPC
########################################
echo "Cleaning up VPC dependencies for VPC $VPC_ID..."

# Delete VPC Endpoints
ENDPOINT_IDS=$(aws ec2 describe-vpc-endpoints --filters Name=vpc-id,Values=$VPC_ID --query 'VpcEndpoints[].VpcEndpointId' --output text --profile $PROFILE --region $REGION)
if [ -n "$ENDPOINT_IDS" ]; then
  echo "Deleting VPC endpoints: $ENDPOINT_IDS"
  aws ec2 delete-vpc-endpoints --vpc-endpoint-ids $ENDPOINT_IDS --profile $PROFILE --region $REGION
fi

# Delete NAT Gateways (if any)
NAT_GW_IDS=$(aws ec2 describe-nat-gateways --filter Name=vpc-id,Values=$VPC_ID --query 'NatGateways[].NatGatewayId' --output text --profile $PROFILE --region $REGION)
if [ -n "$NAT_GW_IDS" ]; then
  for NAT_GW_ID in $NAT_GW_IDS; do
    echo "Deleting NAT gateway: $NAT_GW_ID"
    aws ec2 delete-nat-gateway --nat-gateway-id $NAT_GW_ID --profile $PROFILE --region $REGION
  done
  echo "Waiting for NAT gateways to be deleted..."
  sleep 60
fi

# Delete VPC Peering Connections (if any)
PEERING_IDS=$(aws ec2 describe-vpc-peering-connections --filters Name=requester-vpc-info.vpc-id,Values=$VPC_ID --query 'VpcPeeringConnections[].VpcPeeringConnectionId' --output text --profile $PROFILE --region $REGION)
if [ -n "$PEERING_IDS" ]; then
  for PEERING_ID in $PEERING_IDS; do
    echo "Deleting VPC peering connection: $PEERING_ID"
    aws ec2 delete-vpc-peering-connection --vpc-peering-connection-id $PEERING_ID --profile $PROFILE --region $REGION
  done
fi

echo "Cleaning up lingering Network Interfaces in VPC $VPC_ID..."
ENI_IDS=$(aws ec2 describe-network-interfaces --filters "Name=vpc-id,Values=$VPC_ID" --query "NetworkInterfaces[].NetworkInterfaceId" --output text --profile $PROFILE --region $REGION)
if [ -n "$ENI_IDS" ]; then
  for eni in $ENI_IDS; do
    echo "Deleting network interface $eni..."
    aws ec2 delete-network-interface --network-interface-id $eni --profile $PROFILE --region $REGION || echo "Failed to delete network interface $eni. Check if it's still in use."
  done
else
  echo "No lingering network interfaces found."
fi

echo "Deleting remaining non-default security groups in VPC $VPC_ID..."
SG_IDS=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$VPC_ID" --query "SecurityGroups[?GroupName!='default'].GroupId" --output text --profile $PROFILE --region $REGION)
if [ -n "$SG_IDS" ]; then
  for sg in $SG_IDS; do
    echo "Attempting to delete security group $sg..."
    aws ec2 delete-security-group --group-id $sg --profile $PROFILE --region $REGION || echo "Failed to delete security group $sg. It might still be attached to a resource."
  done
else
  echo "No non-default security groups found."
fi

echo "Attempting to delete security group sg-0ad3255002b88f9be..."
DEPENDENCIES=$(aws ec2 describe-network-interfaces --filters Name=group-id,Values=sg-0ad3255002b88f9be --profile $PROFILE --region $REGION --query "NetworkInterfaces[].NetworkInterfaceId" --output text)
if [ -n "$DEPENDENCIES" ]; then
    echo "Security group sg-0ad3255002b88f9be still has dependent network interfaces: $DEPENDENCIES"
    echo "Waiting 60 seconds for dependencies to clear..."
    sleep 60
fi
aws ec2 delete-security-group --group-id sg-0ad3255002b88f9be --profile $PROFILE --region $REGION || echo "Failed to delete security group sg-0ad3255002b88f9be. It might still be attached to a resource."


# Now you can proceed to delete the VPC
echo "Deleting VPC: $VPC_ID..."
aws ec2 delete-vpc --vpc-id $VPC_ID --profile $PROFILE --region $REGION
echo "VPC $VPC_ID deleted."

########################################
# Step 13: Delete Key Pair and Local Key File
########################################
echo "Step 13: Deleting EC2 Key Pair: $KEY_NAME..."
aws ec2 delete-key-pair --key-name $KEY_NAME --profile $PROFILE --region $REGION
echo "Key Pair deleted from AWS."
if [ -f "$KEY_PATH" ]; then
    rm -f "$KEY_PATH"
    echo "Local key file $KEY_PATH removed."
fi

echo "✅ AWS Infrastructure Removal Complete for profile: $PROFILE!"
