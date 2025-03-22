#!/bin/bash
set -e

# Get AWS Profile Name from command-line argument (default to 'default')
PROFILE="${1:-default}"

# Usage: ./aws_infra_setup.sh [aws_profile]
# Set Variables
VPC_CIDR="10.0.0.0/16"
PUBLIC_SUBNET_CIDR="10.0.1.0/24"
PRIVATE_SUBNET_CIDR_1="10.0.2.0/24"
PRIVATE_SUBNET_CIDR_2="10.0.3.0/24"
REGION="ap-southeast-2"
KEY_NAME="veefix-key-pair"
KEY_PATH="./keys/$KEY_NAME.pem"
INSTANCE_TYPE="t3a.xlarge"
AMI_ID="ami-0013d898808600c4a"
DB_USERNAME="admin"
SECRET_NAME="veefix-rds-secret"
DOMAIN_NAME="app.veefix.com.au"
HOSTED_ZONE_ID="Z07232442XJB7AU1FMWIA"
LOAD_BALANCER_NAME="veefix-lb"
DB_INSTANCE_TYPE="db.t3.medium"
DB_INSTANCE_IDENTIFIER="veefix-db-instance"
DB_SUBNET_GROUP_NAME="veefix-db-subnet-group"

# Create a secure directory for the key pair
mkdir -p ./keys
chmod 700 ./keys

echo "Step 1: Create EC2 Key Pair..."
aws ec2 create-key-pair --key-name $KEY_NAME --query 'KeyMaterial' --output text --profile $PROFILE --region $REGION > $KEY_PATH
chmod 400 $KEY_PATH
read -p "Key Pair created at $KEY_PATH. Press Enter to continue..."

echo "Step 2: Create VPC..."
VPC_ID=$(aws ec2 create-vpc --cidr-block $VPC_CIDR --profile $PROFILE --region $REGION --query 'Vpc.VpcId' --output text)
read -p "VPC created: $VPC_ID. Press Enter to continue..."

echo "Step 3: Create Subnets..."
PUBLIC_SUBNET_ID_1=$(aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block $PUBLIC_SUBNET_CIDR --availability-zone "${REGION}a" --profile $PROFILE --region $REGION --query 'Subnet.SubnetId' --output text)
PUBLIC_SUBNET_ID_2=$(aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block "10.0.4.0/24" --availability-zone "${REGION}b" --profile $PROFILE --region $REGION --query 'Subnet.SubnetId' --output text)
PRIVATE_SUBNET_ID_1=$(aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block $PRIVATE_SUBNET_CIDR_1 --availability-zone "${REGION}a" --profile $PROFILE --region $REGION --query 'Subnet.SubnetId' --output text)
PRIVATE_SUBNET_ID_2=$(aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block $PRIVATE_SUBNET_CIDR_2 --availability-zone "${REGION}b" --profile $PROFILE --region $REGION --query 'Subnet.SubnetId' --output text)
read -p "Subnets created: Public - $PUBLIC_SUBNET_ID_1, $PUBLIC_SUBNET_ID_2; Private - $PRIVATE_SUBNET_ID_1, $PRIVATE_SUBNET_ID_2. Press Enter to continue..."

echo "Step 4: Create Internet Gateway..."
IGW_ID=$(aws ec2 create-internet-gateway --profile $PROFILE --region $REGION --query 'InternetGateway.InternetGatewayId' --output text)
aws ec2 attach-internet-gateway --internet-gateway-id $IGW_ID --vpc-id $VPC_ID --profile $PROFILE --region $REGION
read -p "Internet Gateway created: $IGW_ID. Press Enter to continue..."

echo "Step 5: Create Public Route Table..."
PUBLIC_RT_ID=$(aws ec2 create-route-table --vpc-id $VPC_ID --profile $PROFILE --region $REGION --query 'RouteTable.RouteTableId' --output text)
aws ec2 create-route --route-table-id $PUBLIC_RT_ID --destination-cidr-block 0.0.0.0/0 --gateway-id $IGW_ID --profile $PROFILE --region $REGION
aws ec2 associate-route-table --route-table-id $PUBLIC_RT_ID --subnet-id $PUBLIC_SUBNET_ID_1 --profile $PROFILE --region $REGION
aws ec2 associate-route-table --route-table-id $PUBLIC_RT_ID --subnet-id $PUBLIC_SUBNET_ID_2 --profile $PROFILE --region $REGION
read -p "Public Route Table created: $PUBLIC_RT_ID. Press Enter to continue..."

echo "Step 6: Create EC2 Security Group..."
EC2_SG_ID=$(aws ec2 create-security-group --group-name "EC2-SG" --description "Security group for EC2" --vpc-id $VPC_ID --profile $PROFILE --region $REGION --query 'GroupId' --output text)
aws ec2 authorize-security-group-ingress --group-id $EC2_SG_ID --protocol tcp --port 22 --cidr 0.0.0.0/0 --profile $PROFILE --region $REGION
aws ec2 authorize-security-group-ingress --group-id $EC2_SG_ID --protocol tcp --port 80 --cidr 0.0.0.0/0 --profile $PROFILE --region $REGION
aws ec2 authorize-security-group-ingress --group-id $EC2_SG_ID --protocol tcp --port 443 --cidr 0.0.0.0/0 --profile $PROFILE --region $REGION
read -p "EC2 Security Group created: $EC2_SG_ID. Press Enter to continue..."

echo "Step 7: Launch EC2 Instance with Security Group..."
EC2_ID=$(aws ec2 run-instances \
  --image-id $AMI_ID \
  --count 1 \
  --instance-type $INSTANCE_TYPE \
  --key-name $KEY_NAME \
  --subnet-id $PUBLIC_SUBNET_ID_1 \
  --security-group-ids $EC2_SG_ID \
  --associate-public-ip-address \
  --profile $PROFILE --region $REGION \
  --query 'Instances[0].InstanceId' --output text)
read -p "EC2 Instance launched: $EC2_ID. Press Enter to continue..."

echo "Step 8: Create RDS Security Group..."
RDS_SG_ID=$(aws ec2 describe-security-groups --filters Name=group-name,Values="RDS-SG" Name=vpc-id,Values=$VPC_ID --profile $PROFILE --region $REGION --query 'SecurityGroups[0].GroupId' --output text)
if [ "$RDS_SG_ID" == "None" ]; then
  RDS_SG_ID=$(aws ec2 create-security-group --group-name "RDS-SG" --description "Security group for RDS" --vpc-id $VPC_ID --profile $PROFILE --region $REGION --query 'GroupId' --output text)
fi
aws ec2 authorize-security-group-ingress --group-id $RDS_SG_ID --protocol tcp --port 3306 --source-group $EC2_SG_ID --profile $PROFILE --region $REGION
read -p "RDS Security Group created: $RDS_SG_ID. Press Enter to continue..."

echo "Step 9: Create Secrets Manager Secret..."
SECRET_ARN=$(aws secretsmanager describe-secret --secret-id $SECRET_NAME --profile $PROFILE --region $REGION --query 'ARN' --output text 2>/dev/null || echo "None")
if [ "$SECRET_ARN" == "None" ]; then
  SECRET_ARN=$(aws secretsmanager create-secret --name $SECRET_NAME --description "RDS password for auto-rotation" --secret-string "{\"username\":\"$DB_USERNAME\", \"password\":\"$(openssl rand -base64 16)\"}" --profile $PROFILE --region $REGION --query 'ARN' --output text)
fi
read -p "Secret created: $SECRET_ARN. Press Enter to continue..."

echo "Step 10: Create DB Subnet Group..."
aws rds create-db-subnet-group --db-subnet-group-name $DB_SUBNET_GROUP_NAME --db-subnet-group-description "DB Subnet Group for RDS" --subnet-ids $PRIVATE_SUBNET_ID_1 $PRIVATE_SUBNET_ID_2 --profile $PROFILE --region $REGION
read -p "DB Subnet Group created: $DB_SUBNET_GROUP_NAME. Press Enter to continue..."

echo "Step 11: Launch RDS Instance..."
RDS_PASSWORD=$(aws secretsmanager get-secret-value --secret-id $SECRET_NAME --profile $PROFILE --region $REGION --query 'SecretString' --output text | jq -r .password)
aws rds create-db-instance --db-instance-identifier $DB_INSTANCE_IDENTIFIER --db-instance-class $DB_INSTANCE_TYPE --engine mysql --allocated-storage 20 --db-subnet-group-name $DB_SUBNET_GROUP_NAME --vpc-security-group-ids $RDS_SG_ID --master-username $DB_USERNAME --master-user-password "$RDS_PASSWORD" --no-publicly-accessible --profile $PROFILE --region $REGION
read -p "RDS Instance launched. Press Enter to continue..."

echo "Step 12: Attach IAM Role to EC2 for Secrets Manager..."
aws iam create-role --role-name EC2SecretsManagerRole --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' --profile $PROFILE --region $REGION
sleep 60
aws iam create-policy --policy-name SecretsManagerAccessPolicy --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["secretsmanager:GetSecretValue","secretsmanager:PutSecretValue"],"Resource":"'"$SECRET_ARN"'"}]}' --profile $PROFILE --region $REGION
sleep 60
POLICY_ARN=$(aws iam list-policies --scope Local --query "Policies[?PolicyName=='SecretsManagerAccessPolicy'].Arn" --output text --profile $PROFILE --region $REGION)
aws iam attach-role-policy --role-name EC2SecretsManagerRole --policy-arn $POLICY_ARN --profile $PROFILE --region $REGION
sleep 60
if aws iam get-instance-profile --instance-profile-name EC2SecretsManagerProfile --profile $PROFILE --region $REGION > /dev/null 2>&1; then
  echo "Instance profile already exists."
else
  aws iam create-instance-profile --instance-profile-name EC2SecretsManagerProfile --profile $PROFILE --region $REGION
fi
EXISTING_ROLE=$(aws iam get-instance-profile --instance-profile-name EC2SecretsManagerProfile --query "InstanceProfile.Roles[0].RoleName" --output text --profile $PROFILE --region $REGION)
if [ "$EXISTING_ROLE" == "EC2SecretsManagerRole" ]; then
  echo "Role already attached."
elif [ "$EXISTING_ROLE" != "None" ]; then
  echo "Instance profile already has a different role: $EXISTING_ROLE. Exiting."
  exit 1
else
  aws iam add-role-to-instance-profile --instance-profile-name EC2SecretsManagerProfile --role-name EC2SecretsManagerRole --profile $PROFILE --region $REGION
fi
read -p "IAM Role attached. Press Enter to continue..."

echo "Step 13: Create Load Balancer..."
LB_ARN=$(aws elbv2 create-load-balancer --name $LOAD_BALANCER_NAME --subnets $PUBLIC_SUBNET_ID_1 $PUBLIC_SUBNET_ID_2 --security-groups $EC2_SG_ID --scheme internet-facing --type application --profile $PROFILE --region $REGION --query 'LoadBalancers[0].LoadBalancerArn' --output text)
read -p "Load Balancer created: $LB_ARN. Press Enter to continue..."

echo "Step 14: Create Target Group..."
TARGET_GROUP_ARN=$(aws elbv2 create-target-group --name "${LOAD_BALANCER_NAME}-target-group" --protocol HTTP --port 80 --vpc-id $VPC_ID --target-type instance --health-check-protocol HTTP --health-check-port 80 --health-check-path "/health" --health-check-interval-seconds 30 --health-check-timeout-seconds 5 --healthy-threshold-count 3 --unhealthy-threshold-count 3 --profile $PROFILE --region $REGION --query 'TargetGroups[0].TargetGroupArn' --output text)
read -p "Target Group created: $TARGET_GROUP_ARN. Press Enter to continue..."

echo "Step 15: Create Listener for Load Balancer..."
aws elbv2 create-listener --load-balancer-arn $LB_ARN --protocol HTTP --port 80 --default-actions Type=forward,TargetGroupArn=$TARGET_GROUP_ARN --profile $PROFILE --region $REGION
read -p "Listener created. Press Enter to continue..."

echo "Step 16: Register EC2 Instance with Target Group..."
aws elbv2 register-targets --target-group-arn $TARGET_GROUP_ARN --targets Id=$EC2_ID --profile $PROFILE --region $REGION
read -p "EC2 Instance registered with Target Group. Press Enter to continue..."

echo "Step 17: Create second Listener for Load Balancer..."
aws elbv2 create-listener --load-balancer-arn $LB_ARN --protocol HTTP --port 80 --default-actions Type=forward,TargetGroupArn=$TARGET_GROUP_ARN --profile $PROFILE --region $REGION
read -p "Second Listener created. Press Enter to continue..."

echo "Step 18: Retrieve Load Balancer DNS Name..."
LB_DNS_NAME=$(aws elbv2 describe-load-balancers --load-balancer-arns $LB_ARN --profile $PROFILE --region $REGION --query 'LoadBalancers[0].DNSName' --output text)
echo "Load Balancer DNS Name: $LB_DNS_NAME"
read -p "Press Enter to continue..."

echo "Step 19: Setup Route 53..."
LB_HOSTED_ZONE_ID=$(aws elbv2 describe-load-balancers --names $LOAD_BALANCER_NAME --query 'LoadBalancers[0].CanonicalHostedZoneId' --output text --profile $PROFILE --region $REGION)
aws route53 change-resource-record-sets --hosted-zone-id $HOSTED_ZONE_ID --change-batch "{
  \"Changes\": [{
    \"Action\": \"UPSERT\",
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
echo "Route 53 record created for $DOMAIN_NAME."
read -p "Press Enter to finish..."

echo "✅ AWS Infrastructure Setup Complete for $PROFILE!"
