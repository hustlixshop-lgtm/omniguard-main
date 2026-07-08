# OmniGuard AWS Production Deployment Guide

Complete step-by-step guide for deploying OmniGuard on AWS infrastructure. This guide covers production-grade deployment with high availability, security, and monitoring.

---

## Architecture Overview

```
                                    ┌─────────────────────────────────────────────────────────┐
                                    │                    AWS Cloud                            │
                                    │                                                         │
┌──────────┐    ┌────────────┐      │   ┌─────────────────────────────────────────────────┐   │
│  Users   │───▶│ CloudFront │──────┼──▶│              Application Load Balancer          │   │
└──────────┘    └────────────┘      │   │                    (ALB)                        │   │
                                    │   └──────────────────────┬──────────────────────────┘   │
                                    │                          │                              │
                                    │                          ▼                              │
                                    │   ┌─────────────────────────────────────────────────┐   │
                                    │   │                ECS Fargate                      │   │
                                    │   │  ┌─────────────┐  ┌─────────────┐               │   │
                                    │   │  │  OmniGuard  │  │  OmniGuard  │               │   │
                                    │   │  │  Container  │  │  Container  │   (Auto-scale)│   │
                                    │   │  └──────┬──────┘  └──────┬──────┘               │   │
                                    │   └─────────┼────────────────┼──────────────────────┘   │
                                    │             │                │                           │
                                    │             ▼                ▼                           │
                                    │   ┌─────────────────────────────────────────────────┐   │
                                    │   │            Supabase (Managed)                    │   │
                                    │   │  ┌────────────┐  ┌────────────┐  ┌────────────┐  │   │
                                    │   │  │ PostgreSQL │  │   Auth     │  │   Edge     │  │   │
                                    │   │  │  Database  │  │  Service   │  │  Functions  │  │   │
                                    │   │  └────────────┘  └────────────┘  └────────────┘  │   │
                                    │   └─────────────────────────────────────────────────┘   │
                                    │                                                         │
                                    │   ┌─────────────────────────────────────────────────┐   │
                                    │   │          AWS Supporting Services                 │   │
                                    │   │  ┌────────────┐  ┌────────────┐  ┌────────────┐  │   │
                                    │   │  │  Secrets   │  │ CloudWatch │  │  Route53   │  │   │
                                    │   │  │  Manager    │  │  Logging   │  │    DNS     │  │   │
                                    │   │  └────────────┘  └────────────┘  └────────────┘  │   │
                                    │   └─────────────────────────────────────────────────┘   │
                                    └─────────────────────────────────────────────────────────┘
```

---

## Prerequisites

1. **AWS Account** with appropriate permissions
2. **AWS CLI** installed and configured (`aws configure`)
3. **Docker** installed locally
4. **Domain name** for your deployment (optional but recommended)
5. **Supabase Project** with database migrations applied

---

## Part 1: AWS CLI Setup

### Install AWS CLI

**macOS:**
```bash
brew install awscli
```

**Linux:**
```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
rm -rf awscliv2.zip aws
```

**Windows:**
```powershell
# Run in PowerShell as Administrator
msiexec.exe /i https://awscli.amazonaws.com/AWSCLIV2.msi
```

### Configure AWS CLI

```bash
aws configure
```

You will be prompted for:
- AWS Access Key ID
- AWS Secret Access Key
- Default region (recommended: `us-east-1` or `us-west-2`)
- Default output format (enter `json`)

### Verify Configuration

```bash
aws sts get-caller-identity
```

Output should show your AWS account ID and user ARN.

---

## Part 2: Create IAM Roles

### 2.1 Create ECS Task Execution Role

Create file `iam-ecs-task-execution-role.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

```bash
# Create the role
aws iam create-role \
  --role-name OmniGuardECSTaskExecutionRole \
  --assume-role-policy-document file://iam-ecs-task-execution-role.json

# Attach required policies
aws iam attach-role-policy \
  --role-name OmniGuardECSTaskExecutionRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy

aws iam attach-role-policy \
  --role-name OmniGuardECSTaskExecutionRole \
  --policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly

aws iam attach-role-policy \
  --role-name OmniGuardECSTaskExecutionRole \
  --policy-arn arn:aws:iam::aws:policy/SecretsManagerReadWrite
```

### 2.2 Create ECS Task Role (for application)

Create file `iam-ecs-task-role-trust.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

Create file `iam-ecs-task-role-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "arn:aws:secretsmanager:*:*:secret:omniguard/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

```bash
# Create the role
aws iam create-role \
  --role-name OmniGuardECSTaskRole \
  --assume-role-policy-document file://iam-ecs-task-role-trust.json

# Create inline policy for application permissions
aws iam put-role-policy \
  --role-name OmniGuardECSTaskRole \
  --policy-name OmniGuardTaskPolicy \
  --policy-document file://iam-ecs-task-role-policy.json
```

---

## Part 3: Network Infrastructure (VPC)

### 3.1 Create VPC

```bash
# Create VPC
VPC_ID=$(aws ec2 create-vpc \
  --cidr-block 10.0.0.0/16 \
  --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=OmniGuard-VPC}]' \
  --query 'Vpc.VpcId' \
  --output text)

echo "VPC_ID=$VPC_ID"

# Enable DNS support
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-support
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-hostnames
```

### 3.2 Create Subnets

```bash
# Get availability zones for your region
AZS=$(aws ec2 describe-availability-zones --query 'AvailabilityZones[0:2].ZoneName' --output text)
AZ1=$(echo $AZS | awk '{print $1}')
AZ2=$(echo $AZS | awk '{print $2}')

# Public subnets (for ALB)
PUBLIC_SUBNET_1=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID \
  --cidr-block 10.0.1.0/24 \
  --availability-zone $AZ1 \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=OmniGuard-Public-1}]' \
  --query 'Subnet.SubnetId' \
  --output text)

PUBLIC_SUBNET_2=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID \
  --cidr-block 10.0.2.0/24 \
  --availability-zone $AZ2 \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=OmniGuard-Public-2}]' \
  --query 'Subnet.SubnetId' \
  --output text)

echo "PUBLIC_SUBNET_1=$PUBLIC_SUBNET_1"
echo "PUBLIC_SUBNET_2=$PUBLIC_SUBNET_2"

# Private subnets (for ECS tasks)
PRIVATE_SUBNET_1=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID \
  --cidr-block 10.0.3.0/24 \
  --availability-zone $AZ1 \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=OmniGuard-Private-1}]' \
  --query 'Subnet.SubnetId' \
  --output text)

PRIVATE_SUBNET_2=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID \
  --cidr-block 10.0.4.0/24 \
  --availability-zone $AZ2 \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=OmniGuard-Private-2}]' \
  --query 'Subnet.SubnetId' \
  --output text)

echo "PRIVATE_SUBNET_1=$PRIVATE_SUBNET_1"
echo "PRIVATE_SUBNET_2=$PRIVATE_SUBNET_2"
```

### 3.3 Create Internet Gateway

```bash
# Create Internet Gateway
IGW_ID=$(aws ec2 create-internet-gateway \
  --tag-specifications 'ResourceType=internet-gateway,Tags=[{Key=Name,Value=OmniGuard-IGW}]' \
  --query 'InternetGateway.InternetGatewayId' \
  --output text)

# Attach to VPC
aws ec2 attach-internet-gateway \
  --internet-gateway-id $IGW_ID \
  --vpc-id $VPC_ID

echo "IGW_ID=$IGW_ID"
```

### 3.4 Configure Route Tables

```bash
# Create route table for public subnets
PUBLIC_RT=$(aws ec2 create-route-table \
  --vpc-id $VPC_ID \
  --tag-specifications 'ResourceType=route-table,Tags=[{Key=Name,Value=OmniGuard-Public-RT}]' \
  --query 'RouteTable.RouteTableId' \
  --output text)

# Add route to Internet Gateway
aws ec2 create-route \
  --route-table-id $PUBLIC_RT \
  --destination-cidr-block 0.0.0.0/0 \
  --gateway-id $IGW_ID

# Associate public subnets with route table
aws ec2 associate-route-table --subnet-id $PUBLIC_SUBNET_1 --route-table-id $PUBLIC_RT
aws ec2 associate-route-table --subnet-id $PUBLIC_SUBNET_2 --route-table-id $PUBLIC_RT

# Enable auto-assign public IP for public subnets
aws ec2 modify-subnet-attribute --subnet-id $PUBLIC_SUBNET_1 --map-public-ip-on-launch
aws ec2 modify-subnet-attribute --subnet-id $PUBLIC_SUBNET_2 --map-public-ip-on-launch

# Create NAT Gateway for private subnets (optional, for outbound internet access)
# First allocate Elastic IP
EIP_ALLOC=$(aws ec2 allocate-address \
  --domain vpc \
  --tag-specifications 'ResourceType=elastic-ip,Tags=[{Key=Name,Value=OmniGuard-NAT-EIP}]' \
  --query 'AllocationId' \
  --output text)

# Create NAT Gateway in first public subnet
NAT_GW=$(aws ec2 create-nat-gateway \
  --subnet-id $PUBLIC_SUBNET_1 \
  --allocation-id $EIP_ALLOC \
  --tag-specifications 'ResourceType=natgateway,Tags=[{Key=Name,Value=OmniGuard-NAT}]' \
  --query 'NatGateway.NatGatewayId' \
  --output text)

echo "NAT Gateway creating... wait for it to be available"
aws ec2 wait nat-gateway-available --nat-gateway-ids $NAT_GW

# Create route table for private subnets
PRIVATE_RT=$(aws ec2 create-route-table \
  --vpc-id $VPC_ID \
  --tag-specifications 'ResourceType=route-table,Tags=[{Key=Name,Value=OmniGuard-Private-RT}]' \
  --query 'RouteTable.RouteTableId' \
  --output text)

# Route private traffic through NAT Gateway
aws ec2 create-route \
  --route-table-id $PRIVATE_RT \
  --destination-cidr-block 0.0.0.0/0 \
  --nat-gateway-id $NAT_GW

# Associate private subnets
aws ec2 associate-route-table --subnet-id $PRIVATE_SUBNET_1 --route-table-id $PRIVATE_RT
aws ec2 associate-route-table --subnet-id $PRIVATE_SUBNET_2 --route-table-id $PRIVATE_RT
```

### 3.5 Create Security Groups

```bash
# ALB Security Group (allows inbound HTTP/HTTPS from anywhere)
ALB_SG=$(aws ec2 create-security-group \
  --group-name OmniGuard-ALB-SG \
  --description "Security group for OmniGuard ALB" \
  --vpc-id $VPC_ID \
  --query 'GroupId' \
  --output text)

aws ec2 authorize-security-group-ingress \
  --group-id $ALB_SG \
  --protocol tcp \
  --port 80 \
  --cidr 0.0.0.0/0

aws ec2 authorize-security-group-ingress \
  --group-id $ALB_SG \
  --protocol tcp \
  --port 443 \
  --cidr 0.0.0.0/0

# ECS Task Security Group (allows inbound from ALB only)
ECS_SG=$(aws ec2 create-security-group \
  --group-name OmniGuard-ECS-SG \
  --description "Security group for OmniGuard ECS tasks" \
  --vpc-id $VPC_ID \
  --query 'GroupId' \
  --output text)

aws ec2 authorize-security-group-ingress \
  --group-id $ECS_SG \
  --protocol tcp \
  --port 80 \
  --source-group $ALB_SG

aws ec2 authorize-security-group-ingress \
  --group-id $ECS_SG \
  --protocol tcp \
  --port 443 \
  --source-group $ALB_SG

echo "ALB_SG=$ALB_SG"
echo "ECS_SG=$ECS_SG"
```

---

## Part 4: Container Registry (ECR)

### 4.1 Create ECR Repository

```bash
# Create ECR repository
aws ecr create-repository \
  --repository-name omniguard \
  --image-scanning-configuration scanOnPush=true \
  --encryption-configuration encryptionType=AES256

# Get repository URI
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region)
ECR_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/omniguard"

echo "ECR_URI=$ECR_URI"
```

### 4.2 Build and Push Docker Image

```bash
# Login to ECR
aws ecr get-login-password --region $REGION | \
  docker login --username AWS --password-stdin "${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

# Build the image (from omniguard directory)
cd /path/to/omniguard

docker build \
  --build-arg VITE_SUPABASE_URL="https://your-project.supabase.co" \
  --build-arg VITE_SUPABASE_ANON_KEY="your-anon-key" \
  --platform linux/amd64 \
  -t $ECR_URI:latest \
  -t $ECR_URI:$(date +%Y%m%d%H%M%S) \
  .

# Push to ECR
docker push $ECR_URI:latest
docker push $ECR_URI:$(date +%Y%m%d%H%M%S)
```

---

## Part 5: Secrets Management

### 5.1 Store Secrets in AWS Secrets Manager

```bash
# Store Supabase credentials
aws secretsmanager create-secret \
  --name omniguard/supabase-url \
  --secret-string "https://your-project.supabase.co" \
  --description "Supabase Project URL"

aws secretsmanager create-secret \
  --name omniguard/supabase-anon-key \
  --secret-string "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --description "Supabase Anon Key"

aws secretsmanager create-secret \
  --name omniguard/anthropic-api-key \
  --secret-string "sk-ant-..." \
  --description "Anthropic API Key for AI analysis"

# Store all secrets as a single JSON (alternative)
aws secretsmanager create-secret \
  --name omniguard/all-secrets \
  --secret-string '{
    "VITE_SUPABASE_URL": "https://your-project.supabase.co",
    "VITE_SUPABASE_ANON_KEY": "eyJ...",
    "ANTHROPIC_API_KEY": "sk-ant-...",
    "OPENAI_API_KEY": "sk-...",
    "GITHUB_TOKEN": "ghp_..."
  }' \
  --description "OmniGuard all secrets"
```

### 5.2 Update Task Execution Role for Secrets Access

```bash
# Create policy for Secrets Manager access
cat > secrets-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": [
        "arn:aws:secretsmanager:*:*:secret:omniguard/*"
      ]
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name OmniGuardECSTaskExecutionRole \
  --policy-name OmniGuardSecretsPolicy \
  --policy-document file://secrets-policy.json
```

---

## Part 6: Load Balancer (ALB)

### 6.1 Create Application Load Balancer

```bash
# Create ALB
ALB_ARN=$(aws elbv2 create-load-balancer \
  --name omniguard-alb \
  --subnets $PUBLIC_SUBNET_1 $PUBLIC_SUBNET_2 \
  --security-groups $ALB_SG \
  --type application \
  --query 'LoadBalancers[0].LoadBalancerArn' \
  --output text)

ALB_DNS=$(aws elbv2 describe-load-balancers \
  --load-balancer-arns $ALB_ARN \
  --query 'LoadBalancers[0].DNSName' \
  --output text)

echo "ALB_ARN=$ALB_ARN"
echo "ALB_DNS=$ALB_DNS"
```

### 6.2 Create Target Group

```bash
# Create target group for ECS tasks
TG_ARN=$(aws elbv2 create-target-group \
  --name omniguard-tg \
  --protocol HTTP \
  --port 80 \
  --vpc-id $VPC_ID \
  --target-type ip \
  --health-check-path /health \
  --health-check-interval-seconds 30 \
  --health-check-timeout-seconds 5 \
  --healthy-threshold-count 2 \
  --unhealthy-threshold-count 3 \
  --query 'TargetGroups[0].TargetGroupArn' \
  --output text)

echo "TG_ARN=$TG_ARN"
```

### 6.3 Create Listener (HTTP redirect to HTTPS)

```bash
# Create HTTP listener (redirect to HTTPS)
aws elbv2 create-listener \
  --load-balancer-arn $ALB_ARN \
  --protocol HTTP \
  --port 80 \
  --default-actions Type=redirect,RedirectConfig='{Protocol=HTTPS,Port=443,StatusCode=HTTP_301}'
```

---

## Part 7: SSL Certificate (ACM)

### 7.1 Request SSL Certificate

```bash
# Request certificate (replace with your domain)
CERT_ARN=$(aws acm request-certificate \
  --domain-name omniguard.yourdomain.com \
  --subject-alternative-names "*.omniguard.yourdomain.com" \
  --validation-method DNS \
  --query 'CertificateArn' \
  --output text)

echo "CERT_ARN=$CERT_ARN"

# Get validation records
aws acm describe-certificate \
  --certificate-arn $CERT_ARN \
  --query 'Certificate.DomainValidationOptions[0].ResourceRecord'
```

### 7.2 Create DNS Validation Records

If using Route53 for DNS:

```bash
# Get your hosted zone
HZ_ID=$(aws route53 list-hosted-zones \
  --query "HostedZones[?Name=='yourdomain.com.'].Id" \
  --output text | sed 's|/hostedzone/||')

# Get validation record details
VALIDATION_NAME=$(aws acm describe-certificate \
  --certificate-arn $CERT_ARN \
  --query 'Certificate.DomainValidationOptions[0].ResourceRecord.Name' \
  --output text)

VALIDATION_VALUE=$(aws acm describe-certificate \
  --certificate-arn $CERT_ARN \
  --query 'Certificate.DomainValidationOptions[0].ResourceRecord.Value' \
  --output text)

# Create validation record
cat > validation-record.json << EOF
{
  "Comment": "ACM certificate validation",
  "Changes": [{
    "Action": "CREATE",
    "ResourceRecordSet": {
      "Name": "$VALIDATION_NAME",
      "Type": "CNAME",
      "TTL": 300,
      "ResourceRecords": [{"Value": "$VALIDATION_VALUE"}]
    }
  }]
}
EOF

aws route53 change-resource-record-sets \
  --hosted-zone-id $HZ_ID \
  --change-batch file://validation-record.json

# Wait for validation
echo "Waiting for certificate validation..."
aws acm wait certificate-validated --certificate-arn $CERT_ARN
echo "Certificate validated!"
```

### 7.3 Create HTTPS Listener

```bash
# Create HTTPS listener
HTTPS_LISTENER_ARN=$(aws elbv2 create-listener \
  --load-balancer-arn $ALB_ARN \
  --protocol HTTPS \
  --port 443 \
  --certificates CertificateArn=$CERT_ARN \
  --default-actions Type=forward,TargetGroupArn=$TG_ARN \
  --query 'Listeners[0].ListenerArn' \
  --output text)

echo "HTTPS_LISTENER_ARN=$HTTPS_LISTENER_ARN"
```

---

## Part 8: ECS Cluster and Service

### 8.1 Create ECS Cluster

```bash
# Create ECS cluster
aws ecs create-cluster \
  --cluster-name omniguard-cluster \
  --settings name=containerInsights,value=enabled

# Create CloudWatch log group
aws logs create-log-group \
  --log-group-name /ecs/omniguard \
  --retention-in-days 30
```

### 8.2 Create Task Definition

Create file `task-definition.json`:

```json
{
  "family": "omniguard",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::ACCOUNT_ID:role/OmniGuardECSTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::ACCOUNT_ID:role/OmniGuardECSTaskRole",
  "containerDefinitions": [
    {
      "name": "omniguard",
      "image": "ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/omniguard:latest",
      "essential": true,
      "portMappings": [
        {
          "containerPort": 80,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "NODE_ENV",
          "value": "production"
        }
      ],
      "secrets": [
        {
          "name": "VITE_SUPABASE_URL",
          "valueFrom": "arn:aws:secretsmanager:REGION:ACCOUNT_ID:secret:omniguard/supabase-url"
        },
        {
          "name": "VITE_SUPABASE_ANON_KEY",
          "valueFrom": "arn:aws:secretsmanager:REGION:ACCOUNT_ID:secret:omniguard/supabase-anon-key"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/omniguard",
          "awslogs-region": "REGION",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "wget -qO- http://localhost/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      },
      "ulimits": [
        {
          "name": "nofile",
          "softLimit": 65536,
          "hardLimit": 65536
        }
      ]
    }
  ],
  "tags": [
    {
      "key": "Project",
      "value": "OmniGuard"
    },
    {
      "key": "Environment",
      "value": "Production"
    }
  ]
}
```

Update the placeholders and register:

```bash
# Replace placeholders
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region)

sed -i "s/ACCOUNT_ID/$ACCOUNT_ID/g" task-definition.json
sed -i "s/REGION/$REGION/g" task-definition.json

# Register task definition
aws ecs register-task-definition \
  --cli-input-json file://task-definition.json
```

### 8.3 Create ECS Service

```bash
# Create ECS service
aws ecs create-service \
  --cluster omniguard-cluster \
  --service-name omniguard-service \
  --task-definition omniguard \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={
    subnets=[$PRIVATE_SUBNET_1,$PRIVATE_SUBNET_2],
    securityGroups=[$ECS_SG],
    assignPublicIp=DISABLED
  }" \
  --load-balancers "targetGroupArn=$TG_ARN,containerName=omniguard,containerPort=80" \
  --health-check-grace-period-seconds 120 \
  --enable-execute-command \
  --tags key=Project,value=OmniGuard key=Environment,value=Production
```

---

## Part 9: Auto Scaling

### 9.1 Create Application Auto Scaling

```bash
# Register scalable target
aws application-autoscaling register-scalable-target \
  --service-namespace ecs \
  --resource-id service/omniguard-cluster/omniguard-service \
  --scalable-dimension ecs:service:DesiredCount \
  --min-capacity 2 \
  --max-capacity 10

# Create scaling policy based on CPU
aws application-autoscaling put-scaling-policy \
  --service-namespace ecs \
  --resource-id service/omniguard-cluster/omniguard-service \
  --scalable-dimension ecs:service:DesiredCount \
  --policy-name OmniGuardCPUScaling \
  --policy-type TargetTrackingScaling \
  --target-tracking-scaling-policy-configuration '{
    "TargetValue": 70.0,
    "PredefinedMetricSpecification": {
      "PredefinedMetricType": "ECSServiceAverageCPUUtilization"
    },
    "ScaleOutCooldown": 60,
    "ScaleInCooldown": 300
  }'

# Create scaling policy based on memory (optional)
aws application-autoscaling put-scaling-policy \
  --service-namespace ecs \
  --resource-id service/omniguard-cluster/omniguard-service \
  --scalable-dimension ecs:service:DesiredCount \
  --policy-name OmniGuardMemoryScaling \
  --policy-type TargetTrackingScaling \
  --target-tracking-scaling-policy-configuration '{
    "TargetValue": 80.0,
    "PredefinedMetricSpecification": {
      "PredefinedMetricType": "ECSServiceAverageMemoryUtilization"
    },
    "ScaleOutCooldown": 60,
    "ScaleInCooldown": 300
  }'
```

---

## Part 10: CloudFront CDN (Optional)

### 10.1 Create CloudFront Distribution

```bash
# Create CloudFront distribution
cat > cloudfront-config.json << EOF
{
  "CallerReference": "omniguard-$(date +%s)",
  "Aliases": {
    "Items": ["omniguard.yourdomain.com"],
    "Quantity": 1
  },
  "DefaultRootObject": "index.html",
  "Origins": {
    "Items": [{
      "DomainName": "$ALB_DNS",
      "Id": "omniguard-alb-origin",
      "CustomOriginConfig": {
        "HTTPPort": 80,
        "HTTPSPort": 443,
        "OriginProtocolPolicy": "https-only",
        "OriginSslProtocols": {
          "Items": ["TLSv1.2"],
          "Quantity": 1
        }
      }
    }],
    "Quantity": 1
  },
  "DefaultCacheBehavior": {
    "TargetOriginId": "omniguard-alb-origin",
    "ViewerProtocolPolicy": "redirect-to-https",
    "AllowedMethods": {
      "Items": ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"],
      "CachedMethods": {
        "Items": ["GET", "HEAD", "OPTIONS"],
        "Quantity": 3
      },
      "Quantity": 7
    },
    "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
    "OriginRequestPolicyId": "b689bdc-a69f-4526-8149-0ffd9c5e0a6d",
    "Compress": true,
    "SmoothStreaming": false
  },
  "PriceClass": "PriceClass_100",
  "ViewerCertificate": {
    "ACMCertificateArn": "$CERT_ARN",
    "SSLSupportMethod": "sni-only",
    "MinimumProtocolVersion": "TLSv1.2_2021",
    "Certificate": "$CERT_ARN",
    "CertificateSource": "acm"
  },
  "Enabled": true,
  "HttpVersion": "http2",
  "IsIPV6Enabled": true
}
EOF

CF_DISTRIBUTION_ID=$(aws cloudfront create-distribution \
  --distribution-config file://cloudfront-config.json \
  --query 'Distribution.Id' \
  --output text)

echo "CloudFront Distribution ID: $CF_DISTRIBUTION_ID"

# Wait for deployment
aws cloudfront wait distribution-deployed --id $CF_DISTRIBUTION_ID

# Get CloudFront domain
CF_DOMAIN=$(aws cloudfront get-distribution \
  --id $CF_DISTRIBUTION_ID \
  --query 'Distribution.DomainName' \
  --output text)

echo "CloudFront Domain: $CF_DOMAIN"
```

---

## Part 11: DNS Configuration (Route53)

### 11.1 Create DNS Records

```bash
# Get hosted zone
HZ_ID=$(aws route53 list-hosted-zones \
  --query "HostedZones[?contains(Name, 'yourdomain.com')].Id" \
  --output text | head -1 | sed 's|/hostedzone/||')

# Create ALIAS record for ALB or CloudFront
cat > dns-record.json << EOF
{
  "Comment": "Create ALIAS record for OmniGuard",
  "Changes": [{
    "Action": "CREATE",
    "ResourceRecordSet": {
      "Name": "omniguard.yourdomain.com",
      "Type": "A",
      "AliasTarget": {
        "HostedZoneId": "Z2FDTND73QX2GZ",
        "DNSName": "$CF_DOMAIN",
        "EvaluateTargetHealth": false
      }
    }
  }]
}
EOF

# For CloudFront, use Z2FDTND73QX2GZ as HostedZoneId
# For ALB, get it from: aws elbv2 describe-load-balancers --load-balancer-arns $ALB_ARN --query 'LoadBalancers[0].CanonicalHostedZoneId'

aws route53 change-resource-record-sets \
  --hosted-zone-id $HZ_ID \
  --change-batch file://dns-record.json
```

---

## Part 12: Monitoring and Logging

### 12.1 CloudWatch Dashboard

```bash
# Create CloudWatch dashboard
cat > dashboard-body.json << 'EOF'
{
  "widgets": [
    {
      "type": "metric",
      "x": 0,
      "y": 0,
      "width": 12,
      "height": 6,
      "properties": {
        "metrics": [
          ["AWS/ECS", "CPUUtilization", "ServiceName", "omniguard-service", "ClusterName", "omniguard-cluster"],
          [".", "MemoryUtilization", ".", ".", ".", "."]
        ],
        "period": 300,
        "stat": "Average",
        "region": "us-east-1",
        "title": "ECS Resource Utilization"
      }
    },
    {
      "type": "metric",
      "x": 0,
      "y": 6,
      "width": 12,
      "height": 6,
      "properties": {
        "metrics": [
          ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", "omniguard-alb"],
          [".", "TargetResponseTime", ".", "."],
          [".", "HTTPCode_Target_2XX_Count", ".", "."],
          [".", "HTTPCode_Target_4XX_Count", ".", "."],
          [".", "HTTPCode_Target_5XX_Count", ".", "."]
        ],
        "period": 300,
        "stat": "Sum",
        "region": "us-east-1",
        "title": "ALB Metrics"
      }
    }
  ]
}
EOF

aws cloudwatch put-dashboard \
  --dashboard-name OmniGuard-Production \
  --dashboard-body file://dashboard-body.json
```

### 12.2 CloudWatch Alarms

```bash
# High CPU alarm
aws cloudwatch put-metric-alarm \
  --alarm-name OmniGuard-HighCPU \
  --alarm-description "ECS CPU utilization > 80%" \
  --metric-name CPUUtilization \
  --namespace AWS/ECS \
  --statistic Average \
  --period 300 \
  --threshold 80 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2 \
  --dimensions Name=ServiceName,Value=omniguard-service Name=ClusterName,Value=omniguard-cluster \
  --evaluation-periods 2 \
  --datapoints-to-alarm 2 \
  --treat-missing-data breaching

# High Memory alarm
aws cloudwatch put-metric-alarm \
  --alarm-name OmniGuard-HighMemory \
  --alarm-description "ECS Memory utilization > 80%" \
  --metric-name MemoryUtilization \
  --namespace AWS/ECS \
  --statistic Average \
  --period 300 \
  --threshold 80 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2 \
  --dimensions Name=ServiceName,Value=omniguard-service Name=ClusterName,Value=omniguard-cluster

# ALB 5XX error alarm
aws cloudwatch put-metric-alarm \
  --alarm-name OmniGuard-ALB5XX \
  --alarm-description "ALB 5XX errors detected" \
  --metric-name HTTPCode_Target_5XX_Count \
  --namespace AWS/ApplicationELB \
  --statistic Sum \
  --period 60 \
  --threshold 10 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --dimensions Name=LoadBalancer,Value=omniguard-alb

# Create SNS topic for alerts
SNS_ARN=$(aws sns create-topic \
  --name OmniGuard-Alerts \
  --query 'TopicArn' \
  --output text)

# Subscribe your email
aws sns subscribe \
  --topic-arn $SNS_ARN \
  --protocol email \
  --notification-endpoint your-email@example.com

# Add alarm actions
aws cloudwatch put-metric-alarm \
  --alarm-name OmniGuard-HighCPU \
  --alarm-actions $SNS_ARN

aws cloudwatch put-metric-alarm \
  --alarm-name OmniGuard-HighMemory \
  --alarm-actions $SNS_ARN

aws cloudwatch put-metric-alarm \
  --alarm-name OmniGuard-ALB5XX \
  --alarm-actions $SNS_ARN
```

---

## Part 13: Deployment Script

Save this as `deploy-aws-production.sh`:

```bash
#!/usr/bin/env bash
# OmniGuard AWS Production Deployment
# Usage: ./deploy-aws-production.sh

set -euo pipefail

# Configuration
export AWS_REGION="${AWS_REGION:-us-east-1}"
export APP_NAME="omniguard"
export ENVIRONMENT="production"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# Prerequisites
command -v aws >/dev/null 2>&1 || error "AWS CLI not found"
command -v docker >/dev/null 2>&1 || error "Docker not found"
command -v jq >/dev/null 2>&1 || error "jq not found"

# Get AWS account ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
info "Deploying to AWS account: $AWS_ACCOUNT_ID"

# Variables
ECR_REPO="${APP_NAME}"
ECR_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO}"
TIMESTAMP=$(date +%Y%m%d%H%M%S)
IMAGE_TAG="${TIMESTAMP}"

# Login to ECR
info "Logging in to ECR..."
aws ecr get-login-password --region $AWS_REGION | \
  docker login --username AWS --password-stdin "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

# Ensure ECR repository exists
aws ecr describe-repositories --repository-names $ECR_REPO --region $AWS_REGION >/dev/null 2>&1 || \
  aws ecr create-repository --repository-name $ECR_REPO --region $AWS_REGION

# Build Docker image
info "Building Docker image..."
docker build \
  --platform linux/amd64 \
  -t "${ECR_URI}:${IMAGE_TAG}" \
  -t "${ECR_URI}:latest" \
  .

# Push to ECR
info "Pushing to ECR..."
docker push "${ECR_URI}:${IMAGE_TAG}"
docker push "${ECR_URI}:latest"

# Update ECS service
info "Updating ECS service..."
NEW_TASK_DEF=$(aws ecs describe-task-definition \
  --task-definition $APP_NAME \
  --query 'taskDefinition' \
  --output json | \
  jq --arg IMAGE "${ECR_URI}:${IMAGE_TAG}" '.containerDefinitions[0].image = $IMAGE' | \
  jq 'del(.taskDefinitionArn, .revision, .status, .requiresAttributes, .compatibilities, .registeredBy, .registeredAt)')

aws ecs register-task-definition --cli-input-json "$NEW_TASK_DEF" >/dev/null

# Force new deployment
aws ecs update-service \
  --cluster ${APP_NAME}-cluster \
  --service ${APP_NAME}-service \
  --force-new-deployment \
  --region $AWS_REGION >/dev/null

# Wait for deployment
info "Waiting for deployment to stabilize..."
aws ecs wait services-stable \
  --cluster ${APP_NAME}-cluster \
  --services ${APP_NAME}-service \
  --region $AWS_REGION

info "Deployment complete!"
info "Image: ${ECR_URI}:${IMAGE_TAG}"

# Get ALB URL
ALB_DNS=$(aws elbv2 describe-load-balancers \
  --names ${APP_NAME}-alb \
  --query 'LoadBalancers[0].DNSName' \
  --output text 2>/dev/null || echo "Check AWS Console for ALB URL")

info "Access your application at: https://$ALB_DNS"
```

Make executable:
```bash
chmod +x deploy-aws-production.sh
```

---

## Part 14: CI/CD Pipeline (GitHub Actions)

Create `.github/workflows/deploy-aws.yml`:

```yaml
name: Deploy to AWS Production

on:
  push:
    branches: [main]
  workflow_dispatch:
    inputs:
      environment:
        description: 'Environment'
        required: true
        default: 'production'
        type: choice
        options:
          - production
          - staging

env:
  AWS_REGION: us-east-1
  ECR_REPOSITORY: omniguard
  ECS_CLUSTER: omniguard-cluster
  ECS_SERVICE: omniguard-service
  ECS_TASK_DEFINITION: omniguard

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: ${{ github.event.inputs.environment || 'production' }}

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ env.AWS_REGION }}

      - name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v2

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Build and push Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          file: ./Dockerfile
          push: true
          tags: |
            ${{ steps.login-ecr.outputs.registry }}/${{ env.ECR_REPOSITORY }}:${{ github.sha }}
            ${{ steps.login-ecr.outputs.registry }}/${{ env.ECR_REPOSITORY }}:latest
          build-args: |
            VITE_SUPABASE_URL=${{ secrets.VITE_SUPABASE_URL }}
            VITE_SUPABASE_ANON_KEY=${{ secrets.VITE_SUPABASE_ANON_KEY }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
          platforms: linux/amd64

      - name: Fill in the new image ID in the Amazon ECS task definition
        id: task-def
        uses: aws-actions/amazon-ecs-render-task-definition@v1
        with:
          task-definition-family: ${{ env.ECS_TASK_DEFINITION }}
          container-name: omniguard
          image: ${{ steps.login-ecr.outputs.registry }}/${{ env.ECR_REPOSITORY }}:${{ github.sha }}

      - name: Deploy Amazon ECS task definition
        uses: aws-actions/amazon-ecs-deploy-task-definition@v1
        with:
          task-definition: ${{ steps.task-def.outputs.task-definition }}
          service: ${{ env.ECS_SERVICE }}
          cluster: ${{ env.ECS_CLUSTER }}
          wait-for-service-stability: true

      - name: Notify on success
        if: success()
        run: |
          echo "Deployment successful!"
          # Add Slack/Teams notification here

      - name: Notify on failure
        if: failure()
        run: |
          echo "Deployment failed!"
          # Add Slack/Teams alert here
```

Add secrets to your GitHub repository:
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `VITE_SUPABASE_URL`
- `VITE_SUPABASE_ANON_KEY`

---

## Part 15: Verification

### 15.1 Health Check

```bash
# Check ECS service status
aws ecs describe-services \
  --cluster omniguard-cluster \
  --services omniguard-service \
  --query 'services[0].[status,runningCount,desiredCount]' \
  --output table

# Check ALB target health
aws elbv2 describe-target-health \
  --target-group-arn $TG_ARN

# Check application health
curl -s https://omniguard.yourdomain.com/health | jq
```

### 15.2 View Logs

```bash
# ECS logs
aws logs tail /ecs/omniguard --follow

# Last 100 lines
aws logs get-log-events \
  --log-group-name /ecs/omniguard \
  --log-stream-name-prefix ecs/omniguard \
  --limit 100
```

### 15.3 Test the Stack

```bash
# Test main endpoint
curl https://omniguard.yourdomain.com/

# Test health endpoint
curl https://omniguard.yourdomain.com/health

# Test API endpoint (via Supabase)
curl https://your-project.supabase.co/functions/v1/api-v1-status
```

---

## Part 16: Maintenance

### 16.1 Scaling

```bash
# Scale up
aws ecs update-service \
  --cluster omniguard-cluster \
  --service omniguard-service \
  --desired-count 4

# Scale down
aws ecs update-service \
  --cluster omniguard-cluster \
  --service omniguard-service \
  --desired-count 2
```

### 16.2 Update Task Definition

```bash
# Update CPU/Memory
aws ecs register-task-definition \
  --family omniguard \
  --cpu 1024 \
  --memory 2048 \
  --network-mode awsvpc \
  --requires-compatibilities FARGATE \
  --execution-role-arn arn:aws:iam::$AWS_ACCOUNT_ID:role/OmniGuardECSTaskExecutionRole \
  --task-role-arn arn:aws:iam::$AWS_ACCOUNT_ID:role/OmniGuardECSTaskRole \
  --container-definitions '[...]'

# Update service with new task definition
aws ecs update-service \
  --cluster omniguard-cluster \
  --service omniguard-service \
  --task-definition omniguard:N  # N is the new revision number
```

### 16.3 Backup and Recovery

```bash
# Export task definition
aws ecs describe-task-definition \
  --task-definition omniguard \
  --query 'taskDefinition' > task-definition-backup.json

# ECR image lifecycle policy (clean old images)
aws ecr put-lifecycle-policy \
  --repository-name omniguard \
  --lifecycle-policy-text '{
    "rules": [
      {
        "rulePriority": 1,
        "description": "Keep last 10 images",
        "selection": {
          "tagStatus": "tagged",
          "tagPrefixList": ["20"],
          "countType": "imageCountMoreThan",
          "countNumber": 10
        },
        "action": { "type": "expire" }
      }
    ]
  }'
```

---

## Part 17: Cost Estimation

### Monthly Costs (us-east-1, estimated)

| Service | Configuration | Monthly Cost |
|---------|---------------|--------------|
| ECS Fargate | 2 tasks, 0.5 vCPU, 1GB | ~$30 |
| Application Load Balancer | 1 ALB | ~$20 |
| NAT Gateway | 1 NAT Gateway | ~$32 |
| Data Transfer | 50GB outbound | ~$5 |
| ECR | 2GB storage | ~$2 |
| CloudWatch Logs | 5GB ingestion | ~$5 |
| Route53 | 1 hosted zone | ~$0.50 |
| Secrets Manager | 4 secrets | ~$2 |
| **Total** | | **~$100/month** |

### Cost Optimization Tips

1. **Use Savings Plans** for long-term workloads (up to 72% off)
2. **Right-size your tasks** - monitor utilization and adjust
3. **Use Spot capacity** for non-critical workloads
4. **Delete unused resources** - especially NAT Gateways when not needed
5. **Enable S3 Intelligent Tiering** for logs
6. **Consider ECS capacity providers** for better Spot integration

---

## Troubleshooting

### Common Issues

**Service fails to start:**
```bash
# Check stopped tasks
aws ecs list-tasks \
  --cluster omniguard-cluster \
  --service-name omniguard-service \
  --desired-status STOPPED

# Get stopped task details
aws ecs describe-tasks \
  --cluster omniguard-cluster \
  --tasks TASK_ARN \
  --query 'tasks[0].stoppedReason'
```

**Image pull errors:**
```bash
# Verify ECR permissions
aws ecr batch-get-image \
  --repository-name omniguard \
  --image-ids imageTag=latest

# Check task execution role
aws iam get-role-policy \
  --role-name OmniGuardECSTaskExecutionRole \
  --policy-name OmniGuardSecretsPolicy
```

**ALB health check failures:**
```bash
# Check target health
aws elbv2 describe-target-health \
  --target-group-arn $TG_ARN

# Check security groups
aws ec2 describe-security-groups \
  --group-ids $ECS_SG
```

**Cannot connect to Supabase:**
- Check VPC DNS resolution is enabled
- Verify outbound internet access via NAT Gateway
- Check security group allows HTTPS outbound

---

## Support

- **AWS Documentation**: https://docs.aws.amazon.com/ecs/
- **AWS Support**: Available through AWS Console
- **OmniGuard Issues**: https://github.com/omniguard/omniguard/issues

---

## Quick Reference Commands

```bash
# View all resources
aws resourcegroupstaggingapi get-resources --tag-filters Key=Project,Value=OmniGuard

# Quick redeploy
aws ecs update-service --cluster omniguard-cluster --service omniguard-service --force-new-deployment

# View logs
aws logs tail /ecs/omniguard --follow

# Scale service
aws ecs update-service --cluster omniguard-cluster --service omniguard-service --desired-count 4

# Get public URL
aws elbv2 describe-load-balancers --names omniguard-alb --query 'LoadBalancers[0].DNSName' --output text
```
