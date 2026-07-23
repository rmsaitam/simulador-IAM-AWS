"""Simulação de serviços AWS (S3, EC2, Lambda, DynamoDB, RDS, SNS, SQS, ECS, ECR, EKS)."""

from dataclasses import dataclass, field


@dataclass
class ServiceResource:
    """Recurso simulado de um serviço AWS."""
    service: str
    resource_type: str
    name: str
    arn: str
    metadata: dict = field(default_factory=dict)


# Mapeamento de serviços para ações comuns
SERVICE_ACTIONS: dict[str, list[str]] = {
    "s3": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket",
        "s3:GetBucketPolicy",
        "s3:PutBucketPolicy",
        "s3:DeleteBucketPolicy",
        "s3:GetBucketAcl",
        "s3:PutBucketAcl",
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:GetBucketVersioning",
        "s3:PutBucketVersioning",
        "s3:GetBucketEncryption",
        "s3:PutBucketEncryption",
        "s3:ListAllMyBuckets",
    ],
    "ec2": [
        "ec2:DescribeInstances",
        "ec2:RunInstances",
        "ec2:TerminateInstances",
        "ec2:StopInstances",
        "ec2:StartInstances",
        "ec2:RebootInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:CreateSecurityGroup",
        "ec2:DeleteSecurityGroup",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CreateKeyPair",
        "ec2:DeleteKeyPair",
        "ec2:DescribeKeyPairs",
        "ec2:DescribeImages",
        "ec2:DescribeVolumes",
        "ec2:CreateVolume",
        "ec2:DeleteVolume",
        "ec2:AttachVolume",
        "ec2:DetachVolume",
    ],
    "lambda": [
        "lambda:InvokeFunction",
        "lambda:InvokeAsync",
        "lambda:CreateFunction",
        "lambda:DeleteFunction",
        "lambda:GetFunction",
        "lambda:GetFunctionConfiguration",
        "lambda:ListFunctions",
        "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration",
        "lambda:AddPermission",
        "lambda:RemovePermission",
        "lambda:CreateEventSourceMapping",
        "lambda:DeleteEventSourceMapping",
    ],
    "dynamodb": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:DeleteItem",
        "dynamodb:UpdateItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:BatchGetItem",
        "dynamodb:BatchWriteItem",
        "dynamodb:CreateTable",
        "dynamodb:DeleteTable",
        "dynamodb:DescribeTable",
        "dynamodb:ListTables",
        "dynamodb:DescribeTimeToLive",
        "dynamodb:UpdateTimeToLive",
    ],
    "rds": [
        "rds:DescribeDBInstances",
        "rds:CreateDBInstance",
        "rds:DeleteDBInstance",
        "rds:StopDBInstance",
        "rds:StartDBInstance",
        "rds:RebootDBInstance",
        "rds:DescribeDBClusters",
        "rds:CreateDBCluster",
        "rds:DeleteDBCluster",
        "rds:ModifyDBInstance",
        "rds:CreateDBSnapshot",
        "rds:DeleteDBSnapshot",
        "rds:RestoreDBInstanceFromDBSnapshot",
        "rds:AddTagsToResource",
        "rds:RemoveTagsFromResource",
    ],
    "sns": [
        "sns:Publish",
        "sns:Subscribe",
        "sns:Unsubscribe",
        "sns:CreateTopic",
        "sns:DeleteTopic",
        "sns:GetTopicAttributes",
        "sns:SetTopicAttributes",
        "sns:ListTopics",
        "sns:ListSubscriptions",
        "sns:GetSubscriptionAttributes",
        "sns:SetSubscriptionAttributes",
    ],
    "sqs": [
        "sqs:SendMessage",
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:SetQueueAttributes",
        "sqs:CreateQueue",
        "sqs:DeleteQueue",
        "sqs:ListQueues",
        "sqs:GetQueueUrl",
        "sqs:ChangeMessageVisibility",
        "sqs:PurgeQueue",
    ],
    "ecs": [
        "ecs:DescribeClusters",
        "ecs:CreateCluster",
        "ecs:DeleteCluster",
        "ecs:ListClusters",
        "ecs:DescribeServices",
        "ecs:CreateService",
        "ecs:UpdateService",
        "ecs:DeleteService",
        "ecs:DescribeTaskDefinition",
        "ecs:RegisterTaskDefinition",
        "ecs:DeregisterTaskDefinition",
        "ecs:RunTask",
        "ecs:StopTask",
        "ecs:DescribeTasks",
        "ecs:ListTasks",
    ],
    "ecr": [
        "ecr:DescribeRepositories",
        "ecr:CreateRepository",
        "ecr:DeleteRepository",
        "ecr:ListRepositories",
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:PutImage",
        "ecr:InitiateLayerUpload",
        "ecr:UploadLayerPart",
        "ecr:CompleteLayerUpload",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "ecr:DescribeImages",
        "ecr:DeleteImage",
        "ecr:SetRepositoryPolicy",
        "ecr:DeleteRepositoryPolicy",
        "ecr:GetRepositoryPolicy",
    ],
    "eks": [
        "eks:DescribeCluster",
        "eks:CreateCluster",
        "eks:DeleteCluster",
        "eks:ListClusters",
        "eks:DescribeNodegroup",
        "eks:CreateNodegroup",
        "eks:DeleteNodegroup",
        "eks:UpdateNodegroupConfig",
        "eks:UpdateNodegroupVersion",
        "eks:DescribeFargateProfile",
        "eks:CreateFargateProfile",
        "eks:DeleteFargateProfile",
        "eks:ListFargateProfiles",
        "eks:AccessKubernetesApi",
    ],
}


def get_service_from_arn(arn: str) -> str:
    """Extrai o serviço de um ARN. Ex: arn:aws:s3:::bucket -> s3"""
    parts = arn.split(":")
    if len(parts) >= 3:
        return parts[2]
    return ""


def get_actions_for_service(service: str) -> list[str]:
    """Retorna ações disponíveis para um serviço."""
    return SERVICE_ACTIONS.get(service.lower(), [])


def list_services() -> list[str]:
    """Lista todos os serviços simulados."""
    return sorted(SERVICE_ACTIONS.keys())


def validate_action(action: str) -> bool:
    """Verifica se uma ação é válida para o serviço especificado."""
    service = action.split(":")[0].lower() if ":" in action else ""
    if not service:
        return False
    actions = get_actions_for_service(service)
    return action in actions or f"{service}:*" in actions
