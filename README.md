# IAM Simulator - CLI

Simulador CLI do AWS IAM para testar políticas de acesso a recursos AWS.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Exemplo Completo: Grupo Developer + Usuário Admin

### 1. Criar as Políticas

```bash
# EC2 - Pode acessar, NÃO pode desligar (terminate)
iam policy create EC2DeveloperPolicy --file --document policies/EC2DeveloperPolicy.json

# S3 - Pode criar, listar, editar, NÃO pode apagar
iam policy create S3DeveloperPolicy --file --document policies/S3DeveloperPolicy.json

# DynamoDB - Pode CRUD, NÃO pode dropar tabela
iam policy create DynamoDBDeveloperPolicy --file --document policies/DynamoDBDeveloperPolicy.json

# RDS - Pode CRUD, NÃO pode dropar banco
iam policy create RDSDeveloperPolicy --file --document policies/RDSDeveloperPolicy.json

# ECS, ECR, EKS, SNS, SQS - Acesso total
iam policy create CloudServicesFullAccess --file --document policies/CloudServicesFullAccess.json

# Admin - Acesso total
iam policy create AdministratorAccess --file --document policies/AdministratorAccess.json
```

### 2. Criar o Grupo Developer

```bash
iam group create Developers \
  --policies EC2DeveloperPolicy,S3DeveloperPolicy,DynamoDBDeveloperPolicy,RDSDeveloperPolicy,CloudServicesFullAccess
```

### 3. Criar os Usuários

```bash
# Usuário com permissão total
iam user create admin --policies AdministratorAccess

# Usuário no grupo Developers (herda todas as políticas do grupo)
iam user create dev-joao --groups Developers
```

### 4. Testar Acesso - Developer

```bash
# EC2 - Pode listar instâncias
$ iam sim-access --user dev-joao --action ec2:DescribeInstances \
    --resource "arn:aws:ec2:us-east-1:123456789012:instance/*"

  Access Granted
  User: dev-joao successfully accessed ec2:DescribeInstances
  Matched policies: EC2DeveloperPolicy

# EC2 - NÃO pode desligar instância
$ iam sim-access --user dev-joao --action ec2:TerminateInstances \
    --resource "arn:aws:ec2:us-east-1:123456789012:instance/*"

  An error occurred (AccessDeniedException) when calling the TerminateInstances operation:
  User: arn:aws:iam::123456789012:user/dev-joao is not authorized to perform: ec2:TerminateInstances
  Explicit deny by policy: EC2DeveloperPolicy

# S3 - Pode criar objeto
$ iam sim-access --user dev-joao --action s3:PutObject \
    --resource "arn:aws:s3:::meu-bucket/arquivo.txt"

  Access Granted

# S3 - NÃO pode apagar objeto
$ iam sim-access --user dev-joao --action s3:DeleteObject \
    --resource "arn:aws:s3:::meu-bucket/arquivo.txt"

  An error occurred (AccessDeniedException) when calling the DeleteObject operation:
  Explicit deny by policy: S3DeveloperPolicy

# DynamoDB - Pode inserir item
$ iam sim-access --user dev-joao --action dynamodb:PutItem \
    --resource "arn:aws:dynamodb:us-east-1:123456789012:table/Users"

  Access Granted

# DynamoDB - NÃO pode dropar tabela
$ iam sim-access --user dev-joao --action dynamodb:DeleteTable \
    --resource "arn:aws:dynamodb:us-east-1:123456789012:table/Users"

  An error occurred (AccessDeniedException) when calling the DeleteTable operation:
  Explicit deny by policy: DynamoDBDeveloperPolicy

# RDS - Pode modificar instância
$ iam sim-access --user dev-joao --action rds:ModifyDBInstance \
    --resource "arn:aws:rds:us-east-1:123456789012:db:mydb"

  Access Granted

# RDS - NÃO pode deletar instância
$ iam sim-access --user dev-joao --action rds:DeleteDBInstance \
    --resource "arn:aws:rds:us-east-1:123456789012:db:mydb"

  An error occurred (AccessDeniedException) when calling the DeleteDBInstance operation:
  Explicit deny by policy: RDSDeveloperPolicy

# ECS/ECR/EKS/SNS/SQS - Pode tudo
$ iam sim-access --user dev-joao --action ecs:RunTask \
    --resource "arn:aws:ecs:us-east-1:123456789012:cluster/mycluster"
  Access Granted

$ iam sim-access --user dev-joao --action sns:Publish \
    --resource "arn:aws:sns:us-east-1:123456789012:mytopic"
  Access Granted

$ iam sim-access --user dev-joao --action sqs:SendMessage \
    --resource "arn:aws:sqs:us-east-1:123456789012:myqueue"
  Access Granted
```

### 5. Testar Acesso - Admin (acesso total)

```bash
$ iam sim-access --user admin --action ec2:TerminateInstances \
    --resource "arn:aws:ec2:us-east-1:123456789012:instance/*"
  Access Granted

$ iam sim-access --user admin --action s3:DeleteObject \
    --resource "arn:aws:s3:::bucket/file.txt"
  Access Granted

$ iam sim-access --user admin --action dynamodb:DeleteTable \
    --resource "arn:aws:dynamodb:us-east-1:123456789012:table/Users"
  Access Granted

$ iam sim-access --user admin --action rds:DeleteDBInstance \
    --resource "arn:aws:rds:us-east-1:123456789012:db:mydb"
  Access Granted
```

## Resumo das Permissões

| Serviço | Developer | Admin |
|---------|-----------|-------|
| EC2 | Read, Start, Stop, Reboot | Tudo |
| EC2 Terminate | **NEGADO** | Permitido |
| S3 | Get, Put, List, Create | Tudo |
| S3 Delete | **NEGADO** | Permitido |
| DynamoDB | Get, Put, Update, Delete, Query, Scan | Tudo |
| DynamoDB DeleteTable/CreateTable | **NEGADO** | Permitido |
| RDS | Describe, Create, Modify, Start, Stop | Tudo |
| RDS Delete | **NEGADO** | Permitido |
| ECS | Tudo | Tudo |
| ECR | Tudo | Tudo |
| EKS | Tudo | Tudo |
| SNS | Tudo | Tudo |
| SQS | Tudo | Tudo |

## Comandos

### Usuários

```bash
iam user create <nome> [--groups g1,g2] [--policies p1,p2]
iam user list [--verbose]
iam user get <nome>
iam user delete <nome>
iam user attach-policy <user> <policy>
iam user detach-policy <user> <policy>
iam user add-group <user> <group>
iam user remove-group <user> <group>
```

### Grupos

```bash
iam group create <nome> [--policies p1,p2]
iam group list [--verbose]
iam group get <nome>
iam group delete <nome>
iam group attach-policy <group> <policy>
iam group detach-policy <group> <policy>
```

### Políticas

```bash
iam policy create <nome> --document '{"Version":"2012-10-17","Statement":[...]}'
iam policy create <nome> --document ./policy.json --file
iam policy list [--verbose]
iam policy get <nome>
iam policy delete <nome>
```

### Roles

```bash
iam role create <nome> [--trust-policy <json>] [--policies p1,p2]
iam role list [--verbose]
iam role get <nome>
iam role delete <nome>
iam role attach-policy <role> <policy>
iam role detach-policy <role> <policy>
```

### Simulação de Acesso

```bash
iam sim-access --user <user> --action <action> --resource <arn>
iam sim-access --role <role> --action <action> --resource <arn>
iam sim-access --user <user> --action <action> --resource <arn> --json-output
```

### Utilitários

```bash
iam stats          # Estatísticas
iam seed           # Dados de exemplo alternativos
iam services       # Serviços e ações disponíveis
iam export         # Exportar dados (json/table)
```

## Lógica de Avaliação

1. Coleta todas as políticas aplicáveis (inline + gerenciadas + grupos)
2. Verifica **Explicit Deny** (sempre vence)
3. Verifica **Allow** (pelo menos uma política deve permitir)
4. Sem allow = **ImplicitDeny**

## Testes

```bash
source venv/bin/activate
pytest tests/ -v
pytest tests/ --cov=iam_simulator
```
