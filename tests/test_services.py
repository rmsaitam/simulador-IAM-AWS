"""Testes para o módulo de serviços AWS simulados."""

from iam_simulator.services import (
    get_service_from_arn,
    get_actions_for_service,
    list_services,
    validate_action,
    SERVICE_ACTIONS,
)


class TestServiceFromArn:
    def test_s3(self):
        assert get_service_from_arn("arn:aws:s3:::my-bucket") == "s3"

    def test_ec2(self):
        assert get_service_from_arn("arn:aws:ec2:us-east-1:123456789012:instance/i-123") == "ec2"

    def test_lambda(self):
        assert get_service_from_arn("arn:aws:lambda:us-east-1:123456789012:function:my-func") == "lambda"

    def test_unknown(self):
        assert get_service_from_arn("invalid-arn") == ""


class TestServiceActions:
    def test_s3_actions(self):
        actions = get_actions_for_service("s3")
        assert "s3:GetObject" in actions
        assert "s3:PutObject" in actions
        assert "s3:DeleteObject" in actions

    def test_ec2_actions(self):
        actions = get_actions_for_service("ec2")
        assert "ec2:DescribeInstances" in actions
        assert "ec2:RunInstances" in actions

    def test_unknown_service(self):
        assert get_actions_for_service("unknown") == []


class TestListServices:
    def test_all_services(self):
        services = list_services()
        assert "s3" in services
        assert "ec2" in services
        assert "lambda" in services
        assert "dynamodb" in services
        assert "rds" in services
        assert "sns" in services
        assert "sqs" in services
        assert "ecs" in services
        assert "ecr" in services
        assert "eks" in services


class TestValidateAction:
    def test_valid_action(self):
        assert validate_action("s3:GetObject") is True

    def test_invalid_action(self):
        assert validate_action("s3:InvalidAction") is False

    def test_no_colon(self):
        assert validate_action("invalid") is False
