"""Testes de integração para o CLI."""

import json
import pytest
from click.testing import CliRunner
from iam_simulator.cli import cli
from iam_simulator.storage import DEFAULT_DATA_FILE


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture(autouse=True)
def clean_data(tmp_path):
    """Usa arquivo temporário para dados durante testes."""
    import iam_simulator.cli as cli_mod
    import iam_simulator.storage as storage_mod

    test_data_file = tmp_path / "test_iam_data.json"
    original = storage_mod.DEFAULT_DATA_FILE
    storage_mod.DEFAULT_DATA_FILE = test_data_file
    cli_mod.DATA_FILE = test_data_file

    yield test_data_file

    storage_mod.DEFAULT_DATA_FILE = original
    cli_mod.DATA_FILE = None


class TestUserCommands:
    def test_create_user(self, runner, clean_data):
        result = runner.invoke(cli, ["user", "create", "testuser"])
        assert result.exit_code == 0
        assert "created successfully" in result.output

    def test_create_user_already_exists(self, runner, clean_data):
        runner.invoke(cli, ["user", "create", "testuser"])
        result = runner.invoke(cli, ["user", "create", "testuser"])
        assert result.exit_code == 1
        assert "already exists" in result.output

    def test_list_users(self, runner, clean_data):
        runner.invoke(cli, ["user", "create", "user1"])
        runner.invoke(cli, ["user", "create", "user2"])
        result = runner.invoke(cli, ["user", "list"])
        assert result.exit_code == 0
        assert "user1" in result.output
        assert "user2" in result.output

    def test_delete_user(self, runner, clean_data):
        runner.invoke(cli, ["user", "create", "testuser"])
        result = runner.invoke(cli, ["user", "delete", "testuser"])
        assert result.exit_code == 0
        assert "deleted successfully" in result.output

    def test_delete_user_not_found(self, runner, clean_data):
        result = runner.invoke(cli, ["user", "delete", "nonexistent"])
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_get_user(self, runner, clean_data):
        runner.invoke(cli, ["user", "create", "testuser"])
        result = runner.invoke(cli, ["user", "get", "testuser"])
        assert result.exit_code == 0
        assert "User: testuser" in result.output


class TestGroupCommands:
    def test_create_group(self, runner, clean_data):
        result = runner.invoke(cli, ["group", "create", "testgroup"])
        assert result.exit_code == 0
        assert "created successfully" in result.output

    def test_list_groups(self, runner, clean_data):
        runner.invoke(cli, ["group", "create", "g1"])
        result = runner.invoke(cli, ["group", "list"])
        assert result.exit_code == 0
        assert "g1" in result.output

    def test_add_user_to_group(self, runner, clean_data):
        runner.invoke(cli, ["user", "create", "testuser"])
        runner.invoke(cli, ["group", "create", "testgroup"])
        result = runner.invoke(cli, ["user", "add-group", "testuser", "testgroup"])
        assert result.exit_code == 0
        assert "added to group" in result.output


class TestPolicyCommands:
    def test_create_policy(self, runner, clean_data):
        policy_doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:Get*"], "Resource": ["*"]}],
        })
        result = runner.invoke(cli, ["policy", "create", "TestPolicy", "--document", policy_doc])
        assert result.exit_code == 0
        assert "created successfully" in result.output

    def test_list_policies(self, runner, clean_data):
        policy_doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}],
        })
        runner.invoke(cli, ["policy", "create", "P1", "--document", policy_doc])
        result = runner.invoke(cli, ["policy", "list"])
        assert result.exit_code == 0
        assert "P1" in result.output

    def test_get_policy(self, runner, clean_data):
        policy_doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}],
        })
        runner.invoke(cli, ["policy", "create", "P1", "--document", policy_doc])
        result = runner.invoke(cli, ["policy", "get", "P1"])
        assert result.exit_code == 0
        assert "Policy: P1" in result.output


class TestSimAccess:
    def test_access_allowed(self, runner, clean_data):
        policy_doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::my-bucket/*"]}],
        })
        runner.invoke(cli, ["policy", "create", "S3Read", "--document", policy_doc])
        runner.invoke(cli, ["user", "create", "alice", "--policies", "S3Read"])

        result = runner.invoke(cli, [
            "sim-access", "--user", "alice",
            "--action", "s3:GetObject",
            "--resource", "arn:aws:s3:::my-bucket/file.txt",
        ])
        assert result.exit_code == 0
        assert "Access Granted" in result.output

    def test_access_denied(self, runner, clean_data):
        policy_doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::my-bucket/*"]}],
        })
        runner.invoke(cli, ["policy", "create", "S3Read", "--document", policy_doc])
        runner.invoke(cli, ["user", "create", "bob", "--policies", "S3Read"])

        result = runner.invoke(cli, [
            "sim-access", "--user", "bob",
            "--action", "s3:PutObject",
            "--resource", "arn:aws:s3:::my-bucket/file.txt",
        ])
        assert result.exit_code == 0
        assert "AccessDeniedException" in result.output

    def test_explicit_deny_overrides_allow(self, runner, clean_data):
        allow_doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": ["arn:aws:s3:::*/*"]}],
        })
        deny_doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": ["s3:DeleteObject"], "Resource": ["arn:aws:s3:::*/*"]}],
        })
        runner.invoke(cli, ["policy", "create", "AllowAll", "--document", allow_doc])
        runner.invoke(cli, ["policy", "create", "DenyDelete", "--document", deny_doc])
        runner.invoke(cli, ["user", "create", "charlie", "--policies", "AllowAll,DenyDelete"])

        result = runner.invoke(cli, [
            "sim-access", "--user", "charlie",
            "--action", "s3:DeleteObject",
            "--resource", "arn:aws:s3:::my-bucket/file.txt",
        ])
        assert result.exit_code == 0
        assert "AccessDeniedException" in result.output
        assert "Explicit deny" in result.output

    def test_group_policy_access(self, runner, clean_data):
        policy_doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["ec2:Describe*"], "Resource": ["*"]}],
        })
        runner.invoke(cli, ["policy", "create", "EC2Read", "--document", policy_doc])
        runner.invoke(cli, ["group", "create", "Readers", "--policies", "EC2Read"])
        runner.invoke(cli, ["user", "create", "dave"])
        runner.invoke(cli, ["user", "add-group", "dave", "Readers"])

        result = runner.invoke(cli, [
            "sim-access", "--user", "dave",
            "--action", "ec2:DescribeInstances",
            "--resource", "arn:aws:ec2:us-east-1:123456789012:instance/*",
        ])
        assert result.exit_code == 0
        assert "Access Granted" in result.output

    def test_json_output(self, runner, clean_data):
        policy_doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}],
        })
        runner.invoke(cli, ["policy", "create", "Admin", "--document", policy_doc])
        runner.invoke(cli, ["user", "create", "admin", "--policies", "Admin"])

        result = runner.invoke(cli, [
            "sim-access", "--user", "admin",
            "--action", "s3:GetObject",
            "--resource", "arn:aws:s3:::bucket/*",
            "--json-output",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "Access Granted"


class TestSeedCommand:
    def test_seed_creates_data(self, runner, clean_data):
        result = runner.invoke(cli, ["seed"])
        assert result.exit_code == 0
        assert "Seed data created" in result.output

        result = runner.invoke(cli, ["stats"])
        assert result.exit_code == 0
        assert "Users:      5" in result.output
        assert "Groups:     4" in result.output
        assert "Policies:   10" in result.output
        assert "Roles:      2" in result.output


class TestStatsCommand:
    def test_empty_stats(self, runner, clean_data):
        result = runner.invoke(cli, ["stats"])
        assert result.exit_code == 0
        assert "Users:      0" in result.output
