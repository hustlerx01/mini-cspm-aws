import json, os
os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_DEFAULT_REGION="ap-south-1")
import boto3, pytest
from moto import mock_aws
from minicspm import checks
from minicspm.checks import run_all, CHECKS
from minicspm.demo import build_sandbox
from minicspm.report import to_asff, summary
from minicspm.cli import main

@pytest.fixture
def sess():
    with mock_aws():
        yield boto3.session.Session(region_name="ap-south-1")

def by(findings, cid): return [f for f in findings if f.check_id == cid]

def test_registry_has_20_checks():
    assert len(CHECKS) == 20
    assert len({c.meta["check_id"] for c in CHECKS}) == 20

def test_empty_account_flags_missing_baselines(sess):
    f = run_all(sess)
    assert not [x for x in f if x.status == "ERROR"], [x.detail for x in f if x.status == "ERROR"]
    assert by(f, "IAM-03")[0].status == "FAIL"      # no password policy
    assert by(f, "LOG-01")[0].status == "FAIL"      # no trail
    assert by(f, "EC2-01")[0].status == "FAIL"

def test_sandbox_bad_and_good(sess):
    build_sandbox()
    f = run_all(sess)
    st = lambda cid, res: next(x.status for x in by(f, cid) if res in x.resource)
    assert st("S3-01", "ansar-lab-public") == "FAIL" and st("S3-01", "ansar-lab-logs") == "PASS"
    assert st("S3-02", "ansar-lab-public") == "FAIL" and st("S3-02", "ansar-lab-logs") == "PASS"
    assert st("S3-03", "ansar-lab-logs") == "PASS"
    assert st("IAM-05", "alice") == "FAIL"
    assert st("IAM-07", "alice") == "FAIL"
    assert any(x.status == "FAIL" for x in by(f, "IAM-08"))
    assert by(f, "IAM-03")[0].status == "PASS" and by(f, "IAM-04")[0].status == "PASS"
    assert by(f, "LOG-01")[0].status == "PASS" and by(f, "LOG-02")[0].status == "PASS"
    assert by(f, "EC2-01")[0].status == "PASS"
    assert st("RDS-01", "legacy-db") == "FAIL"
    ssh = [x for x in by(f, "NET-01") if x.status == "FAIL"]
    assert len(ssh) == 1 and "22" in ssh[0].detail
    assert sorted(x.status for x in by(f, "LOG-04")) == ["FAIL", "PASS"]

def test_sg_rule_on_other_port_passes(sess):
    ec2 = sess.client("ec2"); vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    g = ec2.create_security_group(GroupName="web", Description="d", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=g, IpPermissions=[{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    assert next(x for x in run_all(sess) if x.resource == g and x.check_id == "NET-01").status == "PASS"

def test_sg_all_traffic_ipv6_fails(sess):
    ec2 = sess.client("ec2"); vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    g = ec2.create_security_group(GroupName="all6", Description="d", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=g, IpPermissions=[{"IpProtocol": "-1", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])
    assert next(x for x in run_all(sess) if x.resource == g and x.check_id == "NET-01").status == "FAIL"

def test_check_error_is_contained(sess, monkeypatch):
    def boom(s): raise RuntimeError("AccessDenied simulation")
    boom.meta = CHECKS[0].meta
    monkeypatch.setattr(checks, "CHECKS", [boom])
    f = checks.run_all(sess)
    assert f[0].status == "ERROR" and "AccessDenied" in f[0].detail

def test_asff_only_fails_and_valid_fields(sess):
    build_sandbox()
    f = run_all(sess)
    a = to_asff(f, "123456789012", "ap-south-1")
    assert len(a) == summary(f)["fail"]
    for x in a:
        assert x["Compliance"]["Status"] == "FAILED" and x["SchemaVersion"] == "2018-10-08"
        assert x["Severity"]["Label"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

def test_cli_writes_outputs_and_fail_on(sess, tmp_path):
    build_sandbox()
    assert main(["--out", str(tmp_path), "--fail-on", "HIGH"]) == 2
    assert (tmp_path / "report.html").read_text().count("<tr class='FAIL'>") > 5
    assert json.loads((tmp_path / "findings.json").read_text())
