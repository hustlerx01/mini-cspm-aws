"""Each check returns a list of Finding. All calls are read-only (List*/Get*/Describe*)."""
from __future__ import annotations
import datetime as dt
from dataclasses import dataclass, asdict
import botocore

@dataclass
class Finding:
    check_id: str
    cis: str
    title: str
    severity: str
    resource: str
    status: str  # PASS / FAIL / ERROR
    detail: str = ""
    remediation: str = ""
    def to_dict(self): return asdict(self)

CHECKS = []
def check(check_id, cis, title, severity, remediation):
    def deco(fn):
        fn.meta = dict(check_id=check_id, cis=cis, title=title, severity=severity, remediation=remediation)
        CHECKS.append(fn); return fn
    return deco

def _f(fn, resource, ok, detail=""):
    m = fn.meta
    return Finding(m["check_id"], m["cis"], m["title"], m["severity"], resource,
                   "PASS" if ok else "FAIL", detail, "" if ok else m["remediation"])

def _now(): return dt.datetime.now(dt.timezone.utc)

# ---------------- IAM ----------------
@check("IAM-01", "1.4", "No access keys for root user", "CRITICAL", "Delete root access keys.")
def root_access_keys(s):
    summ = s.client("iam").get_account_summary()["SummaryMap"]
    return [_f(root_access_keys, "root", summ.get("AccountAccessKeysPresent", 0) == 0)]

@check("IAM-02", "1.5", "MFA enabled for root user", "CRITICAL", "Enable hardware/virtual MFA on root.")
def root_mfa(s):
    summ = s.client("iam").get_account_summary()["SummaryMap"]
    return [_f(root_mfa, "root", summ.get("AccountMFAEnabled", 0) == 1)]

@check("IAM-03", "1.8", "Password policy min length >= 14", "MEDIUM", "aws iam update-account-password-policy --minimum-password-length 14")
def pw_length(s):
    try:
        p = s.client("iam").get_account_password_policy()["PasswordPolicy"]
        return [_f(pw_length, "password-policy", p.get("MinimumPasswordLength", 0) >= 14, f"min={p.get('MinimumPasswordLength')}")]
    except botocore.exceptions.ClientError:
        return [_f(pw_length, "password-policy", False, "no password policy set")]

@check("IAM-04", "1.9", "Password policy prevents reuse (24)", "LOW", "Set PasswordReusePrevention=24.")
def pw_reuse(s):
    try:
        p = s.client("iam").get_account_password_policy()["PasswordPolicy"]
        return [_f(pw_reuse, "password-policy", p.get("PasswordReusePrevention", 0) >= 24)]
    except botocore.exceptions.ClientError:
        return [_f(pw_reuse, "password-policy", False, "no password policy set")]

@check("IAM-05", "1.10", "MFA for IAM users with console password", "HIGH", "Enable MFA for each console user.")
def user_mfa(s):
    iam, out = s.client("iam"), []
    for u in iam.list_users()["Users"]:
        name = u["UserName"]
        try:
            iam.get_login_profile(UserName=name)
        except botocore.exceptions.ClientError:
            continue  # no console access
        mfa = iam.list_mfa_devices(UserName=name)["MFADevices"]
        out.append(_f(user_mfa, f"iam-user/{name}", bool(mfa)))
    return out

@check("IAM-06", "1.14", "Access keys rotated within 90 days", "MEDIUM", "Rotate keys older than 90 days.")
def key_rotation(s):
    iam, out = s.client("iam"), []
    for u in iam.list_users()["Users"]:
        for k in iam.list_access_keys(UserName=u["UserName"])["AccessKeyMetadata"]:
            if k["Status"] != "Active": continue
            age = (_now() - k["CreateDate"]).days
            out.append(_f(key_rotation, f"iam-user/{u['UserName']}/{k['AccessKeyId']}", age <= 90, f"age={age}d"))
    return out

@check("IAM-07", "1.15", "IAM users get permissions only via groups (no attached/inline policies)", "LOW", "Move user policies onto groups.")
def user_policies(s):
    iam, out = s.client("iam"), []
    for u in iam.list_users()["Users"]:
        n = u["UserName"]
        att = iam.list_attached_user_policies(UserName=n)["AttachedPolicies"]
        inl = iam.list_user_policies(UserName=n)["PolicyNames"]
        out.append(_f(user_policies, f"iam-user/{n}", not att and not inl, f"attached={len(att)} inline={len(inl)}"))
    return out

@check("IAM-08", "1.16", "No customer policy grants full '*:*' admin", "HIGH", "Replace Action:* Resource:* with least-privilege statements.")
def full_admin(s):
    iam, out = s.client("iam"), []
    for p in iam.list_policies(Scope="Local")["Policies"]:
        doc = iam.get_policy_version(PolicyArn=p["Arn"], VersionId=p["DefaultVersionId"])["PolicyVersion"]["Document"]
        stmts = doc["Statement"] if isinstance(doc["Statement"], list) else [doc["Statement"]]
        bad = any(st.get("Effect") == "Allow" and st.get("Action") in ("*", ["*"]) and st.get("Resource") in ("*", ["*"]) for st in stmts)
        out.append(_f(full_admin, p["Arn"], not bad))
    return out

# ---------------- S3 ----------------
def _buckets(s): return [b["Name"] for b in s.client("s3").list_buckets().get("Buckets", [])]

@check("S3-01", "2.1.4", "S3 bucket Block Public Access fully enabled", "HIGH", "aws s3api put-public-access-block --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true")
def s3_bpa(s):
    s3, out = s.client("s3"), []
    for b in _buckets(s):
        try:
            c = s3.get_public_access_block(Bucket=b)["PublicAccessBlockConfiguration"]
            ok = all(c.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
        except botocore.exceptions.ClientError:
            ok = False
        out.append(_f(s3_bpa, f"s3://{b}", ok))
    return out

@check("S3-02", "2.1.1", "S3 bucket policy denies non-TLS (aws:SecureTransport=false)", "MEDIUM", "Add a Deny statement with Condition Bool aws:SecureTransport=false.")
def s3_tls(s):
    import json
    s3, out = s.client("s3"), []
    for b in _buckets(s):
        try:
            pol = json.loads(s3.get_bucket_policy(Bucket=b)["Policy"])
            ok = any(st.get("Effect") == "Deny" and "aws:SecureTransport" in json.dumps(st.get("Condition", {})) for st in pol["Statement"])
        except botocore.exceptions.ClientError:
            ok = False
        out.append(_f(s3_tls, f"s3://{b}", ok))
    return out

@check("S3-03", "2.1.2", "S3 bucket versioning + MFA delete (versioning checked)", "LOW", "Enable bucket versioning.")
def s3_versioning(s):
    s3 = s.client("s3")
    return [_f(s3_versioning, f"s3://{b}", s3.get_bucket_versioning(Bucket=b).get("Status") == "Enabled") for b in _buckets(s)]

# ---------------- Logging ----------------
@check("LOG-01", "3.1", "Multi-region CloudTrail trail is logging", "HIGH", "Create a multi-region trail and start logging.")
def ct_multi(s):
    ct = s.client("cloudtrail")
    trails = ct.describe_trails()["trailList"]
    ok = any(t.get("IsMultiRegionTrail") and ct.get_trail_status(Name=t["TrailARN"]).get("IsLogging") for t in trails)
    return [_f(ct_multi, "cloudtrail", ok, f"trails={len(trails)}")]

@check("LOG-02", "3.2", "CloudTrail log file validation enabled", "MEDIUM", "aws cloudtrail update-trail --enable-log-file-validation")
def ct_validation(s):
    return [_f(ct_validation, t["TrailARN"], bool(t.get("LogFileValidationEnabled"))) for t in s.client("cloudtrail").describe_trails()["trailList"]]

@check("LOG-03", "3.7", "VPC flow logs enabled on every VPC", "MEDIUM", "aws ec2 create-flow-logs --resource-type VPC ...")
def flow_logs(s):
    ec2 = s.client("ec2")
    have = {f["ResourceId"] for f in ec2.describe_flow_logs()["FlowLogs"]}
    return [_f(flow_logs, v["VpcId"], v["VpcId"] in have) for v in ec2.describe_vpcs()["Vpcs"]]

@check("LOG-04", "3.6", "Customer-managed KMS keys have rotation enabled", "MEDIUM", "aws kms enable-key-rotation --key-id ...")
def kms_rotation(s):
    kms, out = s.client("kms"), []
    for k in kms.list_keys()["Keys"]:
        md = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
        if md.get("KeyManager") != "CUSTOMER" or md.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT" or md.get("KeyState") != "Enabled":
            continue
        out.append(_f(kms_rotation, md["Arn"], kms.get_key_rotation_status(KeyId=k["KeyId"])["KeyRotationEnabled"]))
    return out

# ---------------- Network / compute ----------------
ADMIN_PORTS = (22, 3389)
@check("NET-01", "5.2", "No security group allows 0.0.0.0/0 or ::/0 to admin ports 22/3389", "HIGH", "Restrict ingress to a bastion/VPN CIDR or use SSM Session Manager.")
def sg_admin(s):
    out = []
    for g in s.client("ec2").describe_security_groups()["SecurityGroups"]:
        bad = []
        for p in g.get("IpPermissions", []):
            proto = p.get("IpProtocol")
            lo, hi = p.get("FromPort", 0), p.get("ToPort", 65535)
            world = any(r.get("CidrIp") == "0.0.0.0/0" for r in p.get("IpRanges", [])) or any(r.get("CidrIpv6") == "::/0" for r in p.get("Ipv6Ranges", []))
            if world and (proto == "-1" or any(lo <= port <= hi for port in ADMIN_PORTS)):
                bad.append(f"{proto}:{lo}-{hi}")
        out.append(_f(sg_admin, g["GroupId"], not bad, ",".join(bad)))
    return out

@check("NET-02", "5.4", "Default security group restricts all traffic", "LOW", "Remove all rules from each VPC's default SG.")
def default_sg(s):
    out = []
    for g in s.client("ec2").describe_security_groups(Filters=[{"Name": "group-name", "Values": ["default"]}])["SecurityGroups"]:
        out.append(_f(default_sg, g["GroupId"], not g.get("IpPermissions") and not g.get("IpPermissionsEgress")))
    return out

@check("EC2-01", "2.2.1", "EBS default encryption enabled in region", "MEDIUM", "aws ec2 enable-ebs-encryption-by-default")
def ebs_default(s):
    return [_f(ebs_default, f"ebs-default/{s.region_name}", s.client("ec2").get_ebs_encryption_by_default()["EbsEncryptionByDefault"])]

@check("RDS-01", "2.3.3", "RDS instances not publicly accessible", "HIGH", "Set PubliclyAccessible=false and place in private subnets.")
def rds_public(s):
    return [_f(rds_public, d["DBInstanceIdentifier"], not d.get("PubliclyAccessible")) for d in s.client("rds").describe_db_instances()["DBInstances"]]

@check("RDS-02", "2.3.1", "RDS storage encrypted", "HIGH", "Recreate from an encrypted snapshot copy.")
def rds_enc(s):
    return [_f(rds_enc, d["DBInstanceIdentifier"], bool(d.get("StorageEncrypted"))) for d in s.client("rds").describe_db_instances()["DBInstances"]]

def run_all(session):
    findings = []
    for fn in CHECKS:
        try:
            findings.extend(fn(session))
        except Exception as e:  # never let one check kill the scan
            m = fn.meta
            findings.append(Finding(m["check_id"], m["cis"], m["title"], m["severity"], "-", "ERROR", f"{type(e).__name__}: {e}"))
    return findings
