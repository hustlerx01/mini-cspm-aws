"""Build a deliberately-bad + partly-good account inside moto and scan it (no AWS account needed)."""
import json, os, sys
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing"); os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ["AWS_DEFAULT_REGION"] = "ap-south-1"
from moto import mock_aws
import boto3

def build_sandbox(region="ap-south-1"):
    s = boto3.session.Session(region_name=region)
    iam, s3, ec2, ct, kms, rds = (s.client(x) for x in ("iam", "s3", "ec2", "cloudtrail", "kms", "rds"))
    loc = {"LocationConstraint": region}
    # bad
    iam.create_user(UserName="alice"); iam.create_login_profile(UserName="alice", Password="Passw0rd!x")
    iam.attach_user_policy(UserName="alice", PolicyArn=iam.create_policy(PolicyName="god", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))["Policy"]["Arn"])
    iam.create_access_key(UserName="alice")
    s3.create_bucket(Bucket="ansar-lab-public", CreateBucketConfiguration=loc)
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    sg = ec2.create_security_group(GroupName="ssh-world", Description="bad", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    kms.create_key(Description="no-rotation")
    rds.create_db_instance(DBInstanceIdentifier="legacy-db", DBInstanceClass="db.t3.micro", Engine="mysql",
                           MasterUsername="admin", MasterUserPassword="x" * 12, AllocatedStorage=20, PubliclyAccessible=True)
    # good
    iam.update_account_password_policy(MinimumPasswordLength=14, PasswordReusePrevention=24)
    s3.create_bucket(Bucket="ansar-lab-logs", CreateBucketConfiguration=loc)
    s3.put_public_access_block(Bucket="ansar-lab-logs", PublicAccessBlockConfiguration={k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")})
    s3.put_bucket_versioning(Bucket="ansar-lab-logs", VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_policy(Bucket="ansar-lab-logs", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Sid": "TLS", "Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": ["arn:aws:s3:::ansar-lab-logs", "arn:aws:s3:::ansar-lab-logs/*"],
         "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}))
    ct.create_trail(Name="org-trail", S3BucketName="ansar-lab-logs", IsMultiRegionTrail=True, EnableLogFileValidation=True)
    ct.start_logging(Name="org-trail")
    k2 = kms.create_key(Description="rotated")["KeyMetadata"]["KeyId"]; kms.enable_key_rotation(KeyId=k2)
    ec2.enable_ebs_encryption_by_default()
    return s

if __name__ == "__main__":
    from .cli import main
    with mock_aws():
        build_sandbox()
        sys.exit(main(sys.argv[1:]))
