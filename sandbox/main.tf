# Deliberately insecure sandbox. NOT applied by me. Apply only in a throwaway account, then `terraform destroy`.
terraform {
  required_providers { aws = { source = "hashicorp/aws", version = "~> 5.0" } }
}
provider "aws" { region = "ap-south-1" }

resource "aws_s3_bucket" "public" { bucket_prefix = "minicspm-bad-" }  # no BPA, no TLS policy, no versioning

resource "aws_security_group" "ssh_world" {
  name = "minicspm-ssh-world"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_kms_key" "norotate" { description = "minicspm no rotation" }

resource "aws_iam_user" "alice" { name = "minicspm-alice" }
resource "aws_iam_user_policy_attachment" "admin" {
  user       = aws_iam_user.alice.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
