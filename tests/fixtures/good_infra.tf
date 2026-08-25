# ─── Fully Compliant Infrastructure (Test Fixture) ───
# This file should produce ZERO critical or high findings.

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "secure_data" {
  bucket = "my-secure-data-bucket"

  tags = {
    Environment        = "production"
    Owner              = "platform-team"
    DataClassification = "confidential"
  }
}

resource "aws_s3_bucket_public_access_block" "secure_data" {
  bucket = aws_s3_bucket.secure_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_data" {
  bucket = aws_s3_bucket.secure_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data_key.arn
    }
  }
}

resource "aws_db_instance" "encrypted_db" {
  identifier           = "production-database"
  engine               = "postgres"
  engine_version       = "15.4"
  instance_class       = "db.r6g.large"
  allocated_storage    = 200
  storage_encrypted    = true
  kms_key_id           = aws_kms_key.data_key.arn
  publicly_accessible  = false
  deletion_protection  = true
  backup_retention_period = 14
  skip_final_snapshot  = false

  tags = {
    Environment        = "production"
    Owner              = "platform-team"
    DataClassification = "confidential"
  }
}

resource "aws_security_group" "restricted" {
  name        = "app-sg"
  description = "Application security group with restricted access"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from VPN"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  tags = {
    Environment        = "production"
    Owner              = "platform-team"
    DataClassification = "internal"
  }
}

resource "aws_cloudtrail" "main" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.trail_logs.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  enable_logging                = true

  tags = {
    Environment        = "production"
    Owner              = "security-team"
    DataClassification = "internal"
  }
}

resource "aws_kms_key" "data_key" {
  description         = "Data encryption key"
  enable_key_rotation = true
  deletion_window_in_days = 30

  tags = {
    Environment        = "production"
    Owner              = "security-team"
    DataClassification = "confidential"
  }
}
