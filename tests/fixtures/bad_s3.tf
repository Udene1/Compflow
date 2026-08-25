# ─── Non-Compliant S3 Bucket (Test Fixture) ───
# This file intentionally contains compliance violations for testing.

provider "aws" {
  region = "ap-northeast-1"
}

resource "aws_s3_bucket" "public_data" {
  bucket = "my-public-data-bucket"
  acl    = "public-read"

  tags = {
    Name = "public-data"
  }
}

resource "aws_s3_bucket_public_access_block" "public_data" {
  bucket = aws_s3_bucket.public_data.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_db_instance" "unencrypted_db" {
  identifier          = "legacy-database"
  engine              = "mysql"
  instance_class      = "db.t3.medium"
  allocated_storage   = 100
  storage_encrypted   = false
  publicly_accessible = true
  skip_final_snapshot = true
  backup_retention_period = 0

  tags = {
    Name = "legacy-db"
  }
}
