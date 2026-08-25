# ─── Non-Compliant IAM Policy (Test Fixture) ───
# This file intentionally contains IAM wildcard violations.

resource "aws_iam_policy" "admin_everything" {
  name        = "god-mode-policy"
  description = "This policy grants full access to everything"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "open_s3" {
  name = "open-s3-access"
  role = aws_iam_role.some_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect": "Allow",
        "Action": ["*"],
        "Resource": "arn:aws:s3:::*"
        "Principal": "*"
      }
    ]
  })
}
