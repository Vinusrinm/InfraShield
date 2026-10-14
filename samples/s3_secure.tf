# Secure Hardened S3 Bucket Configuration
# Compliant with CKV_AWS_20 and CKV_AWS_19

resource "aws_s3_bucket" "data_archive" {
  bucket = "infrashield-sensitive-archive"
  acl    = "private"

  tags = {
    Environment = "production"
    DataClass   = "confidential"
  }
}

# Block all public access at bucket level
resource "aws_s3_bucket_public_access_block" "data_archive_block" {
  bucket = aws_s3_bucket.data_archive.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enforce Server-Side Encryption with KMS or AES256
resource "aws_s3_bucket_server_side_encryption_configuration" "data_archive_crypto" {
  bucket = aws_s3_bucket.data_archive.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
