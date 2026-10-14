# Insecure Cloud Storage Configuration
# Violates:
# - CKV_AWS_20: S3 bucket has public ACL (public-read)
# - CKV_AWS_19: S3 bucket does not have server-side encryption enabled

resource "aws_s3_bucket" "data_archive" {
  bucket = "infrashield-sensitive-archive"
  acl    = "public-read" # Policy Violation 2: Publicly accessible cloud storage

  tags = {
    Environment = "production"
    DataClass   = "confidential"
  }
}
