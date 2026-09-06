resource "aws_s3_bucket" "hardened_bucket" {
  bucket        = "devsecops-secure-data-bucket"
  force_destroy = true
}

# HARDENING: Bloqueo estricto de cualquier acceso público a nivel de bucket y ACLs
resource "aws_s3_bucket_public_access_block" "secure_public_access" {
  bucket = aws_s3_bucket.hardened_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# HARDENING: Habilitar cifrado en reposo por defecto (SSE-S3)
resource "aws_s3_bucket_server_side_encryption_configuration" "s3_encryption" {
  bucket = aws_s3_bucket.hardened_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
