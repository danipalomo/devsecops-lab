resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket        = "devsecops-public-data-bucket"
  force_destroy = true
}

# VULNERABILIDAD: Deshabilitar el bloqueo de acceso público
resource "aws_s3_bucket_public_access_block" "public_access" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# VULNERABILIDAD: Bucket policy que permite lecturas y subidas públicas (PutObject/GetObject)
resource "aws_s3_bucket_policy" "allow_public_access" {
  bucket     = aws_s3_bucket.vulnerable_bucket.id
  depends_on = [aws_s3_bucket_public_access_block.public_access]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadWriteAccess"
        Effect    = "Allow"
        Principal = "*" # Accesible desde cualquier cuenta
        Action    = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.vulnerable_bucket.arn,
          "${aws_s3_bucket.vulnerable_bucket.arn}/*"
        ]
      }
    ]
  })
}
