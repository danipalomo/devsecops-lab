# 1. Rol con Trust Policy restringida únicamente a EC2
resource "aws_iam_role" "hardened_role" {
  name = "devsecops-restricted-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# 2. Política de PassRole acotada a un recurso específico
resource "aws_iam_policy" "passrole_restricted" {
  name        = "PassRoleRestrictedPolicy"
  description = "Permite pasar únicamente un rol específico acotado"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "arn:aws:iam::000000000000:role/devsecops-restricted-role"
      }
    ]
  })
}

# 3. Attachment explícito (Vincula la política segura al rol acotado)
resource "aws_iam_role_policy_attachment" "passrole_attach" {
  role       = aws_iam_role.hardened_role.name
  policy_arn = aws_iam_policy.passrole_restricted.arn
}
