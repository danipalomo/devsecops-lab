# VULNERABILIDAD: Rol con Trust Policy permitiendo asumir el rol a cualquier origen (*)
resource "aws_iam_role" "overprivileged_role" {
  name = "devsecops-unrestricted-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = "*" # Permite que cualquiera asuma este rol
      }
    ]
  })
}

# VULNERABILIDAD: iam:PassRole sin restricciones en Resource (permite escalada de privilegios)
resource "aws_iam_policy" "passrole_unrestricted" {
  name        = "PassRoleUnrestrictedPolicy"
  description = "Permite pasar cualquier rol a cualquier servicio"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "*" # Permite entregar cualquier rol privilegiado a instancias o lambdas
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_passrole" {
  role       = aws_iam_role.overprivileged_role.name
  policy_arn = aws_iam_policy.passrole_unrestricted.arn
}

# VULNERABILIDAD: Usuario IAM con política de AdministratorAccess adjunta directamente
resource "aws_iam_user" "vulnerable_user" {
  name = "dev-user-admin"
}

resource "aws_iam_user_policy_attachment" "user_admin_attach" {
  user       = aws_iam_user.vulnerable_user.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
