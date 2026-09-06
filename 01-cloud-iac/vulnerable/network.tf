resource "aws_vpc" "vulnerable_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "vulnerable-vpc"
  }
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.vulnerable_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
}

# VULNERABILIDAD: Security Group con exposición total de puertos críticos y egress ilimitado
resource "aws_security_group" "vulnerable_sg" {
  name        = "open-management-sg"
  description = "Security Group permisivo"
  vpc_id      = aws_vpc.vulnerable_vpc.id

  # Ingress: SSH abierto al mundo
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Ingress: Puerto Unencrypted Docker API expuesto abiertamente
  ingress {
    from_port   = 2375
    to_port     = 2375
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Egress: Tráfico de salida totalmente sin restricción (facilita exfiltración)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
