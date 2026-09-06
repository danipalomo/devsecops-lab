resource "aws_vpc" "hardened_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "hardened-vpc"
  }
}

resource "aws_subnet" "private_subnet" {
  vpc_id                  = aws_vpc.hardened_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = false # HARDENING: Subred privada por defecto
}

# HARDENING: Security group restringido con Least Privilege
resource "aws_security_group" "restricted_sg" {
  name        = "restricted-app-sg"
  description = "Security Group acotado"
  vpc_id      = aws_vpc.hardened_vpc.id

  # Ingress: Solo puerto HTTPS (443) desde la red interna/VPN corporativa
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # Egress acotado según necesidades
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
