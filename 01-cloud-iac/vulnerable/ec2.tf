# VULNERABILIDAD: Key pair sin restricciones y Security Group abierto
resource "aws_key_pair" "vulnerable_deployer" {
  key_name   = "devsecops-vulnerable-key"
  public_key = file("~/.ssh/devsecops_lab_key.pub")
}

resource "aws_instance" "vulnerable_app_server" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t3.medium"
  subnet_id                   = aws_subnet.public_subnet.id
  vpc_security_group_ids      = [aws_security_group.vulnerable_sg.id]
  associate_public_ip_address = true # VULNERABILIDAD: IP pública expuesta directamente

  tags = {
    Name        = "devsecops-vulnerable-target-host"
    Environment = "Vulnerable"
  }
}

output "vulnerable_instance_ip" {
  value       = aws_instance.vulnerable_app_server.public_ip
  description = "IP pública de la instancia vulnerable"
}
