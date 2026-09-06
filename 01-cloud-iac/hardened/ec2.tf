# HARDENING: Clave SSH leída desde archivo e instancia en subred privada
resource "aws_key_pair" "deployer" {
  key_name   = "devsecops-deployer-key"
  public_key = file("~/.ssh/devsecops_lab_key.pub")
}

resource "aws_instance" "app_server" {
  ami                    = "ami-0c55b159cbfafe1f0"
  instance_type          = "t3.medium"
  subnet_id              = aws_subnet.private_subnet.id
  vpc_security_group_ids = [aws_security_group.restricted_sg.id]

  tags = {
    Name        = "devsecops-target-host"
    Environment = "Hardened"
    ManagedBy   = "Ansible"
  }
}

# AUTOMATIZACIÓN: Generación automática del inventario de Ansible con los datos de Terraform
resource "local_file" "ansible_inventory" {
  content = <<EOT
[target_hosts]
localhost ansible_connection=local

[ec2_instances]
${aws_instance.app_server.private_ip} ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/devsecops_lab_key
EOT

  filename = "${path.module}/../../02-provisioning/inventory.ini"
}

output "instance_ip" {
  value       = aws_instance.app_server.private_ip
  description = "IP privada de la instancia EC2 desplegada"
}
