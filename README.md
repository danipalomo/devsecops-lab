# DevSecOps & Cloud Security Lab: Vulnerable vs Hardened Architecture

Este repositorio contiene la implementación práctica de un laboratorio end-to-end donde se simulan, explotan y mitigan malas configuraciones de seguridad en un entorno Cloud Nativo (IaC, OS, Kubernetes, Containers y CI/CD).

## Arquitectura por Capas
1. **Capa 1: Cloud & IaC** (Terraform + LocalStack)
2. **Capa 2: Provisioning & OS** (Ansible + Linux Hardening)
3. **Capa 3: Kubernetes Orchestration** (k3d + RBAC/Pod Security)
4. **Capa 4: Container Security** (Dockerfiles + Trivy)
5. **Capa 5: CI/CD Supply Chain** (Pipeline Security)

## Mapeo MITRE ATT&CK & OWASP
Cada vulnerabilidad cuenta con una demostración paso a paso de explotación y su remediación correspondiente.
