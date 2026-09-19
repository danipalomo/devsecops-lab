# DevSecOps Vulnerable Lab: End-to-End Attack Chain & Mitigation Analysis

> Laboratorio integral de simulación de ataques (Red Team / DevSecOps) que modela una intrusión realista de extremo a extremo: desde una aplicación web pública sin privilegios hasta el compromiso total de la cuenta cloud.

![Terraform](https://img.shields.io/badge/IaC-Terraform-844FBA?logo=terraform&logoColor=white)
![AWS/LocalStack](https://img.shields.io/badge/Cloud-AWS%20%2F%20LocalStack-FF9900?logo=amazonaws&logoColor=white)
![Ansible](https://img.shields.io/badge/Provisioning-Ansible-EE0000?logo=ansible&logoColor=white)
![Kubernetes](https://img.shields.io/badge/Orchestration-K3s-326CE5?logo=kubernetes&logoColor=white)
![Gitea](https://img.shields.io/badge/CI%2FCD-Gitea%20%2F%20Act--Runner-609926?logo=giteaVal&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/Mapped%20to-MITRE%20ATT%26CK-red)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen)

---

## Propósito: Riesgo Sistémico Cadenado (Cascading Risk)

Este laboratorio **no busca demostrar vectores de ataque aislados**. Cada capa del stack (IaC, Provisioning, Kubernetes, Aplicación/BBDD y CI/CD) fue desplegada de forma **deliberadamente permisiva y realista**, replicando errores de configuración habituales en entornos productivos reales — no vulnerabilidades artificiales tipo CTF.

El objetivo es demostrar cómo la **ausencia de barreras de seguridad (Guardrails / Defense-in-Depth)** convierte una vulnerabilidad "menor" de capa de aplicación en un compromiso total de la infraestructura cloud. Concretamente, este laboratorio traza el camino completo desde:

> **Una inyección SQL sin autenticación en un formulario web → hasta control administrativo (`cluster-admin` + rol IAM con `PassRole: *`) sobre todo el plano de control cloud y el clúster de Kubernetes.**

Este es el planteamiento realista de exposición: **únicamente la aplicación web (DVWA) está expuesta públicamente a internet.** El resto de la superficie (host, clúster K3s, runners de CI/CD, backend de Terraform) no se conoce de antemano — se descubre y compromete de forma progresiva, exactamente como ocurriría en una intrusión real contra una organización, y no como una lista de vulnerabilidades ya conocidas de antemano por el atacante.

Este proyecto demuestra tres competencias de forma simultánea y correlacionada:

- **Red Team / Explotación ofensiva**: cadena de explotación real, capa a capa, con movimiento lateral y escalada de privilegios.
- **DevSecOps**: identificación de las fallas de diseño (IaC, pipelines, provisioning) que *permiten* que la cadena de ataque sea posible.
- **Auditoría de Seguridad / Blue Team**: mapeo formal a MITRE ATT&CK y propuestas de mitigación en profundidad para cada eslabón de la cadena.

> **Disclaimer de alcance**: Este es un entorno de laboratorio aislado, desplegado localmente sobre LocalStack, sin datos reales ni exposición a producción. Todas las configuraciones inseguras son intencionadas y documentadas con fines exclusivamente educativos y demostrativos de portfolio.

---

## Matriz Ejecutiva de Compromiso (Cadena de Dominó)

Cadena de explotación real (de fuera hacia adentro), correlacionando el punto de entrada con el radio de impacto ganado en cada salto:

| Fase | Capa Afectada | Vector de Entrada / Falla Raíz | Nivel de Privilegio Ganado | Radio de Impacto (Blast Radius) | Táctica MITRE ATT&CK |
|:---:|---|---|---|---|---|
| 01 | **App Web** | SQL Injection (DVWA) | `www-data` (sin privilegios) | Entorno aislado del contenedor web | Initial Access (T1190) |
| 02 | **Base de Datos** | Pivotaje interno / reutilización de credenciales | Acceso DB + credenciales | Compromiso de los datos de la aplicación | Lateral Movement (T1210) |
| 03 | **Host OS** | Socket de Docker expuesto (`0777`) | `root` en el host | Control total del sistema operativo base | Privilege Escalation (T1068) |
| 04 | **CI/CD** | Exfiltración de secretos del runner (Gitea/Act-Runner) | Impersonación del pipeline | Secuestro de la cadena de suministro (PPE) | Unsecured Credentials (T1552) |
| 05 | **Kubernetes** | Lectura de `state.db` (Kine) / `hostPath` | `cluster-admin` (K8s) | Control total sobre todos los namespaces | Exploitation for Privilege Escalation (T1611) |
| 06 | **Cloud / IaC** | Mala configuración IAM (`PassRole: *`) | Administrador Cloud | Compromiso total de la cuenta AWS | Valid Accounts (T1078) |

*Cada fase se documenta en detalle en su propia sección: explicación en lenguaje natural, comandos exactos, evidencia/PoC, esquema visual del flujo de ataque y mitigaciones de defensa en profundidad.*

---

## Navegación Rápida

- [Arquitectura de Infraestructura](#) *(pendiente de anchor real)*
- [Cadena de Explotación Detallada](#)
- [Matriz de Mitigaciones y Defensa en Profundidad](#)
- [Vídeos Complementarios](#)

---
