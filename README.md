# swag-ui Light Web UI for linuxserver/swag
swag-ui is stateless. SWAG /config is the source of truth.\
8.7 MB = All docker image (UI and Guard)\
![Альтернативный текст](screen/swag-ui-dashbord2.PNG)

## ✨ Features

| Category             | Feature                   | Status | Description                                                                    |
| -------------------- | ------------------------- | :----: | ------------------------------------------------------------------------------ |
| 🏠 **Dashboard**     | System overview           |    ✅   | Overview of SWAG, Docker containers, proxies, certificates and detected issues |
|                      | Docker discovery          |    ✅   | Automatically discovers running Docker containers                              |
|                      | Container → Proxy mapping |    ✅   | Shows which Docker container is used by each reverse proxy                     |
|                      | Network validation        |    ✅   | Checks that SWAG and the target container share a Docker network               |
|                      | Health & diagnostics      |    ✅   | Detects common configuration and deployment problems                           |
| 🌐 **Reverse Proxy** | Proxy-confs management    |    ✅   | Enable, disable and manage SWAG proxy configurations                           |
|                      | Site-confs                |    ✅   | View and edit Nginx site configurations                                        |
|                      | Raw configuration editor  |    ✅   | Direct access to SWAG configuration files                                      |
|                      | Docker upstreams          |    ✅   | Configure reverse proxies directly against Docker containers                   |
|                      | Configuration validation  |    ✅   | Runs `nginx -t` before applying changes                                        |
|                      | Safe reload               |    ✅   | Reloads Nginx only after successful configuration validation                   |
|                      | Rollback protection       |    ✅   | Prevents broken configuration from replacing the working state                 |
| 🔄 **Auto Reload**   | Automatic reload          |    ✅   | Automatically detects configuration changes                                    |
|                      | Manual reload             |    ✅   | Keep full control and reload Nginx manually                                    |
|                      | File watcher              |    ✅   | Monitors SWAG configuration for external changes                               |
|                      | Change validation         |    ✅   | Modified configuration is tested before reload                                 |
| 🔐 **Certificates**  | Certificate discovery     |    ✅   | Automatically discovers certificates managed by SWAG                           |
|                      | Certificate status        |    ✅   | Displays expiration and current certificate state                              |
|                      | Nginx certificate mapping |    ✅   | Detects which certificate is actually served by Nginx                          |
|                      | Certificate issuance      |    ✅   | Issue certificates through the SWAG/Certbot stack                              |
|                      | Let's Encrypt             |    ✅   | Support for Let's Encrypt certificates                                         |
|                      | ZeroSSL                   |    ✅   | Support for ZeroSSL certificates                                               |
|                      | HTTP-01                   |    ✅   | HTTP-based ACME validation                                                     |
|                      | DNS-01                    |    ✅   | DNS-based ACME validation                                                      |
|                      | Wildcard certificates     |    ✅   | Issue wildcard certificates using DNS-01                                       |
|                      | DuckDNS                   |    ✅   | Built-in onboarding for free DuckDNS domains and wildcard certificates         |
|                      | Cloudflare                |    ✅   | Dedicated Cloudflare DNS-01 configuration                                      |
|                      | Generic DNS providers     |    ✅   | Configure other SWAG-supported DNS plugins                                     |
|                      | Staging certificates      |    ✅   | Test certificate issuance without hitting production ACME limits               |
| 🛡️ **Security**     | Fail2ban                  |    ✅   | View and manage SWAG Fail2ban status and jails                                 |
|                      | Ban / unban IP            |    ✅   | Manage blocked addresses from the web UI                                       |
|                      | Basic authentication      |    ✅   | Create and manage `.htpasswd` credentials                                      |
|                      | Restricted Docker API     |    ✅   | Docker operations are isolated behind `swag-guard`                             |
|                      | Command allowlist         |    ✅   | Only explicitly permitted SWAG commands can be executed                        |
| 📜 **Logs**          | Access logs               |    ✅   | View Nginx access logs from the web UI                                         |
|                      | Error logs                |    ✅   | View Nginx error logs                                                          |
|                      | Fail2ban logs             |    ✅   | Inspect Fail2ban activity                                                      |
|                      | Line limit                |    ✅   | Prevents excessive log reads from consuming resources                          |
|                      | Log filtering             |    ✅   | Filter and inspect recent log entries                                          |
| 🚀 **HTTP/3**        | HTTP/3 / QUIC             |    ✅   | Enable HTTP/3 support for SWAG                                                 |
|                      | Safe configuration        |    ✅   | UI-managed HTTP/3 changes are isolated from manual configuration               |
|                      | Reversible changes        |    ✅   | Disable HTTP/3 without overwriting unrelated Nginx configuration               |
| 🐳 **Docker**        | Container discovery       |    ✅   | Automatically discover Docker workloads                                        |
|                      | Container ports           |    ✅   | Detect available container ports for proxy configuration                       |
|                      | Docker networks           |    ✅   | Inspect networks shared with SWAG                                              |
|                      | Docker integration        |    ✅   | Manage SWAG reverse proxies around Docker services                             |
| ⚙️ **Configuration** | No database               |    ✅   | SWAG `/config` remains the source of truth                                     |
|                      | Stateless                 |    ✅   | No application state database required                                         |
|                      | Direct SWAG integration   |    ✅   | Works directly with the existing SWAG configuration                            |
|                      | Survives reinstallation   |    ✅   | Reinstalling the UI does not require rebuilding its state                      |
| 📦 **Deployment**    | Docker                    |    ✅   | Designed to run as a lightweight Docker container                              |
|                      | Lightweight image         |   🚀   | ~16 MB Docker image                                                            |
|                      | No Node.js runtime        |   🚀   | Lightweight Go-based backend and embedded UI                                   |
|                      | No external database      |   🚀   | No PostgreSQL, MySQL or Redis required                                         |

### 🎯 Design Goals

* **SWAG remains the engine** — `swag-ui` manages and observes it, rather than replacing it.
* **`/config` is the source of truth** — no duplicate application database.
* **Docker-first** — designed for containerized SWAG deployments.
* **Safe changes** — configuration is validated with `nginx -t` before reload.
* **Security by default** — Docker access is isolated through a restricted API boundary.
* **Small footprint** — approximately **16 MB** Docker image.
* **Simple recovery** — remove and reinstall `swag-ui`, and it can rediscover the existing SWAG state.
* **Advanced users are not locked in** — raw configuration and generic DNS-provider support remain available.


Go + embedded frontend\
No database\
No Node.js runtime\
No nginx replacement\
No heavyweight dependencies\
