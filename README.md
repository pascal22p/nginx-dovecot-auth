# nginx-dovecot-auth

A lightweight, high-performance authentication daemon written in Rust that enables [Nginx `ngx_http_auth_request_module`](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html) to authenticate users against a Dovecot / PostfixAdmin MySQL/MariaDB database.

---

## Features

- **Fast & Lightweight:** Built on [Axum](https://github.com/tokio-rs/axum) and [Tokio](https://tokio.rs/) with asynchronous database connection pooling via [SQLx](https://github.com/launchbadge/sqlx).
- **Dovecot Password Hash Compatibility:** Validates `{ARGON2I}` password hashes directly from the mail database.
- **Header Forwarding:** Returns `X-Remote-User: <username>` upon successful authentication for easy upstream forwarding in Nginx.
- **Configurable via Environment:** Clean 12-factor configuration using environment variables.
- **Structured Logging:** Configurable log filtering via `tracing-subscriber` and `RUST_LOG`.

---

## How It Works

```
[ Client ] 
    │ HTTP Request with Basic Auth
    ▼
[ Nginx ] ──(auth_request /auth)──► [ nginx-dovecot-auth ]
    │                                      │
    │                                 SQL query &
    │                               Password Verify
    │                                      ▼
    │                              [ MySQL / MariaDB ]
    │                              (mailbox database)
    │                                      │
    │ ◄── 200 OK (X-Remote-User) ─────────┘
    ▼
[ Upstream App / Protected Resource ]
```

1. Nginx intercepts incoming HTTP requests and delegates authentication to `nginx-dovecot-auth` via an internal `auth_request` subrequest.
2. `nginx-dovecot-auth` extracts HTTP Basic Auth credentials from the `Authorization` header.
3. It queries the MySQL/MariaDB `mailbox` table for active users (`active = '1'`).
4. It parses and verifies the stored Dovecot password hash.
5. On success, it responds with HTTP `200 OK` and includes the authenticated username in the `X-Remote-User` response header.
6. On invalid credentials or missing users, it responds with HTTP `401 Unauthorized`.

---

## Prerequisites

- **Rust** (1.75+ recommended) for building from source.
- **MySQL** or **MariaDB** database with a `mailbox` table (standard PostfixAdmin / Dovecot schema).

### Database Schema Expectation

The service expects a table matching the standard Dovecot/PostfixAdmin structure:

```sql
SELECT password FROM mailbox WHERE username = ? AND active = '1' LIMIT 1;
```

Expected table columns:
- `username` (e.g. `user@example.com` or `user`)
- `password` (e.g. `{ARGON2I}$argon2i$v=19$m=32768,t=4,p=1$...`)
- `active` (`'1'` for active users)

---

## Configuration

`nginx-dovecot-auth` is configured via environment variables:

| Variable | Required | Default | Description |
|---|---|---|---|
| `DB_HOST` | **Yes** | — | MySQL / MariaDB host address |
| `DB_PORT` | No | `3306` | MySQL / MariaDB port |
| `DB_USER` | **Yes** | — | Database username |
| `DB_PASSWORD` | **Yes** | — | Database password |
| `DB_NAME` | **Yes** | — | Database name (e.g., `mailserver`, `vmail`) |
| `LISTEN_ADDR` | No | `127.0.0.1:8080` | Socket address to listen on (`IP:PORT`) |
| `RUST_LOG` | No | `info` | Log level (`trace`, `debug`, `info`, `warn`, `error`) |

---

## Installation & Build

### 1. Build from Source

```bash
git clone https://github.com/yourusername/nginx-dovecot-auth.git
cd nginx-dovecot-auth
cargo build --release
```

The compiled binary will be located at `target/release/nginx-dovecot-auth`.

---

## Running the Service

### Direct Execution

```bash
export DB_HOST="127.0.0.1"
export DB_PORT="3306"
export DB_USER="mailuser"
export DB_PASSWORD="secretpassword"
export DB_NAME="mailserver"
export LISTEN_ADDR="127.0.0.1:8080"
export RUST_LOG="info"

./target/release/nginx-dovecot-auth
```

### Systemd Service Example

Create `/etc/systemd/system/nginx-dovecot-auth.service`:

```ini
[Unit]
Description=Nginx Dovecot Authentication Backend
After=network.target mysql.service

[Service]
Type=simple
User=www-data
Group=www-data
Environment="DB_HOST=127.0.0.1"
Environment="DB_PORT=3306"
Environment="DB_USER=mailuser"
Environment="DB_PASSWORD=secretpassword"
Environment="DB_NAME=mailserver"
Environment="LISTEN_ADDR=127.0.0.1:8080"
Environment="RUST_LOG=info"
ExecStart=/usr/local/bin/nginx-dovecot-auth
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo cp target/release/nginx-dovecot-auth /usr/local/bin/
sudo systemctl daemon-reload
sudo systemctl enable --now nginx-dovecot-auth
```

---

## Nginx Configuration

Integrate with Nginx using `auth_request` in your server or location block:

```nginx
server {
    listen 443 ssl http2;
    server_name protected.example.com;

    # SSL configuration...

    # Protected location
    location / {
        auth_request /auth-verify;

        # Capture username returned by auth service
        auth_request_set $auth_user $upstream_http_x_remote_user;

        # Forward authenticated user header to upstream backend
        proxy_set_header X-Remote-User $auth_user;
        proxy_pass http://127.0.0.1:3000;
    }

    # Internal auth endpoint proxying to nginx-dovecot-auth
    location = /auth-verify {
        internal;
        proxy_pass http://127.0.0.1:8080/auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        
        # Pass client Authorization header to the auth service
        proxy_set_header Authorization $http_authorization;
    }

    # Optional: custom 401 error handler to trigger browser Basic Auth prompt
    error_page 401 = @error401;
    location @error401 {
        add_header WWW-Authenticate 'Basic realm="Restricted Access"' always;
        return 401 "Unauthorized";
    }
}
```

---

## Supported Hash Schemes

| Scheme Prefix | Algorithm | Notes |
|---|---|---|
| `{ARGON2I}` | Argon2i (v19) | Default recommended scheme for modern Dovecot installations. |

*Note: Passwords without a supported scheme prefix or unsupported algorithms will be rejected and logged at `warn` level.*

---

## Development & Testing

Run unit and integration tests:

```bash
cargo test
```

Run with debug logging:

```bash
RUST_LOG=debug cargo run
```

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
