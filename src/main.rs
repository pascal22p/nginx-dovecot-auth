use axum::{
    body::Body,
    extract::State,
    http::{header::AUTHORIZATION, HeaderMap, HeaderValue, Response, StatusCode},
    routing::any,
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use nginx_dovecot_auth::auth::verify_password;
use sqlx::{
    mysql::{MySqlConnectOptions, MySqlPoolOptions},
    MySqlPool,
};
use std::{env, net::SocketAddr, time::Instant};
use tracing::{debug, error, info, warn};

#[derive(Clone)]
struct AppState {
    db: MySqlPool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .compact()
        .init();

    info!("Starting nginx-dovecot-auth");

    let db_host = required_env("DB_HOST")?;
    let db_port: u16 = env::var("DB_PORT")
        .unwrap_or_else(|_| "3306".to_string())
        .parse()
        .map_err(|e| {
            error!(error = %e, "Invalid DB_PORT; expected a port number");
            e
        })?;
    let db_user = required_env("DB_USER")?;
    let db_password = required_env("DB_PASSWORD")?;
    let db_name = required_env("DB_NAME")?;

    let listen_addr: SocketAddr = env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()
        .map_err(|e| {
            error!(error = %e, "Invalid LISTEN_ADDR");
            e
        })?;

    info!(
        db_host = %db_host,
        db_port,
        db_name = %db_name,
        "Connecting to MySQL"
    );

    let options = MySqlConnectOptions::new()
        .host(&db_host)
        .port(db_port)
        .username(&db_user)
        .password(&db_password)
        .database(&db_name);

    let db = match MySqlPoolOptions::new()
        .max_connections(10)
        .connect_with(options)
        .await
    {
        Ok(pool) => {
            info!("Connected to MySQL successfully");
            pool
        }
        Err(e) => {
            error!(error = %e, "Failed to connect to MySQL");
            return Err(e.into());
        }
    };

    let state = AppState { db };

    let app = Router::new()
        .route("/auth", any(auth_handler))
        .with_state(state);

    let listener = match tokio::net::TcpListener::bind(listen_addr).await {
        Ok(listener) => listener,
        Err(e) => {
            error!(
                address = %listen_addr,
                error = %e,
                "Failed to bind HTTP listener"
            );
            return Err(e.into());
        }
    };

    info!(address = %listen_addr, "Authentication service listening");

    if let Err(e) = axum::serve(listener, app).await {
        error!(error = %e, "HTTP server stopped with an error");
        return Err(e.into());
    }

    info!("Authentication service stopped");
    Ok(())
}

fn required_env(name: &'static str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name).map_err(|_| {
        error!(variable = name, "Missing required environment variable");
        format!("Missing required environment variable: {name}").into()
    })
}

async fn auth_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response<Body> {
    let started = Instant::now();

    let Some((username, password)) = parse_basic_auth(&headers) else {
        info!("Authentication rejected: missing or invalid Basic Auth credentials");
        return empty_response(StatusCode::UNAUTHORIZED);
    };

    debug!("Basic Auth credentials parsed");

    let stored_hash = match sqlx::query_scalar::<_, String>(
        "SELECT password FROM mailbox \
         WHERE username = ? AND active = '1' LIMIT 1",
    )
    .bind(&username)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(hash)) => hash,
        Ok(None) => {
            info!("Authentication rejected: mailbox not found or inactive");
            return empty_response(StatusCode::UNAUTHORIZED);
        }
        Err(e) => {
            error!(error = %e, "Database query failed during authentication");
            return empty_response(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    if !verify_password(&password, &stored_hash) {
        info!("Authentication rejected: password verification failed");
        return empty_response(StatusCode::UNAUTHORIZED);
    }

    let user_header = match HeaderValue::from_str(&username) {
        Ok(value) => value,
        Err(_) => {
            warn!("Authentication rejected: username is invalid for an HTTP header");
            return empty_response(StatusCode::UNAUTHORIZED);
        }
    };

    info!(
        elapsed_ms = started.elapsed().as_millis() as u64,
        "Authentication succeeded"
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("X-Remote-User", user_header)
        .body(Body::empty())
        .expect("valid response")
}

fn parse_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, encoded) = value.split_once(' ')?;

    if !scheme.eq_ignore_ascii_case("Basic") || encoded.trim().is_empty() {
        return None;
    }

    let decoded = STANDARD.decode(encoded.trim()).ok()?;
    let credentials = String::from_utf8(decoded).ok()?;
    let (username, password) = credentials.split_once(':')?;

    if username.is_empty() {
        return None;
    }

    Some((username.to_string(), password.to_string()))
}

fn empty_response(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .expect("valid response")
}
