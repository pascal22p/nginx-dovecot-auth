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
use std::{env, net::SocketAddr};

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
        .init();

    let db_host = env::var("DB_HOST")?;
    let db_port: u16 = env::var("DB_PORT")
        .unwrap_or_else(|_| "3306".to_string())
        .parse()?;
    let db_user = env::var("DB_USER")?;
    let db_password = env::var("DB_PASSWORD")?;
    let db_name = env::var("DB_NAME")?;

    let options = MySqlConnectOptions::new()
        .host(&db_host)
        .port(db_port)
        .username(&db_user)
        .password(&db_password)
        .database(&db_name);

    let db = MySqlPoolOptions::new()
        .max_connections(10)
        .connect_with(options)
        .await?;

    let state = AppState { db };

    let app = Router::new()
        .route("/auth", any(auth_handler))
        .with_state(state);

    let listen_addr: SocketAddr = env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()?;

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;

    println!("Authentication service listening on {listen_addr}");

    axum::serve(listener, app).await?;

    Ok(())
}

async fn auth_handler(State(state): State<AppState>, headers: HeaderMap) -> Response<Body> {
    let Some((username, password)) = parse_basic_auth(&headers) else {
        return empty_response(StatusCode::UNAUTHORIZED);
    };

    let stored_hash = match sqlx::query_scalar::<_, String>(
        "SELECT password FROM mailbox \
         WHERE username = ? AND active = '1' LIMIT 1",
    )
    .bind(&username)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(hash)) => hash,
        Ok(None) => return empty_response(StatusCode::UNAUTHORIZED),
        Err(error) => {
            eprintln!("Database query failed: {error}");
            return empty_response(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    if !verify_password(&password, &stored_hash) {
        return empty_response(StatusCode::UNAUTHORIZED);
    }

    let Ok(user_header) = HeaderValue::from_str(&username) else {
        return empty_response(StatusCode::UNAUTHORIZED);
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("X-Remote-User", user_header)
        .body(Body::empty())
        .expect("valid response")
}

fn parse_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, encoded) = value.split_once(' ')?;

    if !scheme.eq_ignore_ascii_case("Basic") || encoded.is_empty() {
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
