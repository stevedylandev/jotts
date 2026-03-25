use axum::{
    extract::FromRequestParts,
    http::request::Parts,
    response::{IntoResponse, Redirect, Response},
};
use rand::RngCore;
use std::sync::Arc;
use subtle::ConstantTimeEq;

use crate::db;
use crate::server::AppState;

pub fn verify_password(input: &str, expected: &str) -> bool {
    const LEN: usize = 256;
    let mut a = [0u8; LEN];
    let mut b = [0u8; LEN];
    let ib = input.as_bytes();
    let eb = expected.as_bytes();
    a[..ib.len().min(LEN)].copy_from_slice(&ib[..ib.len().min(LEN)]);
    b[..eb.len().min(LEN)].copy_from_slice(&eb[..eb.len().min(LEN)]);
    let lengths_match = subtle::Choice::from((ib.len() == eb.len()) as u8);
    (lengths_match & a.ct_eq(&b)).into()
}

pub fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn build_session_cookie(token: &str, secure: bool) -> String {
    let mut cookie = format!(
        "session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800",
        token
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

pub fn clear_session_cookie() -> String {
    "session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".to_string()
}

pub struct AuthSession;

impl FromRequestParts<Arc<AppState>> for AuthSession {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_session_cookie(&parts.headers);
        if let Some(token) = token {
            if is_valid_session(state, &token) {
                return Ok(AuthSession);
            }
        }
        Err(Redirect::to("/login").into_response())
    }
}

fn extract_session_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    let cookie_header = headers.get("cookie")?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("session=") {
            let val = val.trim().to_string();
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    None
}

fn is_valid_session(state: &AppState, token: &str) -> bool {
    match db::get_session_expiry(&state.db, token) {
        Ok(Some(expires_at)) => {
            // Check if session has not expired
            // expires_at is in "YYYY-MM-DD HH:MM:SS" format from SQLite
            let now = chrono_now();
            expires_at > now
        }
        _ => false,
    }
}

fn chrono_now() -> String {
    // Get current UTC time in SQLite-compatible format
    // We'll use a simple approach: query the DB isn't needed,
    // we can compare strings since SQLite datetime format is sortable
    // But we need the current time. Let's use std::time.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Convert to UTC datetime string
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Calculate date from days since epoch (1970-01-01)
    let (year, month, day) = days_to_ymd(days_since_epoch as i64);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hours, minutes, seconds
    )
}

fn days_to_ymd(mut days: i64) -> (i64, i64, i64) {
    // Algorithm to convert days since 1970-01-01 to (year, month, day)
    days += 719468; // days from 0000-03-01 to 1970-01-01
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = (days - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as i64, d as i64)
}
