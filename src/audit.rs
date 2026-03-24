use chrono::Utc;
use serde::Serialize;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::sync::OnceLock;

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);
static LOG_FILE: OnceLock<Option<Mutex<std::fs::File>>> =
    OnceLock::new();

/// Initialize audit logging. Call once at startup.
/// If path is Some, logs go to the file. Otherwise stdout.
pub fn init(path: Option<&Path>) {
    LOG_FILE.get_or_init(|| {
        path.and_then(|p| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .ok()
                .map(Mutex::new)
        })
    });
}

pub fn new_session_id() -> String {
    let n =
        SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:08x}", n)
}

#[derive(Serialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub session_id: String,
    pub user: String,
    pub client_ip: String,
    pub event: String,
    pub command: String,
    pub result: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl AuditEntry {
    pub fn log(
        session_id: &str,
        user: &str,
        addr: Option<SocketAddr>,
        event: &str,
        command: &str,
        result: &str,
        reason: Option<&str>,
    ) {
        let entry = AuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            session_id: session_id.to_string(),
            user: user.to_string(),
            client_ip: addr
                .map(|a| a.to_string())
                .unwrap_or_default(),
            event: event.to_string(),
            command: command.to_string(),
            result: result.to_string(),
            reason: reason.map(|s| s.to_string()),
        };
        let Ok(json) = serde_json::to_string(&entry)
        else {
            return;
        };
        match LOG_FILE.get() {
            Some(Some(f)) => {
                if let Ok(mut f) = f.lock() {
                    let _ =
                        writeln!(f, "{}", json);
                }
            }
            _ => println!("{}", json),
        }
    }
}
