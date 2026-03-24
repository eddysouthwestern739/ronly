#![allow(dead_code)]
use anyhow::Result;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const DOCKER_SHIM: &str = r#"#!/bin/sh
REAL_DOCKER=/usr/bin/docker
case "$1" in
  ps|logs|inspect|stats|top|images|info|version|events|diff)
    exec "$REAL_DOCKER" "$@"
    ;;
  network)
    case "$2" in
      ls|inspect) exec "$REAL_DOCKER" "$@" ;;
    esac
    ;;
  volume)
    case "$2" in
      ls|inspect) exec "$REAL_DOCKER" "$@" ;;
    esac
    ;;
  *)
    echo "rosshd: docker $1 is blocked (read-only session)" >&2
    exit 1
    ;;
esac
echo "rosshd: docker $* is blocked (read-only session)" >&2
exit 1
"#;

const KUBECTL_SHIM: &str = r#"#!/bin/sh
REAL_KUBECTL=/usr/bin/kubectl
case "$1" in
  get|describe|logs|top|explain|version|cluster-info)
    exec "$REAL_KUBECTL" "$@"
    ;;
  api-resources|api-versions)
    exec "$REAL_KUBECTL" "$@"
    ;;
  config)
    case "$2" in
      view) exec "$REAL_KUBECTL" "$@" ;;
    esac
    ;;
  auth)
    case "$2" in
      can-i) exec "$REAL_KUBECTL" "$@" ;;
    esac
    ;;
  *)
    echo "rosshd: kubectl $1 is blocked (read-only session)" >&2
    exit 1
    ;;
esac
echo "rosshd: kubectl $* is blocked (read-only session)" >&2
exit 1
"#;

pub const SHIMS_DIR: &str = "/usr/lib/rosshd/shims";

/// Write shim scripts to the shims directory.
/// Called during server startup.
pub fn install_shims() -> Result<()> {
    let dir = Path::new(SHIMS_DIR);
    fs::create_dir_all(dir)?;

    let shims = [("docker", DOCKER_SHIM), ("kubectl", KUBECTL_SHIM)];

    for (name, content) in &shims {
        let path = dir.join(name);
        fs::write(&path, content)?;
        fs::set_permissions(
            &path,
            fs::Permissions::from_mode(0o755),
        )?;
    }
    Ok(())
}
