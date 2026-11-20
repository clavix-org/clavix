//! What Clavix is used for on this machine: a vault client (the default),
//! or only the SSH agent of a paired phone, with no vault at all.
//!
//! In phone-only mode there is no account, no server and no master
//! password. The keys are on the phone (Clavix Approve, sign mode); this
//! machine holds the pairing and runs the key-less agent that the vault
//! mode runs while the vault is locked (`phone_sign`). So the mode changes
//! two rules, and nothing else:
//!
//! - pairing and forgetting a phone do not need an unlocked vault (there
//!   is none); every signature still needs the phone's own confirmation;
//! - the agent runs whenever a phone is paired, without the "use while
//!   locked" switch, which is a vault-mode setting.
//!
//! The mode is one small file in the configuration directory, read by the
//! backend at launch (the agent starts before any window). It holds no
//! secret. It exists only where the phone features do.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
use ts_rs::TS;

use crate::state::AppState;
use clavix_core::error::{Error, Result};

const MODE_FILE: &str = "mode.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub enum AppMode {
    /// A Bitwarden or Vaultwarden vault, with or without phone features.
    #[default]
    Vault,
    /// No vault: the agent of the paired phones only.
    PhoneOnly,
}

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct AppModeStatus {
    pub mode: AppMode,
    /// This build can be used in phone-only mode (`phone-approval`
    /// feature, Unix only).
    pub phone_only_available: bool,
}

#[derive(Serialize, Deserialize)]
struct Stored {
    mode: AppMode,
}

fn storage_error(dir: &Path, e: impl std::fmt::Display) -> Error {
    Error::Storage {
        reason: format!("application mode in {}: {e}", dir.display()),
    }
}

/// `<config dir>/clavix`.
pub(crate) fn mode_dir() -> Result<PathBuf> {
    dirs::config_dir()
        .map(|d| d.join("clavix"))
        .ok_or_else(|| Error::Storage {
            reason: "could not locate the configuration directory for this platform".into(),
        })
}

/// The mode stored in `dir`. Anything unreadable is the default: a vault
/// client, which runs no agent without an unlocked vault or an explicit
/// switch.
pub(crate) fn load_from(dir: &Path) -> AppMode {
    if !cfg!(phone_approval) {
        return AppMode::Vault;
    }
    std::fs::read(dir.join(MODE_FILE))
        .ok()
        .and_then(|raw| serde_json::from_slice::<Stored>(&raw).ok())
        .map(|s| s.mode)
        .unwrap_or_default()
}

pub(crate) fn load() -> AppMode {
    mode_dir().map(|d| load_from(&d)).unwrap_or_default()
}

/// Replaced atomically. The default mode is the absence of the file.
pub(crate) fn save_to(dir: &Path, mode: AppMode) -> Result<()> {
    let file = dir.join(MODE_FILE);
    if mode == AppMode::Vault {
        return match std::fs::remove_file(&file) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(storage_error(dir, e)),
            _ => Ok(()),
        };
    }
    let write = || -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let tmp = dir.join(format!("{MODE_FILE}.tmp"));
        std::fs::write(
            &tmp,
            serde_json::to_vec(&Stored { mode }).map_err(std::io::Error::other)?,
        )?;
        std::fs::rename(tmp, &file)
    };
    write().map_err(|e| storage_error(dir, e))
}

/// Whether the mode may become `mode` now.
///
/// Phone-only is for a machine with no vault account: with a session open
/// or stored, the way there is to sign out and keep the phone
/// (`auth::logout`), which the user is asked about.
fn check_change(mode: AppMode, session_open: bool, account_stored: bool) -> Result<()> {
    match mode {
        AppMode::Vault => Ok(()),
        AppMode::PhoneOnly if !cfg!(phone_approval) => Err(Error::Storage {
            reason: "this build of Clavix has no phone-only mode".into(),
        }),
        AppMode::PhoneOnly if session_open || account_stored => Err(Error::Storage {
            reason: "sign out of the vault before switching to phone-only mode".into(),
        }),
        AppMode::PhoneOnly => Ok(()),
    }
}

#[tauri::command]
pub fn app_mode() -> AppModeStatus {
    AppModeStatus {
        mode: load(),
        phone_only_available: cfg!(phone_approval),
    }
}

/// Choose the mode: at first launch, when adding a vault to a phone-only
/// setup, or when going back before any account was added. The phone
/// pairing is kept in both directions.
#[tauri::command]
pub fn set_app_mode(
    app: AppHandle,
    state: State<'_, AppState>,
    mode: AppMode,
) -> Result<AppModeStatus> {
    let session_open = state.session.lock().is_some();
    let account_stored = clavix_core::store::load_session()?.is_some();
    check_change(mode, session_open, account_stored)?;
    let dir = mode_dir()?;
    if mode == AppMode::Vault && load_from(&dir) == AppMode::PhoneOnly {
        // The paired phones keep working while the vault account is
        // being added, and whenever that vault is locked afterwards.
        crate::commands::phone_sign::keep_serving_when_locked()?;
    }
    save_to(&dir, mode)?;
    // The agent follows the mode: started for a phone-only setup that has
    // a phone, left alone otherwise.
    crate::commands::phone_sign::after_vault_lock(&app);
    Ok(app_mode())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(phone_approval)]
    #[test]
    fn the_mode_is_a_vault_client_unless_the_file_says_phone_only() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("clavix");
        assert_eq!(load_from(&dir), AppMode::Vault);

        save_to(&dir, AppMode::PhoneOnly).unwrap();
        assert_eq!(load_from(&dir), AppMode::PhoneOnly);
        assert!(!dir.join(format!("{MODE_FILE}.tmp")).exists());

        // Garbage is not phone-only: no agent without a vault or a switch.
        std::fs::write(dir.join(MODE_FILE), b"{\"mode\":\"anything\"}").unwrap();
        assert_eq!(load_from(&dir), AppMode::Vault);
        std::fs::write(dir.join(MODE_FILE), b"not json").unwrap();
        assert_eq!(load_from(&dir), AppMode::Vault);

        save_to(&dir, AppMode::PhoneOnly).unwrap();
        save_to(&dir, AppMode::Vault).unwrap();
        assert!(!dir.join(MODE_FILE).exists());
        assert_eq!(load_from(&dir), AppMode::Vault);
        // Twice is fine.
        save_to(&dir, AppMode::Vault).unwrap();
    }

    #[cfg(phone_approval)]
    #[test]
    fn phone_only_is_for_a_machine_without_a_vault_account() {
        assert!(check_change(AppMode::PhoneOnly, false, false).is_ok());
        // Unlocked, or locked with an account stored: sign out first.
        assert!(check_change(AppMode::PhoneOnly, true, true).is_err());
        assert!(check_change(AppMode::PhoneOnly, false, true).is_err());
        assert!(check_change(AppMode::PhoneOnly, true, false).is_err());
        // Adding a vault is always possible.
        assert!(check_change(AppMode::Vault, false, false).is_ok());
        assert!(check_change(AppMode::Vault, true, true).is_ok());
    }

    #[cfg(not(phone_approval))]
    #[test]
    fn a_build_without_phone_features_has_no_phone_only_mode() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(MODE_FILE), b"{\"mode\":\"phoneOnly\"}").unwrap();
        assert_eq!(load_from(tmp.path()), AppMode::Vault);
        assert!(check_change(AppMode::PhoneOnly, false, false).is_err());
        assert!(!app_mode().phone_only_available);
    }
}
