//! Joins the command line's socket (`cli_server`) to the running app: the
//! preference that opens and closes it, and what each request does to the
//! open vault. See `cli` for the design.
//!
//! Every write goes through the same command the window uses
//! (`commands::cipher`), so the two cannot drift apart: key selection,
//! password history, `encryptedFor`, the in-memory vault update.

use tauri::{AppHandle, State};

use crate::state::AppState;
use clavix_core::error::{Error, Result};

/// Emitted after every change made from the command line, so the window
/// shows it at once instead of at the next periodic sync.
#[cfg(unix)]
const EVENT_VAULT_CHANGED: &str = "clavix:vault-changed";

/// Whether this build has the command line at all (the preferences hide
/// the switch otherwise).
#[tauri::command]
pub fn cli_access_available() -> bool {
    cfg!(unix)
}

/// Mirror the renderer's "command-line access" preference: open the
/// socket, or close it. Off until the renderer says otherwise.
///
/// The socket is independent of the vault being unlocked. While it is
/// locked a request is answered with "the vault is locked", which tells
/// the person at the terminal what to do; a missing socket could not.
// Async although nothing awaits: binding the listener needs the runtime,
// and a sync command runs on the main thread, outside it.
#[tauri::command]
pub async fn set_cli_access(
    app: AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<()> {
    #[cfg(unix)]
    {
        if let Some(running) = state.cli_server.lock().take() {
            running.stop();
        }
        if enabled {
            let handle = unix::start(app).map_err(|e| Error::Storage {
                reason: format!("command-line socket: {e}"),
            })?;
            *state.cli_server.lock() = Some(handle);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (app, state);
        if enabled {
            return Err(Error::Storage {
                reason: "the command line is not available on this platform".into(),
            });
        }
        Ok(())
    }
}

#[cfg(unix)]
mod unix {
    use std::sync::Arc;

    use serde::Serialize;
    use tauri::{AppHandle, Emitter, Manager};

    use super::EVENT_VAULT_CHANGED;
    use crate::cli::{Reply, Request};
    use crate::cli_server::{
        apply_changes, new_item_input, resolve_folder, resolve_item, with_field_key,
        CliServerHandle, Handler, Scope,
    };
    use crate::commands::cipher;
    use crate::state::AppState;
    use clavix_core::models::SyncResponse;
    use clavix_core::services::cipher::cipher_to_edit_input;
    use clavix_core::session::Session;

    #[derive(Clone, Serialize)]
    struct VaultChanged {
        id: String,
        action: &'static str,
    }

    pub fn start(app: AppHandle) -> std::io::Result<CliServerHandle> {
        use std::os::unix::fs::PermissionsExt;

        let path = crate::cli::socket_path()
            .ok_or_else(|| std::io::Error::other("no runtime or cache directory"))?;
        let dir = path
            .parent()
            .ok_or_else(|| std::io::Error::other("socket path has no directory"))?;
        std::fs::create_dir_all(dir)?;
        // The directory is what keeps other users out during the moment
        // between `bind` and the socket becoming 0600 (see the agent's
        // `make_private`). Under Flatpak it is the app's own directory,
        // which Flatpak creates private and shares with later launches.
        #[cfg(target_os = "linux")]
        let ours = crate::flatpak_instance::runtime_dir().is_none();
        #[cfg(not(target_os = "linux"))]
        let ours = true;
        if ours {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }

        let handler: Handler = Arc::new(move |request| {
            let app = app.clone();
            Box::pin(async move { handle(&app, request).await })
        });
        crate::cli_server::start(path, handler)
    }

    async fn handle(app: &AppHandle, request: Request) -> Reply {
        // Not a sign of the user: see `session::unattended`.
        match crate::session::unattended(dispatch(app, request)).await {
            Ok((id, action)) => {
                let changed = VaultChanged {
                    id: id.clone(),
                    action,
                };
                if let Err(e) = app.emit(EVENT_VAULT_CHANGED, changed) {
                    eprintln!("[clavix cli] could not notify the window: {e}");
                }
                Reply::done(id)
            }
            Err(reason) => Reply::failed(reason),
        }
    }

    /// The open, writable, loaded vault, or why a request cannot go ahead.
    fn open_vault(session: &Option<Session>) -> Result<(&Session, &SyncResponse), String> {
        let session = session
            .as_ref()
            .ok_or("the vault is locked: unlock Clavix first")?;
        if !session.is_writable() {
            return Err(clavix_core::error::Error::ReadOnlySession.to_string());
        }
        let vault = session
            .vault
            .as_ref()
            .ok_or("the vault is not loaded yet: let Clavix finish synchronising")?;
        Ok((session, vault))
    }

    /// The id of the item `target` names, in `scope`.
    fn find(app: &AppHandle, target: &str, scope: Scope) -> Result<String, String> {
        let state = app.state::<AppState>();
        let guard = state.session.lock();
        let (session, vault) = open_vault(&guard)?;
        resolve_item(
            &vault.ciphers,
            &session.user_key,
            &session.org_keys,
            target,
            scope,
        )
        .map(|cipher| cipher.id.clone())
    }

    /// Run one request. On success: the item's id and the name of what was
    /// done to it, for the window.
    async fn dispatch(app: &AppHandle, request: Request) -> Result<(String, &'static str), String> {
        let failed = |e: clavix_core::error::Error| e.to_string();
        match request {
            Request::Create { item } => {
                let input = {
                    let state = app.state::<AppState>();
                    let guard = state.session.lock();
                    let (session, vault) = open_vault(&guard)?;
                    let folder_id = match item.folder.as_deref() {
                        Some(path) => resolve_folder(&vault.folders, &session.user_key, path)?,
                        None => None,
                    };
                    new_item_input(item, folder_id)?
                };
                let id = cipher::create_cipher(app.state(), input)
                    .await
                    .map_err(failed)?;
                Ok((id, "create"))
            }
            Request::Edit { target, changes } => {
                let (id, input) = {
                    let state = app.state::<AppState>();
                    let guard = state.session.lock();
                    let (session, vault) = open_vault(&guard)?;
                    let cipher = resolve_item(
                        &vault.ciphers,
                        &session.user_key,
                        &session.org_keys,
                        &target,
                        Scope::Live,
                    )?;
                    // The window asks for the master password before it
                    // opens such an item in the editor. There is no way to
                    // ask here, so the gate stays shut rather than absent.
                    if cipher.reprompt.unwrap_or(0) != 0 {
                        return Err(
                            "this item asks for the master password before it can be edited: \
                             edit it in Clavix"
                                .into(),
                        );
                    }
                    let folder_id = changes
                        .folder
                        .as_deref()
                        .map(|path| resolve_folder(&vault.folders, &session.user_key, path))
                        .transpose()?;
                    let mut input =
                        with_field_key(cipher, &session.user_key, &session.org_keys, |key| {
                            cipher_to_edit_input(cipher, key)
                        })
                        .map_err(failed)?;
                    apply_changes(&mut input, changes, folder_id)?;
                    (cipher.id.clone(), input)
                };
                cipher::update_cipher(app.state(), id.clone(), input)
                    .await
                    .map_err(failed)?;
                Ok((id, "edit"))
            }
            Request::Archive { target } => {
                let id = find(app, &target, Scope::Live)?;
                cipher::archive_cipher(app.state(), id.clone())
                    .await
                    .map_err(failed)?;
                Ok((id, "archive"))
            }
            Request::Unarchive { target } => {
                let id = find(app, &target, Scope::Live)?;
                cipher::unarchive_cipher(app.state(), id.clone())
                    .await
                    .map_err(failed)?;
                Ok((id, "unarchive"))
            }
            Request::Delete { target } => {
                let id = find(app, &target, Scope::Live)?;
                cipher::soft_delete_cipher(app.state(), id.clone())
                    .await
                    .map_err(failed)?;
                Ok((id, "delete"))
            }
            Request::Restore { target } => {
                let id = find(app, &target, Scope::Trash)?;
                cipher::restore_cipher(app.state(), id.clone())
                    .await
                    .map_err(failed)?;
                Ok((id, "restore"))
            }
        }
    }
}
