use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State, UserAttentionType};
use tokio::sync::oneshot;

use crate::phone_approval::{self, ApprovalRequest, BoxFuture, ConfirmDialog, LockProbe, Verdict};
use crate::ssh_agent::{self, SignGuard, SignPolicy, SignRequest};
use crate::state::AppState;
use clavix_core::crypto::decrypt_name;
use clavix_core::error::{Error, Result};
use clavix_core::models::CipherType;

/// Payload emitted to the frontend when a signature needs approval.
/// The dialog shows the key and answers via `respond_ssh_agent_confirm`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmRequest {
    pub id: u64,
    pub comment: String,
    pub algorithm: String,
    pub fingerprint: String,
    /// Process name of the requesting client, when it could be resolved.
    /// Advisory only — see `ssh_agent::CallerInfo` for why this must not
    /// drive a trust decision.
    pub caller_name: Option<String>,
    /// Pid of the requesting client, when it could be resolved.
    pub caller_pid: Option<u32>,
    /// Hosts the requesting `ssh` is bound to (`session-bind@openssh.com`),
    /// outermost first; the last one is the destination. Empty when the
    /// client sent no binding (OpenSSH < 8.9, git signing, PuTTY).
    pub hops: Vec<ConfirmHop>,
    /// How long the dialog waits before denying: 30 s, or 90 s when the
    /// phone is asked too.
    pub timeout_ms: u64,
    /// The same request was sent to the paired phone; the first answer
    /// wins.
    pub phone_asked: bool,
}

/// Emitted when a confirmation was answered elsewhere (on the phone), so
/// the dialog closes or drops it from its queue.
pub const EVENT_CONFIRM_RESOLVED: &str = "ssh-agent-confirm-resolved";

/// How long the dialog alone waits before denying.
const DIALOG_TIMEOUT: Duration = Duration::from_secs(30);

/// "Ask the phone too" settings, a per-device preference kept by the
/// front end next to the confirmation policy and pushed here with
/// `set_phone_approval_options`. Read at each confirmation, so a change
/// applies without restarting the agent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, ts_rs::TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct PhoneApprovalOptions {
    pub enabled: bool,
    /// Seconds the dialog is up alone before the phone is asked too;
    /// 0 asks both at once. Capped at `phone_approval::MAX_DELAY`.
    pub delay_s: u32,
}

/// One verified session binding, ready for display.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmHop {
    /// Names `known_hosts` gives this host key, e.g. `"github.com"`.
    /// `None` when the key is absent or only in hashed entries — the
    /// dialog then falls back to the fingerprint.
    pub host: Option<String>,
    /// `"SHA256:…"` fingerprint of the server host key.
    pub fingerprint: String,
    /// The agent is forwarded through this host (`ssh -A`).
    pub forwarded: bool,
}

/// Plain-text `known_hosts` names recorded for `key_blob`, comma-joined.
///
/// Hashed entries (`|1|salt|hash`, `HashKnownHosts yes`) can't be turned
/// back into a name and are skipped, as are `@revoked` lines; a
/// `@cert-authority` key is a CA, not this host's key, so it never
/// matches a host key blob anyway. Names are labels the user already
/// accepted for that key — nothing here is trusted beyond display.
fn known_host_names(key_blob: &[u8], known_hosts: &str) -> Option<String> {
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::STANDARD;
    let mut names: Vec<String> = Vec::new();
    for line in known_hosts.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(mut hosts) = fields.next() else {
            continue;
        };
        if hosts.starts_with('@') {
            if hosts == "@revoked" {
                continue;
            }
            hosts = match fields.next() {
                Some(h) => h,
                None => continue,
            };
        }
        let (Some(_keytype), Some(b64)) = (fields.next(), fields.next()) else {
            continue;
        };
        if hosts.starts_with('|') || engine.decode(b64).ok().as_deref() != Some(key_blob) {
            continue;
        }
        for h in hosts.split(',') {
            let h: String = h.chars().filter(|c| !c.is_control()).take(64).collect();
            if !h.is_empty() && !h.starts_with('!') && !names.contains(&h) {
                names.push(h);
            }
        }
    }
    (!names.is_empty()).then(|| names.join(", "))
}

/// Read the user's and the system `known_hosts` files, best effort.
fn read_known_hosts() -> String {
    let mut out = String::new();
    let mut paths = Vec::new();
    if let Some(home) = dirs::home_dir() {
        paths.push(home.join(".ssh").join("known_hosts"));
    }
    #[cfg(unix)]
    paths.push(std::path::PathBuf::from("/etc/ssh/ssh_known_hosts"));
    for p in paths {
        if let Ok(text) = std::fs::read_to_string(p) {
            out.push_str(&text);
            out.push('\n');
        }
    }
    out
}

fn confirm_hops(hops: &[ssh_agent::HostHop]) -> Vec<ConfirmHop> {
    if hops.is_empty() {
        return Vec::new();
    }
    let known_hosts = read_known_hosts();
    hops.iter()
        .map(|h| ConfirmHop {
            host: known_host_names(&h.key_blob, &known_hosts),
            fingerprint: h.fingerprint.clone(),
            forwarded: h.forwarded,
        })
        .collect()
}

/// Turn one SSH-key cipher into either agent-loadable material
/// (`(id, name, pem)`) or a `SkippedKey` explaining the refusal.
///
/// Total by construction: there is no third outcome, which is what keeps
/// the agent's key count reconcilable with the vault's SSH-key count.
fn classify_ssh_cipher(
    c: &clavix_core::models::Cipher,
    key: &clavix_core::crypto::SymmetricKey,
) -> std::result::Result<(String, String, String), SkippedKey> {
    // The name is itself vault ciphertext and can fail to decrypt. Fall
    // back to the cipher id so the row stays identifiable — an unnamed
    // entry the user can't locate is barely better than no entry at all.
    let name =
        decrypt_name(&c.name, key).unwrap_or_else(|_| format!("(unreadable name — item {})", c.id));

    let Some(ssh) = c.ssh_key.as_ref() else {
        return Err(SkippedKey {
            name,
            reason: "item is typed as an SSH key but carries no SSH key data".into(),
        });
    };
    let Some(pk_enc) = ssh.private_key.as_deref() else {
        return Err(SkippedKey {
            name,
            reason: "no private key stored on this item — only a public key".into(),
        });
    };
    let Ok(pem) = decrypt_name(pk_enc, key) else {
        return Err(SkippedKey {
            name,
            reason: "could not decrypt the private key with this vault's keys".into(),
        });
    };
    Ok((c.id.clone(), name, pem))
}

fn parse_sign_policy(policy: &str) -> SignPolicy {
    match policy {
        "always" => SignPolicy::Always,
        "session" => SignPolicy::PerSession,
        // Unknown / "never" → sign silently (historical default).
        _ => SignPolicy::Never,
    }
}

fn next_confirm_id(state: &AppState) -> u64 {
    let mut seq = state.ssh_confirm_seq.lock();
    *seq = seq.wrapping_add(1);
    *seq
}

/// Ask the user (via the confirmation dialog) to approve one signature.
/// Runs inside the agent task; parks a `oneshot` in `AppState`, surfaces
/// the window, emits the request, and waits — denying on timeout so a
/// missed prompt can't hang an `ssh`/`git` invocation forever.
async fn request_confirmation(
    app: &AppHandle,
    id: u64,
    req: &SignRequest,
    timeout: Duration,
    phone_asked: bool,
) -> bool {
    let state = app.state::<AppState>();
    let (tx, rx) = oneshot::channel();
    state.ssh_confirms.lock().insert(id, tx);

    surface_prompt(app);

    let payload = ConfirmRequest {
        id,
        comment: req.key.comment.clone(),
        algorithm: req.key.algorithm.clone(),
        fingerprint: req.key.fingerprint.clone(),
        caller_name: req.caller.as_ref().and_then(|c| c.name.clone()),
        caller_pid: req.caller.as_ref().map(|c| c.pid),
        hops: confirm_hops(&req.hops),
        timeout_ms: timeout.as_millis() as u64,
        phone_asked,
    };
    if app.emit("ssh-agent-confirm", &payload).is_err() {
        state.ssh_confirms.lock().remove(&id);
        return false;
    }

    let approved = match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(approved)) => approved,
        // Timed out, or the sender was dropped — deny and clean up.
        _ => {
            state.ssh_confirms.lock().remove(&id);
            false
        }
    };
    release_prompt(app);
    approved
}

/// Make a confirmation impossible to miss. Signing usually happens while
/// Clavix sits in the tray or behind other windows, and a prompt nobody
/// sees just times out.
///
/// A plain `show` + `set_focus` is not enough: GNOME's focus-stealing
/// prevention leaves the window buried (see `tray::raise_main_window`).
/// So: the tray's raise dance, the window kept above the others while any
/// confirmation is pending, and the platform's attention request (urgency
/// hint on Linux, taskbar flash on Windows, dock bounce on macOS) in case
/// the window manager refuses to raise it at all. Always-on-top has no
/// effect under Wayland; the attention request still applies.
fn surface_prompt(app: &AppHandle) {
    super::tray::raise_main_window_pinned(app, |app| {
        let pending = !app.state::<AppState>().ssh_confirms.lock().is_empty();
        if pending {
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.request_user_attention(Some(UserAttentionType::Critical));
            }
        }
        pending
    });
}

/// Undo `surface_prompt` once no confirmation is pending any more. Runs
/// on the main thread, after any raise already queued there, and checks
/// the pending set at that moment: a prompt that arrived since keeps the
/// window pinned.
fn release_prompt(app: &AppHandle) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        if !handle.state::<AppState>().ssh_confirms.lock().is_empty() {
            return;
        }
        if let Some(win) = handle.get_webview_window("main") {
            let _ = win.set_always_on_top(false);
            let _ = win.request_user_attention(None);
        }
    });
}

/// The dialog side of one request raced against the phone.
struct DialogPrompt {
    app: AppHandle,
    id: u64,
    req: SignRequest,
}

impl ConfirmDialog for DialogPrompt {
    fn open(&self, timeout: Duration, phone_asked: bool) -> BoxFuture<bool> {
        let (app, id, req) = (self.app.clone(), self.id, self.req.clone());
        Box::pin(async move { request_confirmation(&app, id, &req, timeout, phone_asked).await })
    }

    fn close(&self) {
        let state = self.app.state::<AppState>();
        // Dropping the sender ends the parked `request_confirmation`
        // (which nobody awaits any more) and makes a late click a no-op.
        let was_pending = state.ssh_confirms.lock().remove(&self.id).is_some();
        if was_pending {
            let _ = self.app.emit(EVENT_CONFIRM_RESOLVED, self.id);
        }
        // The parked `request_confirmation` is dropped, so its own
        // `release_prompt` never runs: unpin the window here.
        release_prompt(&self.app);
    }
}

/// A short name for this machine, shown on the phone ("from Clavix
/// desktop « name »"). Unverified by the phone, like the caller.
fn machine_label() -> String {
    let from_env = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok();
    #[cfg(unix)]
    let from_env = from_env.or_else(|| {
        std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|s| s.trim().to_string())
    });
    from_env
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Clavix desktop".into())
}

/// Host key fingerprint → `known_hosts` names, for the phone's hints.
pub(crate) fn phone_hints(
    hops: &[ssh_agent::HostHop],
) -> std::collections::BTreeMap<String, String> {
    confirm_hops(hops)
        .into_iter()
        .filter_map(|h| h.host.map(|name| (h.fingerprint, name)))
        .collect()
}

/// Confirm one signature: the dialog alone, or the dialog raced against
/// the paired phone when the user turned that on and the phone can check
/// this request on its own.
async fn confirm_signature(app: AppHandle, req: SignRequest) -> bool {
    let state = app.state::<AppState>();
    let id = next_confirm_id(&state);
    let phone = *state.phone_options.lock();
    let approver = state.phone_approver.lock().clone();
    // One journal line per approval, saying where it was given: a login
    // that goes through with no prompt later (an approval remembered for
    // the session) can then be traced back to the answer that allowed it.
    let what = approved_what(&req);
    if !(phone.enabled && approver.is_paired() && req.phone_eligible()) {
        let approved = request_confirmation(&app, id, &req, DIALOG_TIMEOUT, false).await;
        if approved {
            eprintln!("[clavix agent] approved in the desktop dialog for {what}");
        }
        return approved;
    }
    let approval =
        ApprovalRequest::from_sign_request(&req, machine_label(), phone_hints(&req.hops));
    let dialog = DialogPrompt { app, id, req };
    let probe: LockProbe = Arc::new(|| Box::pin(crate::screen_lock::probe()));
    let verdict = phone_approval::race(
        approval,
        approver,
        &dialog,
        Duration::from_secs(phone.delay_s.into()),
        probe,
    )
    .await;
    match verdict {
        Verdict::ApprovedOnThePhone => eprintln!("[clavix phone] approved on the phone for {what}"),
        Verdict::ApprovedAtTheDesk => {
            eprintln!("[clavix agent] approved in the desktop dialog for {what}")
        }
        Verdict::Refused => {}
    }
    verdict.approved()
}

/// "<key fingerprint> → <destination host key fingerprint>", for the
/// journal; the key alone for a request that names no destination.
fn approved_what(req: &SignRequest) -> String {
    match req.hops.last().filter(|h| !h.forwarded) {
        Some(host) => format!("{} → {}", req.key.fingerprint, host.fingerprint),
        None => req.key.fingerprint.clone(),
    }
}

/// Whether approvals remembered under "once per session" are for one
/// destination only: while a paired phone is asked. Its approval is for
/// the server it showed, not for every server the key opens.
fn remember_per_host(state: &AppState) -> bool {
    state.phone_options.lock().enabled && state.phone_approver.lock().is_paired()
}

/// Apply the "ask the phone too" settings.
#[tauri::command]
pub fn set_phone_approval_options(
    state: State<'_, AppState>,
    options: PhoneApprovalOptions,
) -> Result<()> {
    *state.phone_options.lock() = options;
    // Called on every unlock: the moment the stored pairing can be read.
    crate::commands::phone::load_paired_phone(&state);
    Ok(())
}

/// Resolve a pending signature confirmation. Called by the dialog with
/// the user's decision; a no-op if the request already timed out.
#[tauri::command]
pub fn respond_ssh_agent_confirm(
    state: State<'_, AppState>,
    id: u64,
    approved: bool,
) -> Result<()> {
    if let Some(tx) = state.ssh_confirms.lock().remove(&id) {
        let _ = tx.send(approved);
    }
    Ok(())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExposedKey {
    /// Comment field of the OpenSSH key — falls back to the cipher name
    /// when the key's own comment is empty.
    pub comment: String,
    /// Wire-format algorithm name, e.g. `"ssh-ed25519"` / `"ssh-rsa"`.
    pub algorithm: String,
    /// Same `"SHA256:…"` format `ssh-add -l` prints.
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedKey {
    /// Cipher name (or key comment if cipher decryption failed).
    pub name: String,
    /// Human-readable reason — surfaced to the user so they know whether
    /// the key was skipped because of an unsupported algorithm
    /// (DSA, FIDO `sk-*`), a leftover passphrase-encrypted PEM that pre-dates
    /// the import-time decrypt flow, or a malformed key.
    pub reason: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshAgentStatus {
    pub running: bool,
    pub socket_path: Option<String>,
    pub keys: Vec<ExposedKey>,
    /// Keys the last start could not load. Carried by `ssh_agent_status`
    /// too (replayed from `AppState`, not recomputed), so reopening the
    /// settings dialog still explains a key count that looks short.
    pub skipped: Vec<SkippedKey>,
}

/// Deny every pending signature confirmation: send `false` down each
/// parked oneshot. The agent itself already cancels parked authorizations
/// when it stops (`SignGuard::cancel`), so this is not what makes the
/// stop prompt — it is what closes the *UI side* of a prompt that is
/// about to become unreachable, instead of leaving the dialog waiting
/// for its own timeout.
pub(crate) fn deny_pending_confirmations(state: &AppState) {
    let pending = std::mem::take(&mut *state.ssh_confirms.lock());
    for (_, tx) in pending {
        let _ = tx.send(false);
    }
}

/// Take the running agent (and the locked-vault agent, if any) out of
/// `state`, deny every pending confirmation and stop them.
///
/// Every synchronous teardown path — `auth::lock`, `auth::logout`,
/// `tray::lock_session` — goes through this instead of taking the handle
/// and calling `stop_sync()` on it directly. The agent cancels its own
/// parked authorizations, so the waiting *client* is answered either way;
/// the dialog on screen is not. A path that skips the drain leaves a
/// prompt with inert buttons up for the rest of its 30 s timeout, over a
/// session that is already locked.
pub(crate) fn stop_agent_sync(state: &AppState) {
    stop_vault_agent_sync(state);
    // A locked-vault agent too: logout stops everything, and the lock
    // paths start it again afterwards (`phone_sign::after_vault_lock`).
    crate::commands::phone_sign::stop_locked_agent_sync(state);
}

/// Everything `stop_agent_sync` stops but the locked-vault agent: the
/// vault agent, its prompts, the approving phone's channel keys.
fn stop_vault_agent_sync(state: &AppState) {
    let handle = {
        let mut slot = state.ssh_agent.lock();
        slot.take()
    };
    // Unconditionally, before the stop: a prompt outliving the agent that
    // raised it is exactly the state this exists to prevent, so it must
    // not depend on the slot still holding a handle.
    deny_pending_confirmations(state);
    // The pairing's channel keys go with the vault keys.
    crate::commands::phone::unload_paired_phone(state);
    if let Some(h) = handle {
        h.stop_sync();
    }
    // Same reasoning as `stop_ssh_agent`: the skip list describes a load
    // that no longer has a running agent behind it.
    state.ssh_skipped.lock().clear();
}

/// Lock: drop the session, then stop the agents. Returns whether there
/// was a session to drop.
///
/// The order is what `install_vault_agent` relies on. A `start_ssh_agent`
/// that began before the lock loaded its keys from a session that was
/// still there, and puts its agent in the slot later. With the session
/// gone first, it either sees that under the session lock and gives up,
/// or it stored its agent before, and the stop that follows here takes
/// it. Stopping first left a window where the start found the session,
/// the stop found an empty slot, and the vault's keys were then served
/// over a locked vault until the next unlock.
///
/// A lock that finds the vault already locked leaves the locked-vault
/// agent alone. That agent is what the first lock started to serve the
/// phone's keys, and the second lock is routine: after an auto-lock or a
/// tray lock, the renderer hears `clavix:session-locked` and calls `lock`
/// in turn, at whatever moment it gets to run (late, with the window
/// hidden and the screen locked). Stopping it there left Clavix running
/// with no agent socket until the next unlock, and nothing restarted it:
/// `after_vault_lock` only follows a lock that dropped a session.
pub(crate) fn lock_session_sync(state: &AppState) -> bool {
    let was_unlocked = state.session.lock().take().is_some();
    if was_unlocked {
        stop_agent_sync(state);
    } else {
        stop_vault_agent_sync(state);
    }
    was_unlocked
}

/// Logout: drop the session and stop every agent, the locked-vault one
/// included, whether or not the vault was unlocked. The caller restarts
/// it if the phone is kept (`auth::logout`).
pub(crate) fn logout_session_sync(state: &AppState) {
    state.session.lock().take();
    stop_agent_sync(state);
}

/// Put a freshly started vault agent in its slot, unless the vault was
/// locked (or logged out) while it was starting: then the agent is handed
/// back, for the caller to stop. Checked and stored under the session
/// lock; see `lock_session_sync` for why that is enough.
fn install_vault_agent(
    state: &AppState,
    handle: ssh_agent::SshAgentHandle,
) -> Option<ssh_agent::SshAgentHandle> {
    let session = state.session.lock();
    if session.is_none() {
        return Some(handle);
    }
    *state.ssh_agent.lock() = Some(handle);
    None
}

#[tauri::command]
pub async fn start_ssh_agent(
    state: State<'_, AppState>,
    app: AppHandle,
    policy: String,
) -> Result<SshAgentStatus> {
    // One agent transition at a time on the socket (see `AppState::
    // agent_transition`); held until the new agent is in its slot.
    let _transition = state.agent_transition.lock().await;
    // The locked-vault agent, if the vault was locked until now, goes
    // first: it holds the socket, and only the phones' keys.
    crate::commands::phone_sign::stop_locked_agent(&state).await;
    // Stop any previous instance first — simpler than reconciling state.
    let previous = {
        let mut slot = state.ssh_agent.lock();
        slot.take()
    };
    if let Some(h) = previous {
        deny_pending_confirmations(&state);
        h.stop().await;
    }

    // Decrypt every SSH key item from the current vault, inside the lock.
    //
    // Every SSH-key cipher must come out of this loop as either a decrypted
    // entry or a `SkippedKey`. Dropping one silently (as an earlier
    // `filter_map` did) makes the agent's key count disagree with the
    // vault's SSH-key count with nothing anywhere to explain the gap.
    let mut skipped: Vec<SkippedKey> = Vec::new();
    let decrypted: Vec<(String, String, String)> = {
        let guard = state.session.lock();
        let session = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        let vault = session.vault.as_ref().ok_or_else(|| Error::Storage {
            reason: "no vault synced yet — synchronise first".into(),
        })?;
        let mut out = Vec::new();
        for c in vault
            .ciphers
            .iter()
            .filter(|c| c.deleted_date.is_none())
            .filter(|c| matches!(c.kind, CipherType::SshKey))
        {
            let owner =
                clavix_core::services::cipher::owning_key(c, &session.user_key, &session.org_keys);
            let item = clavix_core::services::cipher::item_key(c, owner);
            let key = item.as_ref().unwrap_or(owner);
            match classify_ssh_cipher(c, key) {
                Ok(entry) => out.push(entry),
                Err(s) => skipped.push(s),
            }
        }
        out
    };

    let socket_path = ssh_agent::default_socket_path()?;

    let mut agent_keys = Vec::new();
    for (_id, name, pem) in &decrypted {
        match ssh_agent::try_load_agent_key(pem, name) {
            Ok(Some(k)) => agent_keys.push(k),
            Ok(None) => skipped.push(SkippedKey {
                name: name.clone(),
                reason: "unsupported algorithm (only Ed25519 and RSA load into the agent today)"
                    .into(),
            }),
            Err(Error::Crypto { reason }) => {
                // The most common case here is the legacy "passphrase-protected"
                // marker from before the import-time decrypt flow shipped.
                // Surface the underlying message verbatim so the user
                // understands what to do (re-open the cipher to decrypt it,
                // or fix a malformed PEM).
                // Don't log the decrypted item name — it's vault-content
                // metadata that would land in stderr/journald. The name still
                // reaches the user via the returned `SkippedKey` list.
                eprintln!("[clavix agent] skipping a key: {reason}");
                skipped.push(SkippedKey {
                    name: name.clone(),
                    reason,
                });
            }
            Err(e) => {
                eprintln!("[clavix agent] skipping a key: {e}");
                skipped.push(SkippedKey {
                    name: name.clone(),
                    reason: e.to_string(),
                });
            }
        }
    }

    // Wire the signature-approval policy. `Never` needs no callback and
    // keeps the fast silent path; the confirming policies get a callback
    // that drives the front-end dialog through `AppState`.
    let sign_policy = parse_sign_policy(&policy);
    let confirm: Option<ssh_agent::ConfirmFn> = if matches!(sign_policy, SignPolicy::Never) {
        None
    } else {
        let app = app.clone();
        Some(Arc::new(move |req: SignRequest| {
            Box::pin(confirm_signature(app.clone(), req))
                as std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>
        }))
    };
    let per_host_app = app.clone();
    let guard = SignGuard::new(sign_policy, confirm).remembering_per_host(Arc::new(move || {
        remember_per_host(&per_host_app.state::<AppState>())
    }));

    let handle = ssh_agent::start_agent(socket_path.clone(), agent_keys, guard).await?;
    let exposed: Vec<ExposedKey> = handle
        .keys
        .iter()
        .map(|k| ExposedKey {
            comment: k.comment.clone(),
            algorithm: k.algorithm.clone(),
            fingerprint: k.fingerprint.clone(),
        })
        .collect();
    let status = SshAgentStatus {
        running: true,
        socket_path: Some(handle.socket_path.to_string_lossy().into_owned()),
        keys: exposed,
        skipped: skipped.clone(),
    };

    // The keys were read from the session a while ago (decryption, key
    // parsing, the socket bind): the vault may have locked since.
    if let Some(stale) = install_vault_agent(&state, handle) {
        stale.stop().await;
        return Err(Error::NotAuthenticated);
    }

    // Remember why keys were left out so `ssh_agent_status` can answer the
    // "why does it say 8 when I have 9?" question on any later poll, not
    // just in this reply.
    *state.ssh_skipped.lock() = skipped;
    Ok(status)
}

#[tauri::command]
pub async fn stop_ssh_agent(state: State<'_, AppState>) -> Result<()> {
    let _transition = state.agent_transition.lock().await;
    let handle = {
        let mut slot = state.ssh_agent.lock();
        slot.take()
    };
    if let Some(h) = handle {
        deny_pending_confirmations(&state);
        h.stop().await;
    }
    // The skip list describes a load that no longer has a running agent
    // behind it — drop it rather than let it resurface on a later start
    // that skipped nothing.
    state.ssh_skipped.lock().clear();
    Ok(())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptedSshKey {
    pub private_key: String,
    pub public_key: String,
    pub key_fingerprint: String,
}

/// Parse an OpenSSH private key, decrypt it with `passphrase` if needed,
/// and return the canonical unencrypted PEM together with the SSH public-key
/// line and SHA-256 fingerprint. Mirrors the import-time UX of Bitwarden
/// Desktop: the passphrase is consumed once, never stored.
#[tauri::command]
pub fn decrypt_ssh_private_key(
    private_key: String,
    passphrase: Option<String>,
) -> Result<DecryptedSshKey> {
    use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};

    let mut pk = PrivateKey::from_openssh(&private_key).map_err(|e| Error::Crypto {
        reason: format!("ssh key parse: {e}"),
    })?;

    // Check the algorithm BEFORE prompting for or consuming a passphrase.
    // The algorithm header is in the unencrypted portion of the OpenSSH
    // format, so we can reject DSA / FIDO keys up front instead of having
    // the user type a passphrase that turns out to be useless.
    match pk.algorithm() {
        Algorithm::Ed25519 | Algorithm::Rsa { .. } | Algorithm::Ecdsa { .. } => {}
        other => {
            return Err(Error::Crypto {
                reason: format!(
                    "unsupported SSH algorithm: {other} — only Ed25519, RSA and ECDSA can be loaded into the agent"
                ),
            });
        }
    }

    if pk.is_encrypted() {
        let pass = passphrase.ok_or(Error::SshPassphraseRequired)?;
        pk = pk
            .decrypt(pass.as_bytes())
            .map_err(|_| Error::SshWrongPassphrase)?;
    }

    let private_pem = pk
        .to_openssh(LineEnding::LF)
        .map_err(|e| Error::Crypto {
            reason: format!("ssh key re-encode: {e}"),
        })?
        .to_string();
    let public_pem = pk.public_key().to_openssh().map_err(|e| Error::Crypto {
        reason: format!("ssh public encode: {e}"),
    })?;
    let fingerprint = pk.fingerprint(HashAlg::Sha256).to_string();

    Ok(DecryptedSshKey {
        private_key: private_pem,
        public_key: public_pem,
        key_fingerprint: fingerprint,
    })
}

/// Generate a fresh Ed25519 SSH keypair, returning the canonical
/// OpenSSH-format private key, the public-key line, and the SHA-256
/// fingerprint. Same shape as `decrypt_ssh_private_key` so the editor
/// can drop the result straight into its sshKey state.
///
/// Ed25519 only for now: it's the modern default (`ssh-keygen` picks
/// it by default since OpenSSH 9.5), 256-bit equivalent security with
/// 32-byte keys, generation is essentially instantaneous. RSA support
/// can ship later as a separate algorithm parameter — until then,
/// users with infra that requires RSA can paste an existing key.
#[tauri::command]
pub fn generate_ssh_key() -> Result<DecryptedSshKey> {
    generate_ed25519_key("")
}

/// The generation behind [`generate_ssh_key`], with the key's comment:
/// the free text that ends an `authorized_keys` line and says, on the
/// server, which key this is. Empty for none. The command line sets one
/// (`clavix item create --type ssh`); the editor does not.
///
/// The comment ends up on a line of a file that grants logins, so a line
/// break in it would start a second entry. Refused here rather than left
/// to each caller.
pub fn generate_ed25519_key(comment: &str) -> Result<DecryptedSshKey> {
    use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};

    if comment.chars().any(char::is_control) {
        return Err(Error::Crypto {
            reason: "an ssh key comment cannot contain control characters".into(),
        });
    }
    let mut rng = rand::thread_rng();
    let mut pk = PrivateKey::random(&mut rng, Algorithm::Ed25519).map_err(|e| Error::Crypto {
        reason: format!("generate ed25519 ssh key: {e}"),
    })?;
    pk.set_comment(comment);

    let private_pem = pk
        .to_openssh(LineEnding::LF)
        .map_err(|e| Error::Crypto {
            reason: format!("encode generated private key: {e}"),
        })?
        .to_string();
    let public_pem = pk.public_key().to_openssh().map_err(|e| Error::Crypto {
        reason: format!("encode generated public key: {e}"),
    })?;
    let fingerprint = pk.fingerprint(HashAlg::Sha256).to_string();

    Ok(DecryptedSshKey {
        private_key: private_pem,
        public_key: public_pem,
        key_fingerprint: fingerprint,
    })
}

#[cfg(test)]
mod generate_comment_tests {
    use super::*;

    #[test]
    fn a_generated_key_carries_its_comment_in_both_halves() {
        let key = generate_ed25519_key("deploy example").unwrap();
        assert!(key.public_key.starts_with("ssh-ed25519 "));
        assert!(key.public_key.ends_with(" deploy example"));
        assert!(key.key_fingerprint.starts_with("SHA256:"));
        // The private half parses back to the same key, comment included:
        // this is what `ssh-keygen -y` would print from it.
        let parsed = ssh_key::PrivateKey::from_openssh(&key.private_key).unwrap();
        assert_eq!(parsed.comment(), "deploy example");
        assert_eq!(parsed.public_key().to_openssh().unwrap(), key.public_key);
        assert!(!parsed.is_encrypted());
    }

    #[test]
    fn without_a_comment_the_public_line_is_bare() {
        let key = generate_ed25519_key("").unwrap();
        assert_eq!(key.public_key.split(' ').count(), 2);
    }

    #[test]
    fn a_comment_cannot_start_a_second_authorized_keys_line() {
        assert!(generate_ed25519_key("ok\nssh-ed25519 AAAA attacker").is_err());
        assert!(generate_ed25519_key("tab\there").is_err());
    }
}

#[cfg(test)]
mod decrypt_tests {
    use super::*;

    #[test]
    fn rejects_non_pem_garbage() {
        let res = decrypt_ssh_private_key("this is definitely not an OpenSSH key".into(), None);
        match res {
            Err(Error::Crypto { reason }) => assert!(reason.starts_with("ssh key parse:")),
            other => panic!("expected Crypto parse error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_input() {
        let res = decrypt_ssh_private_key(String::new(), None);
        assert!(matches!(res, Err(Error::Crypto { .. })));
    }

    #[test]
    fn rejects_truncated_pem_header() {
        // Truncated mid-header — must not panic, must return parse error.
        let res = decrypt_ssh_private_key("-----BEGIN OPENSSH PRIVATE KEY-----\n".into(), None);
        assert!(matches!(res, Err(Error::Crypto { .. })));
    }
}

/// Every SSH-key cipher must leave `classify_ssh_cipher` accounted for —
/// either loadable or explicitly skipped. A silent third outcome is what
/// made the agent report fewer keys than the vault held, with no
/// explanation anywhere.
#[cfg(test)]
mod classify_tests {
    use super::*;
    use clavix_core::crypto::{encrypt_string, SymmetricKey};
    use clavix_core::models::{Cipher, CipherSshKey};

    fn test_key() -> SymmetricKey {
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        SymmetricKey::from_bytes(&bytes).unwrap()
    }

    fn foreign_key() -> SymmetricKey {
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(47);
        }
        SymmetricKey::from_bytes(&bytes).unwrap()
    }

    fn ssh_cipher(key: &SymmetricKey, ssh_key: Option<CipherSshKey>) -> Cipher {
        Cipher {
            id: "ssh-cipher-id".into(),
            kind: CipherType::SshKey,
            key: None,
            name: encrypt_string("my-server-key", key).unwrap(),
            notes: None,
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            revision_date: None,
            deleted_date: None,
            archived_date: None,
            favorite: false,
            login: None,
            card: None,
            identity: None,
            ssh_key,
            fields: None,
            password_history: None,
            reprompt: None,
            attachments: None,
        }
    }

    #[test]
    fn loadable_key_round_trips_name_and_pem() {
        let key = test_key();
        let c = ssh_cipher(
            &key,
            Some(CipherSshKey {
                private_key: Some(encrypt_string("PEM-BODY", &key).unwrap()),
                public_key: None,
                key_fingerprint: None,
            }),
        );
        let (id, name, pem) = classify_ssh_cipher(&c, &key).expect("should load");
        assert_eq!(id, "ssh-cipher-id");
        assert_eq!(name, "my-server-key");
        assert_eq!(pem, "PEM-BODY");
    }

    #[test]
    fn missing_ssh_payload_is_reported_not_dropped() {
        let key = test_key();
        let c = ssh_cipher(&key, None);
        let s = classify_ssh_cipher(&c, &key).expect_err("should be skipped");
        assert_eq!(s.name, "my-server-key");
        assert!(s.reason.contains("no SSH key data"), "{}", s.reason);
    }

    #[test]
    fn public_key_only_item_is_reported_not_dropped() {
        let key = test_key();
        let c = ssh_cipher(
            &key,
            Some(CipherSshKey {
                private_key: None,
                public_key: Some("ssh-ed25519 AAAA…".into()),
                key_fingerprint: None,
            }),
        );
        let s = classify_ssh_cipher(&c, &key).expect_err("should be skipped");
        assert!(s.reason.contains("no private key"), "{}", s.reason);
    }

    #[test]
    fn undecryptable_private_key_is_reported_not_dropped() {
        let key = test_key();
        // Encrypted under a key this vault doesn't hold.
        let c = ssh_cipher(
            &key,
            Some(CipherSshKey {
                private_key: Some(encrypt_string("PEM-BODY", &foreign_key()).unwrap()),
                public_key: None,
                key_fingerprint: None,
            }),
        );
        let s = classify_ssh_cipher(&c, &key).expect_err("should be skipped");
        assert!(s.reason.contains("could not decrypt"), "{}", s.reason);
    }

    /// An unreadable name must still produce a locatable row rather than
    /// an anonymous one — the id is the only handle left.
    #[test]
    fn undecryptable_name_falls_back_to_the_cipher_id() {
        let key = test_key();
        let mut c = ssh_cipher(&key, None);
        c.name = encrypt_string("my-server-key", &foreign_key()).unwrap();
        let s = classify_ssh_cipher(&c, &key).expect_err("should be skipped");
        assert!(s.name.contains("ssh-cipher-id"), "{}", s.name);
    }
}

#[cfg(test)]
mod generate_tests {
    use super::*;

    #[test]
    fn generated_key_round_trips_through_decrypt_command() {
        // Fresh Ed25519 → returned PEM is unencrypted, so feeding it
        // back through decrypt_ssh_private_key (no passphrase) gives
        // a stable result. Catches regressions where the encoder and
        // parser disagree on the wire format.
        let gen = generate_ssh_key().expect("generate ed25519");
        assert!(gen.public_key.starts_with("ssh-ed25519 "));
        assert!(gen.key_fingerprint.starts_with("SHA256:"));
        assert!(gen.private_key.contains("BEGIN OPENSSH PRIVATE KEY"));
        assert!(!gen.private_key.contains("ENCRYPTED"));

        let parsed = decrypt_ssh_private_key(gen.private_key.clone(), None)
            .expect("freshly generated key parses back");
        assert_eq!(parsed.public_key, gen.public_key);
        assert_eq!(parsed.key_fingerprint, gen.key_fingerprint);
    }

    #[test]
    fn two_calls_produce_different_keys() {
        // Sanity check that the RNG is actually being consumed —
        // a wedged generator that returned a constant key would
        // be a serious zero-day (and a hilarious test failure).
        let a = generate_ssh_key().unwrap();
        let b = generate_ssh_key().unwrap();
        assert_ne!(a.key_fingerprint, b.key_fingerprint);
        assert_ne!(a.private_key, b.private_key);
        assert_ne!(a.public_key, b.public_key);
    }

    #[test]
    fn ecdsa_keys_are_accepted_by_the_editor_gate() {
        let pem = include_str!("../../tests/fixtures/ssh/ecdsa-p256");
        let out = decrypt_ssh_private_key(pem.into(), None).unwrap();
        assert!(out.public_key.starts_with("ecdsa-sha2-nistp256 "));
    }

    #[test]
    fn dsa_keys_are_rejected_before_any_passphrase() {
        let pem = include_str!("../../tests/fixtures/ssh/dsa");
        match decrypt_ssh_private_key(pem.into(), None) {
            Err(Error::Crypto { reason }) => {
                assert!(reason.contains("unsupported SSH algorithm"), "{reason}")
            }
            other => panic!("expected an algorithm rejection, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod known_hosts_tests {
    use super::known_host_names;
    use base64::Engine as _;

    fn b64(b: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    #[test]
    fn plain_entries_name_the_host() {
        let key = b"host-key-blob";
        let other = b"another-key";
        let text = format!(
            "# comment\n\
             other.example {t} {o}\n\
             github.com,140.82.121.4 {t} {k} a comment\n\
             [git.example]:2222 {t} {k}\n",
            t = "ssh-ed25519",
            k = b64(key),
            o = b64(other),
        );
        assert_eq!(
            known_host_names(key, &text).as_deref(),
            Some("github.com, 140.82.121.4, [git.example]:2222")
        );
        assert_eq!(
            known_host_names(other, &text).as_deref(),
            Some("other.example")
        );
        assert_eq!(known_host_names(b"absent", &text), None);
    }

    #[test]
    fn hashed_revoked_and_negated_entries_give_no_name() {
        let key = b"host-key-blob";
        let text = format!(
            "|1|c2FsdA==|aGFzaA== ssh-ed25519 {k}\n\
             @revoked evil.example ssh-ed25519 {k}\n\
             !negated.example ssh-ed25519 {k}\n\
             malformed-line-without-key\n",
            k = b64(key)
        );
        assert_eq!(known_host_names(key, &text), None);
    }

    #[test]
    fn markers_are_skipped_before_the_host_field() {
        let key = b"ca-key";
        let text = format!("@cert-authority *.example ssh-ed25519 {}\n", b64(key));
        assert_eq!(known_host_names(key, &text).as_deref(), Some("*.example"));
    }

    #[test]
    fn control_characters_are_stripped() {
        let key = b"k";
        let text = format!("evil\u{1b}[31mhost ssh-ed25519 {}\n", b64(key));
        assert_eq!(
            known_host_names(key, &text).as_deref(),
            Some("evil[31mhost")
        );
    }
}

#[tauri::command]
pub fn ssh_agent_status(state: State<'_, AppState>) -> Result<SshAgentStatus> {
    let slot = state.ssh_agent.lock();
    // Replayed from the last start, never recomputed: this command must not
    // touch the vault. An agent that isn't running has nothing to explain,
    // so the list stays empty there.
    Ok(match slot.as_ref() {
        Some(h) => SshAgentStatus {
            running: true,
            socket_path: Some(h.socket_path.to_string_lossy().into_owned()),
            keys: h
                .keys
                .iter()
                .map(|k| ExposedKey {
                    comment: k.comment.clone(),
                    algorithm: k.algorithm.clone(),
                    fingerprint: k.fingerprint.clone(),
                })
                .collect(),
            skipped: state.ssh_skipped.lock().clone(),
        },
        None => SshAgentStatus {
            running: false,
            socket_path: None,
            keys: Vec::new(),
            skipped: Vec::new(),
        },
    })
}

/// Returns whatever `SSH_AUTH_SOCK` was set to in the process
/// environment when Clavix launched. Used by the agent UI to tell the
/// user whether the variable already points at our socket or whether
/// they still need to export it. Reads only this single variable, no
/// arbitrary env access.
#[tauri::command]
pub fn ssh_auth_sock() -> Option<String> {
    std::env::var("SSH_AUTH_SOCK").ok()
}

#[cfg(test)]
mod teardown_tests {
    use super::*;

    /// `lock` / `logout` / the tray must not leave a confirmation dialog
    /// behind. The agent answers its own parked clients when it stops, but
    /// the prompt on screen is only closed by the oneshot behind it, and
    /// nothing else will: the session it belongs to is gone, so the user
    /// is left with a dialog whose buttons do nothing until it times out
    /// 30 s later. Deliberately asserted with an empty agent slot — the
    /// drain must not be conditional on a handle still being there.
    #[test]
    fn stop_agent_sync_denies_pending_confirmations() {
        let state = AppState::default();
        let (tx, mut rx) = oneshot::channel::<bool>();
        state.ssh_confirms.lock().insert(1, tx);
        state.ssh_skipped.lock().push(SkippedKey {
            name: "some key".into(),
            reason: "unsupported algorithm".into(),
        });

        stop_agent_sync(&state);

        assert!(!rx
            .try_recv()
            .expect("the prompt must be answered, not dropped"));
        assert!(state.ssh_confirms.lock().is_empty());
        assert!(state.ssh_skipped.lock().is_empty());
    }

    #[cfg(unix)]
    fn unlock(state: &AppState) {
        crate::session::store_standalone_session(
            state,
            clavix_core::session::SessionOrigin::ExportFile,
            clavix_core::crypto::SymmetricKey::from_bytes(&[7; 64]).unwrap(),
            None,
            Default::default(),
            None,
        );
    }

    #[cfg(unix)]
    async fn started(socket: &std::path::Path) -> ssh_agent::SshAgentHandle {
        let guard = SignGuard::new(SignPolicy::Never, None);
        ssh_agent::start_agent(socket.to_path_buf(), Vec::new(), guard)
            .await
            .unwrap()
    }

    /// `start_ssh_agent` read its keys, then the vault locked, then its
    /// agent was ready: the agent must not be installed.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_vault_agent_started_across_a_lock_is_not_installed() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("agent.sock");
        let state = AppState::default();
        unlock(&state);
        let handle = started(&socket).await;

        assert!(lock_session_sync(&state));

        let stale = install_vault_agent(&state, handle).expect("handed back, not installed");
        assert!(state.ssh_agent.lock().is_none());
        stale.stop().await;
        assert!(!socket.exists());
    }

    /// The other order: installed just before the lock, so the lock's own
    /// stop takes it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_vault_agent_installed_before_a_lock_is_stopped_by_it() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("agent.sock");
        let state = AppState::default();
        unlock(&state);
        assert!(install_vault_agent(&state, started(&socket).await).is_none());
        assert!(state.ssh_agent.lock().is_some());

        assert!(lock_session_sync(&state));
        assert!(state.ssh_agent.lock().is_none());
        assert!(!socket.exists());
        // Locking twice reports that there was nothing left to lock.
        assert!(!lock_session_sync(&state));
    }

    /// After an auto-lock or a tray lock, the renderer calls `lock` again
    /// once it hears `clavix:session-locked`, possibly long after the
    /// phone's locked-vault agent started. That second lock must leave
    /// the agent and its socket in place: stopping it left Clavix with no
    /// socket at all until the next unlock.
    #[cfg(unix)]
    #[tokio::test]
    async fn locking_a_locked_vault_keeps_the_phone_agent() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("agent.sock");
        let state = AppState::default();
        *state.locked_agent.lock() = Some(started(&socket).await);

        assert!(!lock_session_sync(&state));
        assert!(state.locked_agent.lock().is_some());
        assert!(socket.exists());

        // A logout, though, stops it whatever the vault's state.
        logout_session_sync(&state);
        assert!(state.locked_agent.lock().is_none());
        assert!(!socket.exists());
    }

    /// The interleaving that used to leave an agent over a locked vault:
    /// the lock runs while the start is between "the session is there"
    /// and "the agent is in its slot". The start holds the session lock
    /// across both (as `install_vault_agent` does); the lock must wait
    /// for it before it looks for an agent to stop.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lock_waits_for_an_agent_being_installed_then_stops_it() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("agent.sock");
        let state = Arc::new(AppState::default());
        unlock(&state);
        let handle = started(&socket).await;

        let session = state.session.lock();
        assert!(session.is_some());
        let locking = std::thread::spawn({
            let state = state.clone();
            move || lock_session_sync(&state)
        });
        // Give the lock every chance to run ahead; it cannot pass the
        // session lock held here.
        std::thread::sleep(Duration::from_millis(200));
        *state.ssh_agent.lock() = Some(handle);
        drop(session);

        assert!(locking.join().unwrap());
        assert!(state.session.lock().is_none());
        assert!(
            state.ssh_agent.lock().is_none(),
            "a vault agent is running over a locked vault"
        );
        assert!(!socket.exists());
    }
}
