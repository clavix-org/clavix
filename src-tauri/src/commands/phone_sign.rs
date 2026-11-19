//! Signing with the phone's own key while the vault is locked.
//!
//! "A locked session holds no keys": when the vault locks, the agent and
//! every vault key leave memory, as they always have. What can take the
//! agent's place is a key-less agent, on the same socket, offering only
//! the keys of phones paired in *sign mode* (Clavix Approve): the phone
//! signs with its own key, after Face ID, exactly like the standalone
//! `clavix-agent`. The phone's public key has to be in the servers'
//! `authorized_keys`, next to the vault keys.
//!
//! The protocol fixes a channel's mode at pairing, so this is a second
//! pairing, separate from the approve-mode one of `commands::phone`.
//!
//! **Stored outside the vault**, since it must work while the vault is
//! locked: the crate's `state.json` (relay, bearer token, this machine's
//! channel keys, the phones' public keys) in `<config dir>/clavix/
//! phone-sign/`, written 0600 in a 0700 directory, as `clavix-agent` does.
//! Those secrets only let a process *ask* a paired phone for a signature:
//! the phone shows the destination, requires biometrics, and signs with a
//! key that never leaves it. They never sign anything themselves.
//!
//! The commands exist in every build so the front end has one surface;
//! without the `phone-approval` feature they report it unavailable.

use serde::Serialize;
use tauri::{AppHandle, State};
use ts_rs::TS;

use crate::state::AppState;
use clavix_core::error::{Error, Result};

use super::phone::{PhonePairCandidate, PhonePairOffer};

/// A phone paired in sign mode.
#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct PhoneSignDevice {
    /// Signer id on the channel (16 hex digits).
    pub id: String,
    /// The name the phone gave its key.
    pub name: String,
    /// Its SSH public key, as an `authorized_keys` line.
    pub public_key: String,
    /// `SHA256:…`, as `ssh-add -l` prints it.
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct PhoneSignStatus {
    /// This build can talk to a relay (`phone-approval` feature).
    pub available: bool,
    /// At least one phone is paired in sign mode.
    pub paired: bool,
    /// In the order their keys are offered to `ssh`.
    pub devices: Vec<PhoneSignDevice>,
    pub relay: Option<String>,
    /// This machine's name on the phones.
    pub label: Option<String>,
    /// Serve the phones' keys while the vault is locked.
    pub use_when_locked: bool,
    /// The locked-vault agent is running now.
    pub locked_agent_running: bool,
}

/// A pairing kept: the new phone's key, to install on servers.
#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct PhoneSignConfirmed {
    pub status: PhoneSignStatus,
    /// The phone's SSH public key, as an `authorized_keys` line.
    pub public_key: String,
    /// The phone was already paired (same key): its entry was renewed and
    /// nothing changes on the servers.
    pub renewed: bool,
}

#[cfg_attr(feature = "phone-approval", allow(dead_code))]
fn unavailable() -> Error {
    Error::Storage {
        reason: "this build of Clavix cannot sign with a phone".into(),
    }
}

/// Settings and pairing change only while the vault is unlocked, like
/// every other preference.
#[cfg_attr(not(feature = "phone-approval"), allow(dead_code))]
fn require_unlocked(state: &AppState) -> Result<()> {
    if state.session.lock().is_some() {
        Ok(())
    } else {
        Err(Error::NotAuthenticated)
    }
}

#[cfg(feature = "phone-approval")]
pub(crate) mod imp {
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use parking_lot::Mutex;
    use serde::{Deserialize, Serialize};
    use tokio::sync::Notify;

    use super::*;
    use crate::phone_sign_relay::RelayPhoneSigner;
    use crate::ssh_agent::{self, AgentKey, SignGuard, SignPolicy};
    use clavix_approve_core::bytes::b64u;
    use clavix_approve_core::pairing::{pairing_url, Offer, Paired, PAIRING_WINDOW};
    use clavix_approve_core::relay::{revoke, revoke_device, RelayClient};
    use clavix_approve_core::state::{self as core_state, State as Pairing};

    const OPTIONS_FILE: &str = "options.json";

    /// `<config dir>/clavix/phone-sign`: outside the vault, next to (not
    /// inside) anything `clavix-agent` keeps, so the two never share a
    /// channel by accident.
    pub fn sign_dir() -> Result<PathBuf> {
        dirs::config_dir()
            .map(|d| d.join("clavix").join("phone-sign"))
            .ok_or_else(|| Error::Storage {
                reason: "could not locate the configuration directory for this platform".into(),
            })
    }

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Options {
        #[serde(default)]
        pub use_when_locked: bool,
    }

    fn storage_error(dir: &Path, e: impl std::fmt::Display) -> Error {
        Error::Storage {
            reason: format!("phone pairing in {}: {e}", dir.display()),
        }
    }

    fn relay_error(e: impl std::fmt::Display) -> Error {
        Error::InvalidResponse {
            reason: format!("phone relay: {e}"),
        }
    }

    pub fn load_pairing(dir: &Path) -> Option<Pairing> {
        core_state::load(dir).ok()
    }

    pub fn load_options(dir: &Path) -> Options {
        std::fs::read(dir.join(OPTIONS_FILE))
            .ok()
            .and_then(|raw| serde_json::from_slice(&raw).ok())
            .unwrap_or_default()
    }

    /// Written like the crate writes `state.json`: readable by the user
    /// only, replaced atomically. (On Windows the file inherits the user
    /// profile's ACLs.)
    pub fn save_options(dir: &Path, options: Options) -> std::io::Result<()> {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(dir)?;
        let tmp = dir.join(format!("{OPTIONS_FILE}.tmp"));
        let mut open = std::fs::OpenOptions::new();
        open.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut open, 0o600);
        let mut file = open.open(&tmp)?;
        file.write_all(&serde_json::to_vec(&options).map_err(std::io::Error::other)?)?;
        file.sync_all()?;
        std::fs::rename(tmp, dir.join(OPTIONS_FILE))
    }

    fn save_pairing(dir: &Path, pairing: &Pairing) -> Result<()> {
        core_state::save(dir, pairing).map_err(|e| storage_error(dir, e))
    }

    /// Forget the pairing and its options.
    fn remove_all(dir: &Path) -> Result<()> {
        core_state::remove(dir).map_err(|e| storage_error(dir, e))?;
        match std::fs::remove_file(dir.join(OPTIONS_FILE)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(storage_error(dir, e)),
            _ => Ok(()),
        }
    }

    fn key_comment(line: &str) -> String {
        line.split_whitespace().nth(2).unwrap_or("").to_string()
    }

    fn key_fingerprint(line: &str) -> String {
        ssh_key::PublicKey::from_openssh(line)
            .map(|k| k.fingerprint(Default::default()).to_string())
            .unwrap_or_else(|_| "unreadable key".into())
    }

    /// Two `authorized_keys` lines for the same key, whatever their comments.
    fn same_key(a: &str, b: &str) -> bool {
        fn key(line: &str) -> Vec<&str> {
            line.split_whitespace().take(2).collect()
        }
        key(a) == key(b)
    }

    pub fn status(dir: &Path, locked_agent_running: bool) -> PhoneSignStatus {
        let pairing = load_pairing(dir);
        PhoneSignStatus {
            available: true,
            paired: pairing.is_some(),
            devices: pairing
                .as_ref()
                .map(|p| {
                    p.signers
                        .iter()
                        .map(|s| PhoneSignDevice {
                            id: s.id.clone(),
                            name: key_comment(&s.public_key),
                            public_key: s.public_key.clone(),
                            fingerprint: key_fingerprint(&s.public_key),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            relay: pairing.as_ref().map(|p| p.relay.clone()),
            label: pairing.as_ref().map(|p| p.label.clone()),
            use_when_locked: pairing.is_some() && load_options(dir).use_when_locked,
            locked_agent_running,
        }
    }

    // ---- pairing -------------------------------------------------------

    /// A pairing in progress. One at a time.
    struct InProgress {
        offer: Arc<Offer>,
        client: RelayClient,
        relay: String,
        label: String,
        /// The pairing being extended with one more phone.
        existing: Option<Pairing>,
        candidate: Option<Paired>,
        cancel: Arc<Notify>,
    }

    static PAIRING: Mutex<Option<InProgress>> = Mutex::new(None);

    pub async fn pair_start(
        dir: &Path,
        relay: String,
        enroll_secret: String,
        label: String,
    ) -> Result<PhonePairOffer> {
        let existing = load_pairing(dir);
        let (offer, client, relay, label) = match &existing {
            // One more phone on the same channel (`clavix-agent pair --add`).
            Some(p) => {
                let client = RelayClient::new(&p.relay).map_err(relay_error)?;
                let offer = Offer::for_channel(p).map_err(relay_error)?;
                offer
                    .open_on_channel(&client, &p.label)
                    .await
                    .map_err(relay_error)?;
                (offer, client, p.relay.clone(), p.label.clone())
            }
            None => {
                let relay = relay.trim().trim_end_matches('/').to_string();
                let label = label.trim().to_string();
                let client = RelayClient::new(&relay).map_err(relay_error)?;
                let offer = Offer::new();
                offer
                    .open(&client, enroll_secret.trim(), &label)
                    .await
                    .map_err(relay_error)?;
                (offer, client, relay, label)
            }
        };
        let link = pairing_url(&relay, &offer.code);
        let out = PhonePairOffer {
            code: offer.code.clone(),
            qr_svg: super::super::phone::qr_svg(&link)?,
            link,
        };
        if let Some(old) = PAIRING.lock().replace(InProgress {
            offer: Arc::new(offer),
            client,
            relay,
            label,
            existing,
            candidate: None,
            cancel: Arc::new(Notify::new()),
        }) {
            old.cancel.notify_waiters();
        }
        Ok(out)
    }

    pub async fn pair_wait() -> Result<PhonePairCandidate> {
        let (offer, client, cancel) = {
            let slot = PAIRING.lock();
            let p = slot
                .as_ref()
                .ok_or_else(|| relay_error("no pairing in progress"))?;
            (p.offer.clone(), p.client.clone(), p.cancel.clone())
        };
        let paired = tokio::select! {
            r = offer.wait_for_signer(&client, PAIRING_WINDOW) => r.map_err(relay_error)?,
            _ = cancel.notified() => return Err(relay_error("pairing cancelled")),
        };
        let out = PhonePairCandidate {
            digits: paired.fingerprint.clone(),
            device_name: key_comment(&paired.signer.public_key),
        };
        let mut slot = PAIRING.lock();
        match slot.as_mut() {
            Some(p) if Arc::ptr_eq(&p.offer, &offer) => p.candidate = Some(paired),
            _ => return Err(relay_error("pairing cancelled")),
        }
        Ok(out)
    }

    /// The user saw the same digits on both screens: keep the phone.
    pub async fn pair_confirm(
        dir: &Path,
        locked_agent_running: bool,
    ) -> Result<PhoneSignConfirmed> {
        let pairing = PAIRING
            .lock()
            .take()
            .ok_or_else(|| relay_error("no pairing in progress"))?;
        let new = pairing
            .candidate
            .ok_or_else(|| relay_error("no phone answered yet"))?
            .signer;
        let public_key = new.public_key.clone();
        let renewed = match pairing.existing {
            Some(mut existing) => {
                // The same phone paired again (same key): it replaces its
                // old entry, which it no longer answers for.
                match existing
                    .signers
                    .iter()
                    .position(|s| same_key(&s.public_key, &new.public_key))
                {
                    Some(i) => {
                        let old = std::mem::replace(&mut existing.signers[i], new);
                        save_pairing(dir, &existing)?;
                        if let Err(e) = revoke_device(
                            &pairing.client,
                            &existing.ch,
                            &existing.agent_token,
                            &old.id,
                        )
                        .await
                        {
                            eprintln!("[clavix phone] could not revoke the replaced entry: {e}");
                        }
                        true
                    }
                    None => {
                        existing.signers.push(new);
                        save_pairing(dir, &existing)?;
                        false
                    }
                }
            }
            None => {
                let (kem_private, sig_private) = pairing.offer.identity.secrets();
                let fresh = Pairing {
                    relay: pairing.relay,
                    ch: pairing.offer.ch.clone(),
                    agent_token: pairing.offer.agent_token.clone(),
                    label: pairing.label,
                    kem_private: b64u(&kem_private),
                    sig_private: b64u(&sig_private),
                    signers: vec![new],
                };
                save_pairing(dir, &fresh)?;
                // Pairing for this purpose is opting in; the switch is
                // there to turn it off.
                save_options(
                    dir,
                    Options {
                        use_when_locked: true,
                    },
                )
                .map_err(|e| storage_error(dir, e))?;
                false
            }
        };
        Ok(PhoneSignConfirmed {
            status: status(dir, locked_agent_running),
            public_key,
            renewed,
        })
    }

    /// Digits differ, or the user gave up. A phone that already answered
    /// is taken off the relay again (best effort), so it does not believe
    /// itself paired.
    pub fn pair_cancel() {
        let Some(p) = PAIRING.lock().take() else {
            return;
        };
        p.cancel.notify_waiters();
        let Some(candidate) = p.candidate else {
            return;
        };
        tauri::async_runtime::spawn(async move {
            let outcome = match &p.existing {
                Some(existing) => {
                    revoke_device(
                        &p.client,
                        &existing.ch,
                        &existing.agent_token,
                        &candidate.signer.id,
                    )
                    .await
                }
                None => revoke(&p.client, &p.offer.ch, &p.offer.agent_token).await,
            };
            if let Err(e) = outcome {
                eprintln!("[clavix phone] could not withdraw the abandoned pairing: {e}");
            }
        });
    }

    /// Revoke one phone on the relay, then forget it here. With
    /// `local_only`, forget it even though the relay cannot be reached.
    pub async fn forget(
        dir: &Path,
        id: &str,
        local_only: bool,
        locked_agent_running: bool,
    ) -> Result<PhoneSignStatus> {
        let mut pairing = load_pairing(dir).ok_or_else(|| relay_error("no phone is paired"))?;
        let i = pairing
            .signers
            .iter()
            .position(|s| s.id == id)
            .ok_or_else(|| relay_error(format!("no paired phone {id}")))?;
        if !local_only {
            let client = RelayClient::new(&pairing.relay).map_err(relay_error)?;
            revoke_device(&client, &pairing.ch, &pairing.agent_token, id)
                .await
                .map_err(|e| relay_error(format!("{e}; nothing was changed")))?;
        }
        pairing.signers.remove(i);
        if pairing.signers.is_empty() {
            remove_all(dir)?;
        } else {
            save_pairing(dir, &pairing)?;
        }
        Ok(status(dir, locked_agent_running))
    }

    pub fn set_use_when_locked(
        dir: &Path,
        enabled: bool,
        locked_agent_running: bool,
    ) -> Result<PhoneSignStatus> {
        if load_pairing(dir).is_none() {
            return Err(relay_error("no phone is paired"));
        }
        save_options(
            dir,
            Options {
                use_when_locked: enabled,
            },
        )
        .map_err(|e| storage_error(dir, e))?;
        Ok(status(dir, locked_agent_running))
    }

    // ---- the locked-vault agent ---------------------------------------

    /// The keys the locked-vault agent should offer: the paired phones',
    /// if the user wants them used while locked. `None`: no agent.
    pub fn locked_agent_keys(dir: &Path) -> Option<Vec<AgentKey>> {
        if !load_options(dir).use_when_locked {
            return None;
        }
        let pairing = load_pairing(dir)?;
        match RelayPhoneSigner::from_state(&pairing).and_then(|s| s.agent_keys()) {
            Ok(keys) if !keys.is_empty() => Some(keys),
            Ok(_) => None,
            Err(e) => {
                eprintln!("[clavix agent] phone pairing unusable, no agent while locked: {e}");
                None
            }
        }
    }

    /// Start the locked-vault agent on `socket`, unless the vault is
    /// unlocked, a vault agent is still there, one is already running, or
    /// `keys` has nothing to offer. Idempotent.
    pub async fn ensure_locked_agent_with(
        state: &AppState,
        socket: PathBuf,
        keys: impl FnOnce() -> Option<Vec<AgentKey>>,
    ) {
        let _transition = state.agent_transition.lock().await;
        let busy = state.session.lock().is_some()
            || state.ssh_agent.lock().is_some()
            || state.locked_agent.lock().is_some();
        if busy {
            return;
        }
        let Some(keys) = keys() else {
            return;
        };
        let count = keys.len();
        // No local dialog: the vault is locked, there is no window to
        // answer it. The phone is the confirmation, for every signature.
        let guard = SignGuard::new(SignPolicy::Never, None);
        match ssh_agent::start_agent(socket, keys, guard).await {
            Ok(handle) => {
                eprintln!(
                    "[clavix agent] vault locked: offering {count} phone key(s) on {}",
                    handle.socket_path.display()
                );
                *state.locked_agent.lock() = Some(handle);
            }
            Err(e) => eprintln!("[clavix agent] could not start the locked-vault agent: {e}"),
        }
        // Unlocked while it was starting (the unlock path found the slot
        // still empty): it must not outlive the lock.
        if state.session.lock().is_some() {
            let handle = state.locked_agent.lock().take();
            if let Some(handle) = handle {
                handle.stop().await;
            }
        }
    }

    pub async fn ensure_locked_agent(app: AppHandle) {
        use tauri::Manager;
        let state = app.state::<AppState>();
        let (socket, dir) = match (ssh_agent::default_socket_path(), sign_dir()) {
            (Ok(socket), Ok(dir)) => (socket, dir),
            (Err(e), _) | (_, Err(e)) => {
                eprintln!("[clavix agent] no locked-vault agent: {e}");
                return;
            }
        };
        ensure_locked_agent_with(&state, socket, || locked_agent_keys(&dir)).await;
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::phone_sign_relay::tests::sample_state;
        use crate::ssh_agent::{PhoneSignFuture, PhoneSigner, SignRequest};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        struct NeverAsked;
        impl PhoneSigner for NeverAsked {
            fn sign(&self, _req: SignRequest) -> PhoneSignFuture {
                Box::pin(async { Err("not in this test".to_string()) })
            }
        }

        fn phone_key() -> AgentKey {
            let blob = ssh_key::PublicKey::from_openssh(&sample_state().signers[0].public_key)
                .unwrap()
                .to_bytes()
                .unwrap();
            AgentKey::phone(blob, "iphone".into(), Arc::new(NeverAsked)).unwrap()
        }

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

        /// Ask the agent on `socket` for its keys; their comments.
        async fn listed(socket: &Path) -> Vec<String> {
            let mut s = tokio::net::UnixStream::connect(socket).await.unwrap();
            s.write_all(&[0, 0, 0, 1, 11]).await.unwrap();
            let len = s.read_u32().await.unwrap() as usize;
            let mut buf = vec![0; len];
            s.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf[0], 12);
            let mut r = &buf[1..];
            let n = u32::from_be_bytes(r[..4].try_into().unwrap());
            r = &r[4..];
            let mut out = Vec::new();
            for _ in 0..n {
                let l = u32::from_be_bytes(r[..4].try_into().unwrap()) as usize;
                r = &r[4 + l..];
                let l = u32::from_be_bytes(r[..4].try_into().unwrap()) as usize;
                out.push(String::from_utf8(r[4..4 + l].to_vec()).unwrap());
                r = &r[4 + l..];
            }
            out
        }

        #[test]
        fn phone_sign_files_are_private() {
            use std::os::unix::fs::PermissionsExt;
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("clavix").join("phone-sign");
            save_pairing(&dir, &sample_state()).unwrap();
            save_options(
                &dir,
                Options {
                    use_when_locked: true,
                },
            )
            .unwrap();
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir), 0o700);
            assert_eq!(mode(&dir.join("state.json")), 0o600);
            assert_eq!(mode(&dir.join(OPTIONS_FILE)), 0o600);
            assert!(!dir.join(format!("{OPTIONS_FILE}.tmp")).exists());
            assert_eq!(load_pairing(&dir).unwrap().signers.len(), 1);
            assert!(load_options(&dir).use_when_locked);
        }

        #[test]
        fn phone_sign_status_reflects_what_is_stored() {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path();
            let empty = status(dir, false);
            assert!(empty.available && !empty.paired && !empty.use_when_locked);
            assert!(empty.devices.is_empty());

            save_pairing(dir, &sample_state()).unwrap();
            let paired = status(dir, true);
            assert!(paired.paired && !paired.use_when_locked && paired.locked_agent_running);
            assert_eq!(paired.devices.len(), 1);
            assert_eq!(paired.devices[0].name, "iphone");
            assert!(paired.devices[0].fingerprint.starts_with("SHA256:"));
            assert_eq!(paired.label.as_deref(), Some("desk"));

            let on = set_use_when_locked(dir, true, false).unwrap();
            assert!(on.use_when_locked);
        }

        #[test]
        fn phone_sign_switch_needs_a_pairing() {
            let tmp = tempfile::tempdir().unwrap();
            assert!(set_use_when_locked(tmp.path(), true, false).is_err());
        }

        #[tokio::test]
        async fn forgetting_the_last_phone_locally_removes_the_files() {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path();
            save_pairing(dir, &sample_state()).unwrap();
            save_options(
                dir,
                Options {
                    use_when_locked: true,
                },
            )
            .unwrap();
            assert!(forget(dir, "nope", true, false).await.is_err());
            let id = sample_state().signers[0].id.clone();
            let after = forget(dir, &id, true, false).await.unwrap();
            assert!(!after.paired);
            assert!(!dir.join("state.json").exists());
            assert!(!dir.join(OPTIONS_FILE).exists());
        }

        #[test]
        fn phone_keys_are_offered_while_locked_only_when_switched_on() {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path();
            assert!(locked_agent_keys(dir).is_none(), "nothing paired");
            save_pairing(dir, &sample_state()).unwrap();
            assert!(locked_agent_keys(dir).is_none(), "switched off");
            save_options(
                dir,
                Options {
                    use_when_locked: true,
                },
            )
            .unwrap();
            let keys = locked_agent_keys(dir).expect("paired and switched on");
            assert_eq!(keys.len(), 1);
            assert_eq!(keys[0].comment, "iphone");
        }

        #[tokio::test]
        async fn phone_locked_agent_runs_only_while_locked() {
            let tmp = tempfile::tempdir().unwrap();
            let socket = tmp.path().join("agent.sock");
            let state = AppState::default();

            // Unlocked: never started, and the keys are not even built.
            unlock(&state);
            ensure_locked_agent_with(&state, socket.clone(), || panic!("must not be asked")).await;
            assert!(state.locked_agent.lock().is_none());

            // Locked: started, serving only the phone's key.
            crate::commands::ssh::stop_agent_sync(&state);
            *state.session.lock() = None;
            ensure_locked_agent_with(&state, socket.clone(), || Some(vec![phone_key()])).await;
            assert!(state.locked_agent.lock().is_some());
            assert_eq!(listed(&socket).await, vec!["iphone".to_string()]);

            // Idempotent: a second lock path does not start another.
            ensure_locked_agent_with(&state, socket.clone(), || panic!("already running")).await;

            // Unlock: stopped at once, the socket freed for the vault agent.
            unlock(&state);
            assert!(state.locked_agent.lock().is_none());
            assert!(!socket.exists());
            let vault = ssh_agent::start_agent(
                socket.clone(),
                Vec::new(),
                SignGuard::new(SignPolicy::Never, None),
            )
            .await
            .unwrap();
            assert!(listed(&socket).await.is_empty());
            vault.stop().await;
        }

        #[tokio::test]
        async fn phone_locked_agent_is_not_started_without_keys_or_over_a_vault_agent() {
            let tmp = tempfile::tempdir().unwrap();
            let socket = tmp.path().join("agent.sock");
            let state = AppState::default();

            // Not paired, or switched off.
            ensure_locked_agent_with(&state, socket.clone(), || None).await;
            assert!(state.locked_agent.lock().is_none());
            assert!(!socket.exists());

            // A vault agent still in its slot: left alone.
            let vault = ssh_agent::start_agent(
                socket.clone(),
                Vec::new(),
                SignGuard::new(SignPolicy::Never, None),
            )
            .await
            .unwrap();
            *state.ssh_agent.lock() = Some(vault);
            ensure_locked_agent_with(&state, socket.clone(), || panic!("must not be asked")).await;
            assert!(state.locked_agent.lock().is_none());
            let vault = state.ssh_agent.lock().take().unwrap();
            vault.stop().await;
        }

        #[tokio::test]
        async fn logout_stops_the_phone_locked_agent() {
            let tmp = tempfile::tempdir().unwrap();
            let socket = tmp.path().join("agent.sock");
            let state = AppState::default();
            ensure_locked_agent_with(&state, socket.clone(), || Some(vec![phone_key()])).await;
            assert!(state.locked_agent.lock().is_some());
            // `auth::logout` (and the lock paths, before restarting it).
            crate::commands::ssh::stop_agent_sync(&state);
            assert!(state.locked_agent.lock().is_none());
            assert!(!socket.exists());
        }
    }
}

/// Stop the locked-vault agent, if running, without waiting: the vault
/// was just unlocked (`session::store_*`), or the user logs out. A vault
/// agent start that follows waits on `agent_transition`.
pub(crate) fn stop_locked_agent_sync(state: &AppState) {
    let handle = state.locked_agent.lock().take();
    if let Some(handle) = handle {
        handle.stop_sync();
        eprintln!("[clavix agent] locked-vault agent stopped");
    }
}

/// Stop the locked-vault agent, if running. The caller holds
/// `agent_transition`.
pub(crate) async fn stop_locked_agent(state: &AppState) {
    let handle = state.locked_agent.lock().take();
    if let Some(handle) = handle {
        handle.stop().await;
    }
}

/// The vault was just locked (not logged out): serve the phones' keys in
/// its place, if a phone is paired in sign mode and the user wants it.
/// Runs in the background; a no-op without the feature.
pub(crate) fn after_vault_lock(_app: &AppHandle) {
    #[cfg(feature = "phone-approval")]
    tauri::async_runtime::spawn(imp::ensure_locked_agent(_app.clone()));
}

#[cfg_attr(not(feature = "phone-approval"), allow(dead_code))]
fn running(state: &AppState) -> bool {
    state.locked_agent.lock().is_some()
}

#[tauri::command]
pub fn phone_sign_status(_state: State<'_, AppState>) -> Result<PhoneSignStatus> {
    #[cfg(feature = "phone-approval")]
    return Ok(imp::status(&imp::sign_dir()?, running(&_state)));
    #[cfg(not(feature = "phone-approval"))]
    Ok(PhoneSignStatus {
        available: false,
        paired: false,
        devices: Vec::new(),
        relay: None,
        label: None,
        use_when_locked: false,
        locked_agent_running: false,
    })
}

#[tauri::command]
pub async fn phone_sign_pair_start(
    state: State<'_, AppState>,
    relay: String,
    enroll_secret: String,
    label: String,
) -> Result<PhonePairOffer> {
    require_unlocked(&state)?;
    #[cfg(feature = "phone-approval")]
    return imp::pair_start(&imp::sign_dir()?, relay, enroll_secret, label).await;
    #[cfg(not(feature = "phone-approval"))]
    {
        let _ = (relay, enroll_secret, label);
        Err(unavailable())
    }
}

#[tauri::command]
pub async fn phone_sign_pair_wait() -> Result<PhonePairCandidate> {
    #[cfg(feature = "phone-approval")]
    return imp::pair_wait().await;
    #[cfg(not(feature = "phone-approval"))]
    Err(unavailable())
}

#[tauri::command]
pub async fn phone_sign_pair_confirm(state: State<'_, AppState>) -> Result<PhoneSignConfirmed> {
    require_unlocked(&state)?;
    #[cfg(feature = "phone-approval")]
    return imp::pair_confirm(&imp::sign_dir()?, running(&state)).await;
    #[cfg(not(feature = "phone-approval"))]
    Err(unavailable())
}

#[tauri::command]
pub fn phone_sign_pair_cancel() {
    #[cfg(feature = "phone-approval")]
    imp::pair_cancel();
}

#[tauri::command]
pub async fn phone_sign_forget(
    state: State<'_, AppState>,
    id: String,
    local_only: bool,
) -> Result<PhoneSignStatus> {
    require_unlocked(&state)?;
    #[cfg(feature = "phone-approval")]
    return imp::forget(&imp::sign_dir()?, &id, local_only, running(&state)).await;
    #[cfg(not(feature = "phone-approval"))]
    {
        let _ = (id, local_only);
        Err(unavailable())
    }
}

#[tauri::command]
pub fn phone_sign_set_use_when_locked(
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<PhoneSignStatus> {
    require_unlocked(&state)?;
    #[cfg(feature = "phone-approval")]
    return imp::set_use_when_locked(&imp::sign_dir()?, enabled, running(&state));
    #[cfg(not(feature = "phone-approval"))]
    {
        let _ = enabled;
        Err(unavailable())
    }
}
