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
//! without the `phone-approval` feature, and on Windows, they report it
//! unavailable.

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
    /// This build can talk to a relay (`phone-approval` feature, Unix only).
    pub available: bool,
    /// At least one phone is paired in sign mode.
    pub paired: bool,
    /// The pairing predates the current pairing protocol: the phone no
    /// longer honours it, so its keys are not offered. Forget it and pair
    /// again.
    pub outdated: bool,
    /// In the order their keys are offered to `ssh`.
    pub devices: Vec<PhoneSignDevice>,
    pub relay: Option<String>,
    /// This machine's name on the phones.
    pub label: Option<String>,
    /// Serve the phones' keys while the vault is locked.
    pub use_when_locked: bool,
    /// The locked-vault agent is running now.
    pub locked_agent_running: bool,
    /// The relay refused this pairing's last sign request for a reason
    /// the user has to act on.
    pub relay_refusal: Option<super::phone::RelayRefusal>,
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

#[cfg_attr(phone_approval, allow(dead_code))]
fn unavailable() -> Error {
    Error::Storage {
        reason: "this build of Clavix cannot sign with a phone".into(),
    }
}

/// Settings and pairing change only while the vault is unlocked, like
/// every other preference.
#[cfg_attr(not(phone_approval), allow(dead_code))]
fn require_unlocked(state: &AppState) -> Result<()> {
    if state.session.lock().is_some() {
        Ok(())
    } else {
        Err(Error::NotAuthenticated)
    }
}

#[cfg(phone_approval)]
pub(crate) mod imp {
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use parking_lot::Mutex;
    use serde::{Deserialize, Serialize};
    use tokio::sync::Notify;

    use super::super::phone::{no_pairing, outdated, phone_error, relay_call_error, relay_client};
    use super::*;
    use crate::phone_sign_relay::RelayPhoneSigner;
    use crate::ssh_agent::{self, AgentKey, SignGuard, SignPolicy};
    use clavix_approve_core::bytes::b64u;
    use clavix_approve_core::pairing::{
        pairing_url, Offer, Paired, PAIRING_VERSION, PAIRING_WINDOW,
    };
    use clavix_approve_core::relay::{revoke, revoke_device, RelayClient};
    use clavix_approve_core::state::{self as core_state, State as Pairing};
    use clavix_core::error::PhoneErrorKind;

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

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Options {
        #[serde(default)]
        pub use_when_locked: bool,
        /// The pairing protocol version the stored pairing was made with.
        /// Absent from the options written before it was recorded: those
        /// pairings are of version 1.
        #[serde(default = "first_pairing_version")]
        pub pairing_version: u64,
    }

    fn first_pairing_version() -> u64 {
        1
    }

    impl Default for Options {
        fn default() -> Self {
            Self {
                use_when_locked: false,
                pairing_version: first_pairing_version(),
            }
        }
    }

    impl Options {
        /// For a pairing made now.
        pub fn current(use_when_locked: bool) -> Self {
            Self {
                use_when_locked,
                pairing_version: PAIRING_VERSION,
            }
        }

        /// The phone no longer honours a pairing of an earlier protocol.
        pub fn outdated(&self) -> bool {
            self.pairing_version < PAIRING_VERSION
        }
    }

    /// What the relay last refused a sign request of this pairing for.
    static REFUSAL: super::super::phone::RefusalSlot = super::super::phone::RefusalSlot::new();
    static NOTIFIED: crate::relay_notice::Notified = crate::relay_notice::Notified::new();

    /// Record how a sign request went: a refusal by the relay to show in
    /// the settings (`ssh` only says "agent refused operation"), or an
    /// answer from the phone, which clears the last one. Anything else
    /// (unreachable relay, back-off) says nothing either way.
    pub(crate) fn note_request<T>(
        outcome: &std::result::Result<T, clavix_approve_core::sign_requester::SignError>,
    ) {
        if let Some(refusal) = request_verdict(outcome) {
            REFUSAL.set(refusal);
            match refusal {
                Some(refusal) => crate::relay_notice::refused(&NOTIFIED, refusal),
                None => NOTIFIED.reset(),
            }
        }
    }

    /// What `note_request` records: `None` leaves the last refusal as it
    /// is.
    fn request_verdict<T>(
        outcome: &std::result::Result<T, clavix_approve_core::sign_requester::SignError>,
    ) -> Option<Option<super::super::phone::RelayRefusal>> {
        use clavix_approve_core::sign_requester::SignError;
        match outcome {
            // The request reached the phone: the relay served it.
            Ok(_) | Err(SignError::Denied | SignError::Refused(_) | SignError::Expired) => {
                Some(None)
            }
            Err(SignError::Relay(e)) => super::super::phone::refusal_of(e).map(Some),
            Err(_) => None,
        }
    }

    fn storage_error(dir: &Path, e: impl std::fmt::Display) -> Error {
        Error::Storage {
            reason: format!("phone pairing in {}: {e}", dir.display()),
        }
    }

    fn not_paired(reason: impl std::fmt::Display) -> Error {
        phone_error(PhoneErrorKind::NotPaired, reason)
    }

    /// The stored pairing, `None` when there is none (or none that can be
    /// parsed). A pairing file that other users of this machine can read
    /// or write is an error, not an absent pairing: the crate refuses to
    /// load it, and saying "not paired" would invite a new pairing over
    /// secrets that may already be exposed.
    pub fn load_pairing(dir: &Path) -> Result<Option<Pairing>> {
        match core_state::load(dir) {
            Ok(pairing) => Ok(Some(pairing)),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                Err(phone_error(PhoneErrorKind::Exposed, e))
            }
            Err(_) => Ok(None),
        }
    }

    pub fn load_options(dir: &Path) -> Options {
        std::fs::read(dir.join(OPTIONS_FILE))
            .ok()
            .and_then(|raw| serde_json::from_slice(&raw).ok())
            .unwrap_or_default()
    }

    /// Written like the crate writes `state.json`: readable by the user
    /// only, replaced atomically.
    pub fn save_options(dir: &Path, options: Options) -> std::io::Result<()> {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(dir)?;
        let tmp = dir.join(format!("{OPTIONS_FILE}.tmp"));
        let mut open = std::fs::OpenOptions::new();
        open.write(true).create(true).truncate(true);
        std::os::unix::fs::OpenOptionsExt::mode(&mut open, 0o600);
        let mut file = open.open(&tmp)?;
        file.write_all(&serde_json::to_vec(&options).map_err(std::io::Error::other)?)?;
        file.sync_all()?;
        std::fs::rename(tmp, dir.join(OPTIONS_FILE))
    }

    fn save_pairing(dir: &Path, pairing: &Pairing) -> Result<()> {
        // A phone added or forgotten: what the relay refused before
        // shows again at the next request, if it still does.
        REFUSAL.set(None);
        NOTIFIED.reset();
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

    pub fn status(dir: &Path, locked_agent_running: bool) -> Result<PhoneSignStatus> {
        let pairing = load_pairing(dir)?;
        let options = load_options(dir);
        Ok(PhoneSignStatus {
            available: true,
            paired: pairing.is_some(),
            outdated: pairing.is_some() && options.outdated(),
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
            use_when_locked: pairing.is_some() && options.use_when_locked,
            locked_agent_running,
            relay_refusal: pairing.as_ref().and_then(|_| REFUSAL.get()),
        })
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
        let existing = load_pairing(dir)?;
        if existing.is_some() && load_options(dir).outdated() {
            return Err(outdated());
        }
        let (offer, client, relay, label) = match &existing {
            // One more phone on the same channel (`clavix-agent pair --add`).
            Some(p) => {
                let client = relay_client(&p.relay)?;
                let offer = Offer::for_channel(p).map_err(|e| storage_error(dir, e))?;
                offer
                    .open_on_channel(&client, &p.label)
                    .await
                    .map_err(|e| relay_call_error(&p.relay, e))?;
                (offer, client, p.relay.clone(), p.label.clone())
            }
            None => {
                let relay = relay.trim().trim_end_matches('/').to_string();
                let label = label.trim().to_string();
                let client = relay_client(&relay)?;
                let offer = Offer::new();
                // The enrolment secret is the relay's own admission
                // secret: empty for a relay with open enrolment.
                offer
                    .open(&client, enroll_secret.trim(), &label)
                    .await
                    .map_err(|e| relay_call_error(&relay, e))?;
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
            discard(old);
        }
        Ok(out)
    }

    pub async fn pair_wait() -> Result<PhonePairCandidate> {
        let (offer, client, cancel) = {
            let slot = PAIRING.lock();
            let p = slot
                .as_ref()
                .ok_or_else(|| no_pairing("no pairing in progress"))?;
            (p.offer.clone(), p.client.clone(), p.cancel.clone())
        };
        let paired = tokio::select! {
            r = offer.wait_for_signer(&client, PAIRING_WINDOW) => {
                r.map_err(|e| relay_call_error(client.base(), e))?
            }
            _ = cancel.notified() => return Err(no_pairing("pairing cancelled")),
        };
        let out = PhonePairCandidate {
            digits: paired.fingerprint.clone(),
            device_name: key_comment(&paired.signer.public_key),
        };
        let mut slot = PAIRING.lock();
        match slot.as_mut() {
            Some(p) if Arc::ptr_eq(&p.offer, &offer) => p.candidate = Some(paired),
            _ => return Err(no_pairing("pairing cancelled")),
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
            .ok_or_else(|| no_pairing("no pairing in progress"))?;
        let new = pairing
            .candidate
            .ok_or_else(|| no_pairing("no phone answered yet"))?
            .signer;
        let public_key = new.public_key.clone();
        let renewed = match pairing.existing {
            Some(snapshot) => {
                // One more phone: added to the pairing as it is on disk
                // now, not as it was when the code was shown. A phone
                // forgotten in between must not come back with it. If
                // they were all forgotten, the channel is still the one
                // this phone just joined, and it becomes its only device.
                let mut existing = match load_pairing(dir)? {
                    Some(current) if current.ch == snapshot.ch => current,
                    Some(_) => return Err(no_pairing("the pairing was replaced meanwhile")),
                    None => Pairing {
                        signers: Vec::new(),
                        ..snapshot
                    },
                };
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
                save_options(dir, Options::current(true)).map_err(|e| storage_error(dir, e))?;
                false
            }
        };
        Ok(PhoneSignConfirmed {
            status: status(dir, locked_agent_running)?,
            public_key,
            renewed,
        })
    }

    /// Digits differ, or the user gave up. A phone that already answered
    /// is taken off the relay again (best effort), so it does not believe
    /// itself paired.
    pub fn pair_cancel() {
        let pairing = PAIRING.lock().take();
        if let Some(p) = pairing {
            discard(p);
        }
    }

    fn discard(p: InProgress) {
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
        let mut pairing = load_pairing(dir)?.ok_or_else(|| not_paired("no phone is paired"))?;
        let i = pairing
            .signers
            .iter()
            .position(|s| s.id == id)
            .ok_or_else(|| not_paired(format!("no paired phone {id}")))?;
        if !local_only {
            let client = relay_client(&pairing.relay)?;
            revoke_device(&client, &pairing.ch, &pairing.agent_token, id)
                .await
                .map_err(|e| match relay_call_error(&pairing.relay, e) {
                    Error::Phone { kind, reason } => Error::Phone {
                        kind,
                        reason: format!("{reason}; nothing was changed"),
                    },
                    unreachable => unreachable,
                })?;
        }
        pairing.signers.remove(i);
        if pairing.signers.is_empty() {
            remove_all(dir)?;
        } else {
            save_pairing(dir, &pairing)?;
        }
        status(dir, locked_agent_running)
    }

    pub fn set_use_when_locked(
        dir: &Path,
        enabled: bool,
        locked_agent_running: bool,
    ) -> Result<PhoneSignStatus> {
        if load_pairing(dir)?.is_none() {
            return Err(not_paired("no phone is paired"));
        }
        let options = Options {
            use_when_locked: enabled,
            ..load_options(dir)
        };
        save_options(dir, options).map_err(|e| storage_error(dir, e))?;
        status(dir, locked_agent_running)
    }

    // ---- the locked-vault agent ---------------------------------------

    /// The keys the locked-vault agent should offer: the paired phones',
    /// if the user wants them used while locked. `None`: no agent.
    pub fn locked_agent_keys(dir: &Path) -> Option<Vec<AgentKey>> {
        let options = load_options(dir);
        if !options.use_when_locked {
            return None;
        }
        let pairing = match load_pairing(dir) {
            Ok(pairing) => pairing?,
            Err(e) => {
                eprintln!("[clavix agent] phone pairing not used, no agent while locked: {e}");
                return None;
            }
        };
        if options.outdated() {
            eprintln!(
                "[clavix agent] the phone pairing predates the current pairing protocol, no \
                 agent while locked: forget it and pair again in Settings, SSH"
            );
            return None;
        }
        match RelayPhoneSigner::from_state(&pairing).and_then(|s| s.agent_keys()) {
            Ok(keys) if !keys.is_empty() => Some(keys),
            Ok(_) => None,
            Err(e) => {
                eprintln!("[clavix agent] phone pairing unusable, no agent while locked: {e}");
                None
            }
        }
    }

    /// Logout: forget the pairing here, and hand it back so the caller
    /// can revoke it on the relay. A pairing in progress is abandoned.
    /// The files go even when the pairing cannot be read.
    pub fn remove_for_logout(dir: &Path) -> Option<Pairing> {
        pair_cancel();
        // An exposed pairing is removed like any other; without reading
        // it, there is no token to revoke it on the relay with.
        let pairing = load_pairing(dir).unwrap_or_else(|e| {
            eprintln!("[clavix phone] the phone pairing is not revoked on the relay: {e}");
            None
        });
        if let Err(e) = remove_all(dir) {
            eprintln!("[clavix phone] could not remove the phone pairing at logout: {e}");
        }
        pairing
    }

    /// Logout ends sign mode: the pairing is removed from this machine at
    /// once, then revoked on the relay in the background (best effort:
    /// without its token, this machine could not use it anyway).
    pub fn forget_on_logout() {
        let Ok(dir) = sign_dir() else {
            return;
        };
        let Some(pairing) = remove_for_logout(&dir) else {
            return;
        };
        tauri::async_runtime::spawn(async move {
            let outcome = match RelayClient::new(&pairing.relay) {
                Ok(client) => revoke(&client, &pairing.ch, &pairing.agent_token)
                    .await
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e),
            };
            if let Err(e) = outcome {
                eprintln!(
                    "[clavix phone] pairing removed here at logout, but not revoked on the relay: {e}"
                );
            }
        });
    }

    /// Start the locked-vault agent on `socket`, unless the vault is
    /// unlocked, a vault agent is still there, one is already running, or
    /// `keys` has nothing to offer. Idempotent.
    ///
    /// `keys` is asked a second time once the agent is in its slot: what
    /// it reads (the pairing, the switch) can be removed while the agent
    /// starts, by a logout above all, and whoever removed it looked for an
    /// agent to stop before this one was there.
    pub async fn ensure_locked_agent_with(
        state: &AppState,
        socket: PathBuf,
        keys: impl Fn() -> Option<Vec<AgentKey>>,
    ) {
        let _transition = state.agent_transition.lock().await;
        let busy = state.session.lock().is_some()
            || state.ssh_agent.lock().is_some()
            || state.locked_agent.lock().is_some();
        if busy {
            return;
        }
        let Some(offered) = keys() else {
            return;
        };
        let count = offered.len();
        // No local dialog: the vault is locked, there is no window to
        // answer it. The phone is the confirmation, for every signature.
        let guard = SignGuard::new(SignPolicy::Never, None);
        match ssh_agent::start_agent(socket, offered, guard).await {
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
        // still empty), or no longer wanted (logged out, switched off):
        // it must not outlive either.
        if state.session.lock().is_some() || keys().is_none() {
            let handle = state.locked_agent.lock().take();
            if let Some(handle) = handle {
                handle.stop().await;
            }
        }
    }

    /// The locked-vault agent for the pairing stored in `dir`: after a
    /// lock, and at launch (Clavix starts with the vault locked).
    pub async fn ensure_locked_agent_from(state: &AppState, socket: PathBuf, dir: &Path) {
        ensure_locked_agent_with(state, socket, || locked_agent_keys(dir)).await;
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
        ensure_locked_agent_from(&state, socket, &dir).await;
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

        /// `PAIRING` is one per process, and the test threads share it:
        /// a test that fills it or runs a logout (which cancels the pairing
        /// in progress) holds this for its whole length.
        static PAIRING_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
            save_options(&dir, Options::current(true)).unwrap();
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir), 0o700);
            assert_eq!(mode(&dir.join("state.json")), 0o600);
            assert_eq!(mode(&dir.join(OPTIONS_FILE)), 0o600);
            assert!(!dir.join(format!("{OPTIONS_FILE}.tmp")).exists());
            assert_eq!(load_pairing(&dir).unwrap().unwrap().signers.len(), 1);
            assert!(load_options(&dir).use_when_locked);
        }

        /// A pairing file other users can read is not "no pairing": it is
        /// reported, with what to do, and nothing is done with it.
        #[test]
        fn a_pairing_file_open_to_other_users_is_reported_not_used() {
            use std::os::unix::fs::PermissionsExt;
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path();
            save_pairing(dir, &sample_state()).unwrap();
            save_options(dir, Options::current(true)).unwrap();
            let file = dir.join("state.json");
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();

            let exposed = |r: Result<PhoneSignStatus>| match r {
                Err(Error::Phone { kind, reason }) => {
                    assert_eq!(kind, PhoneErrorKind::Exposed);
                    assert!(reason.contains("chmod 600"), "{reason}");
                    assert!(reason.contains("state.json"), "{reason}");
                }
                other => panic!("expected an exposed pairing, got {other:?}"),
            };
            exposed(status(dir, false));
            exposed(set_use_when_locked(dir, false, false));
            assert!(locked_agent_keys(dir).is_none(), "no agent on that file");

            // Fixed by the user: used again.
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(status(dir, false).unwrap().paired);
            assert!(locked_agent_keys(dir).is_some());
        }

        /// `ssh` only says "agent refused operation": the reason the
        /// hosted relay gave is kept for the settings, until a request
        /// reaches the phone again.
        #[test]
        fn a_refused_sign_request_is_kept_for_the_settings() {
            use super::super::super::phone::RelayRefusal::{MachineLimit, SubscriptionRequired};
            use clavix_approve_core::relay::RelayError;
            use clavix_approve_core::sign_requester::SignError;
            let verdict = |e| request_verdict::<()>(&Err(e));
            assert_eq!(
                verdict(SignError::Relay(RelayError::SubscriptionRequired)),
                Some(Some(SubscriptionRequired))
            );
            assert_eq!(
                verdict(SignError::Relay(RelayError::MachineLimit)),
                Some(Some(MachineLimit))
            );
            // Served by the relay, whatever the phone then said.
            assert_eq!(request_verdict(&Ok(())), Some(None));
            assert_eq!(verdict(SignError::Denied), Some(None));
            assert_eq!(verdict(SignError::Expired), Some(None));
            // Proves nothing about the subscription.
            assert_eq!(
                verdict(SignError::Relay(RelayError::Transport("down".into()))),
                None
            );
            assert_eq!(verdict(SignError::BackingOff), None);
            assert_eq!(verdict(SignError::Revoked), None);
        }

        #[test]
        fn phone_sign_status_reflects_what_is_stored() {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path();
            let empty = status(dir, false).unwrap();
            assert!(empty.available && !empty.paired && !empty.use_when_locked);
            assert!(empty.devices.is_empty());

            save_pairing(dir, &sample_state()).unwrap();
            let paired = status(dir, true).unwrap();
            assert!(paired.paired && !paired.use_when_locked && paired.locked_agent_running);
            assert_eq!(paired.devices.len(), 1);
            assert_eq!(paired.devices[0].name, "iphone");
            assert!(paired.devices[0].fingerprint.starts_with("SHA256:"));
            assert_eq!(paired.label.as_deref(), Some("desk"));

            let on = set_use_when_locked(dir, true, false).unwrap();
            assert!(on.use_when_locked);
        }

        /// A pairing whose options do not say which pairing protocol made
        /// it predates version 2: shown, never used, and not extended.
        #[tokio::test]
        async fn a_phone_sign_pairing_from_before_pairing_v2_is_outdated() {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path();
            save_pairing(dir, &sample_state()).unwrap();
            std::fs::write(dir.join(OPTIONS_FILE), br#"{"useWhenLocked":true}"#).unwrap();

            let old = status(dir, false).unwrap();
            assert!(old.paired && old.outdated && old.use_when_locked);
            assert_eq!(old.devices.len(), 1, "still listed, to be forgotten");
            assert!(locked_agent_keys(dir).is_none(), "its keys are not offered");
            assert!(matches!(
                pair_start(dir, String::new(), String::new(), String::new()).await,
                Err(Error::Phone {
                    kind: PhoneErrorKind::Outdated,
                    ..
                })
            ));
            // The switch keeps what is known of the pairing.
            assert!(set_use_when_locked(dir, false, false).unwrap().outdated);
            // No options at all (the pairing alone): version 1 too.
            std::fs::remove_file(dir.join(OPTIONS_FILE)).unwrap();
            assert!(status(dir, false).unwrap().outdated);

            // Forgetting it works without the relay, and clears the flag.
            let id = sample_state().signers[0].id.clone();
            let after = forget(dir, &id, true, false).await.unwrap();
            assert!(!after.paired && !after.outdated);

            // A pairing made now is current.
            save_pairing(dir, &sample_state()).unwrap();
            save_options(dir, Options::current(true)).unwrap();
            assert!(!status(dir, false).unwrap().outdated);
            assert!(locked_agent_keys(dir).is_some());
            assert!(!set_use_when_locked(dir, false, false).unwrap().outdated);
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
            save_options(dir, Options::current(true)).unwrap();
            assert!(forget(dir, "nope", true, false).await.is_err());
            let id = sample_state().signers[0].id.clone();
            let after = forget(dir, &id, true, false).await.unwrap();
            assert!(!after.paired);
            assert!(!dir.join("state.json").exists());
            assert!(!dir.join(OPTIONS_FILE).exists());
        }

        /// "Add a phone" shows its code, a paired phone is forgotten while
        /// it is displayed, then the new phone is confirmed: the forgotten
        /// one must not be written back from the snapshot taken when the
        /// code was shown.
        #[tokio::test]
        async fn a_phone_forgotten_while_adding_another_stays_forgotten() {
            use clavix_approve_core::state::Signer;

            let _pairing = PAIRING_TESTS.lock().await;
            let signer = |id: &str, key: &str| Signer {
                id: id.into(),
                public_key: format!("ecdsa-sha2-nistp256 {key} {id}"),
                ..sample_state().signers[0].clone()
            };
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path();
            let mut paired = sample_state();
            paired.signers = vec![signer("kept", "AAAA"), signer("forgotten", "BBBB")];
            save_pairing(dir, &paired).unwrap();

            // `pair_start`, then the new phone answered.
            *PAIRING.lock() = Some(InProgress {
                offer: Arc::new(Offer::for_channel(&paired).unwrap()),
                client: RelayClient::new(&paired.relay).unwrap(),
                relay: paired.relay.clone(),
                label: paired.label.clone(),
                existing: Some(paired.clone()),
                candidate: Some(Paired {
                    signer: signer("new", "CCCC"),
                    fingerprint: "042 917".into(),
                }),
                cancel: Arc::new(Notify::new()),
            });

            forget(dir, "forgotten", true, false).await.unwrap();
            let done = pair_confirm(dir, false).await.unwrap();

            assert!(!done.renewed);
            let ids: Vec<String> = load_pairing(dir)
                .unwrap()
                .unwrap()
                .signers
                .into_iter()
                .map(|s| s.id)
                .collect();
            assert_eq!(ids, ["kept", "new"]);
        }

        #[test]
        fn phone_keys_are_offered_while_locked_only_when_switched_on() {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path();
            assert!(locked_agent_keys(dir).is_none(), "nothing paired");
            save_pairing(dir, &sample_state()).unwrap();
            assert!(locked_agent_keys(dir).is_none(), "switched off");
            save_options(dir, Options::current(true)).unwrap();
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

        /// What `at_launch` runs: the stored pairing and switch decide.
        #[tokio::test]
        async fn phone_locked_agent_at_launch_follows_the_stored_pairing() {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("phone-sign");
            let socket = tmp.path().join("agent.sock");

            // Not paired: nothing.
            let state = AppState::default();
            ensure_locked_agent_from(&state, socket.clone(), &dir).await;
            assert!(state.locked_agent.lock().is_none());

            // Paired, switch off: nothing.
            save_pairing(&dir, &sample_state()).unwrap();
            ensure_locked_agent_from(&state, socket.clone(), &dir).await;
            assert!(state.locked_agent.lock().is_none());
            assert!(!socket.exists());

            // Paired and on, but a session already unlocked: nothing.
            save_options(&dir, Options::current(true)).unwrap();
            let unlocked = AppState::default();
            unlock(&unlocked);
            ensure_locked_agent_from(&unlocked, socket.clone(), &dir).await;
            assert!(unlocked.locked_agent.lock().is_none());
            assert!(!socket.exists());

            // Paired and on, vault locked: the phone's key is offered.
            ensure_locked_agent_from(&state, socket.clone(), &dir).await;
            assert!(state.locked_agent.lock().is_some());
            assert_eq!(listed(&socket).await, vec!["iphone".to_string()]);

            // And the first unlock stops it.
            unlock(&state);
            assert!(state.locked_agent.lock().is_none());
            assert!(!socket.exists());
        }

        /// Logout ends sign mode on this machine: nothing is left that
        /// could bring the agent back at the next launch.
        #[test]
        fn logout_removes_the_phone_sign_pairing() {
            let _pairing = PAIRING_TESTS.blocking_lock();
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path();
            assert!(remove_for_logout(dir).is_none(), "nothing paired");

            save_pairing(dir, &sample_state()).unwrap();
            save_options(dir, Options::current(true)).unwrap();
            assert!(locked_agent_keys(dir).is_some());

            let pairing = remove_for_logout(dir).expect("handed back, to revoke on the relay");
            assert_eq!(pairing.ch, sample_state().ch);
            assert!(!dir.join("state.json").exists());
            assert!(!dir.join(OPTIONS_FILE).exists());
            assert!(locked_agent_keys(dir).is_none());

            // A pairing that cannot be read is removed all the same.
            std::fs::write(dir.join("state.json"), b"not json").unwrap();
            assert!(remove_for_logout(dir).is_none());
            assert!(!dir.join("state.json").exists());
        }

        /// What `at_launch` finds after a logout: no agent.
        #[tokio::test]
        async fn phone_locked_agent_does_not_come_back_after_logout() {
            let _pairing = PAIRING_TESTS.lock().await;
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("phone-sign");
            let socket = tmp.path().join("agent.sock");
            save_pairing(&dir, &sample_state()).unwrap();
            save_options(&dir, Options::current(true)).unwrap();
            let state = AppState::default();
            ensure_locked_agent_from(&state, socket.clone(), &dir).await;
            assert!(state.locked_agent.lock().is_some());

            // `auth::logout`.
            remove_for_logout(&dir);
            crate::commands::ssh::lock_session_sync(&state);
            assert!(state.locked_agent.lock().is_none());

            // The next launch.
            ensure_locked_agent_from(&AppState::default(), socket.clone(), &dir).await;
            assert!(!socket.exists());
        }

        /// A logout that lands while the agent starts: it removed the
        /// pairing and found no agent to stop yet. The agent must notice
        /// once it is in its slot.
        #[tokio::test]
        async fn phone_locked_agent_started_across_a_logout_stops() {
            let tmp = tempfile::tempdir().unwrap();
            let socket = tmp.path().join("agent.sock");
            let state = AppState::default();
            let asked = std::sync::atomic::AtomicU32::new(0);
            // Paired when the start read it, gone when it looks again.
            let keys = || {
                (asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0)
                    .then(|| vec![phone_key()])
            };
            ensure_locked_agent_with(&state, socket.clone(), keys).await;
            assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 2);
            assert!(state.locked_agent.lock().is_none());
            assert!(!socket.exists());
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

/// Logout: forget the sign-mode pairing (see `imp::forget_on_logout`). A
/// no-op without the feature.
pub(crate) fn forget_on_logout() {
    #[cfg(phone_approval)]
    imp::forget_on_logout();
}

/// The vault was just locked (not logged out): serve the phones' keys in
/// its place, if a phone is paired in sign mode and the user wants it.
/// Runs in the background; a no-op without the feature.
pub(crate) fn after_vault_lock(_app: &AppHandle) {
    #[cfg(phone_approval)]
    tauri::async_runtime::spawn(imp::ensure_locked_agent(_app.clone()));
}

/// Clavix starts with the vault locked: same as after a lock, under the
/// same conditions (a sign-mode pairing, its switch on, no session, no
/// vault agent, one transition at a time). Like `after_vault_lock`, it
/// follows only the phone block's own switch: whether the vault agent
/// starts on unlock is a front-end preference about vault keys, which
/// this agent never holds. Runs in the background; a no-op without the
/// feature.
pub(crate) fn at_launch(app: &AppHandle) {
    after_vault_lock(app);
}

#[cfg_attr(not(phone_approval), allow(dead_code))]
fn running(state: &AppState) -> bool {
    state.locked_agent.lock().is_some()
}

#[tauri::command]
pub fn phone_sign_status(_state: State<'_, AppState>) -> Result<PhoneSignStatus> {
    #[cfg(phone_approval)]
    return imp::status(&imp::sign_dir()?, running(&_state));
    #[cfg(not(phone_approval))]
    Ok(PhoneSignStatus {
        available: false,
        paired: false,
        outdated: false,
        devices: Vec::new(),
        relay: None,
        label: None,
        use_when_locked: false,
        locked_agent_running: false,
        relay_refusal: None,
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
    #[cfg(phone_approval)]
    return imp::pair_start(&imp::sign_dir()?, relay, enroll_secret, label).await;
    #[cfg(not(phone_approval))]
    {
        let _ = (relay, enroll_secret, label);
        Err(unavailable())
    }
}

#[tauri::command]
pub async fn phone_sign_pair_wait() -> Result<PhonePairCandidate> {
    #[cfg(phone_approval)]
    return imp::pair_wait().await;
    #[cfg(not(phone_approval))]
    Err(unavailable())
}

#[tauri::command]
pub async fn phone_sign_pair_confirm(state: State<'_, AppState>) -> Result<PhoneSignConfirmed> {
    require_unlocked(&state)?;
    #[cfg(phone_approval)]
    return imp::pair_confirm(&imp::sign_dir()?, running(&state)).await;
    #[cfg(not(phone_approval))]
    Err(unavailable())
}

#[tauri::command]
pub fn phone_sign_pair_cancel() {
    #[cfg(phone_approval)]
    imp::pair_cancel();
}

#[tauri::command]
pub async fn phone_sign_forget(
    state: State<'_, AppState>,
    id: String,
    local_only: bool,
) -> Result<PhoneSignStatus> {
    require_unlocked(&state)?;
    #[cfg(phone_approval)]
    return imp::forget(&imp::sign_dir()?, &id, local_only, running(&state)).await;
    #[cfg(not(phone_approval))]
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
    #[cfg(phone_approval)]
    return imp::set_use_when_locked(&imp::sign_dir()?, enabled, running(&state));
    #[cfg(not(phone_approval))]
    {
        let _ = enabled;
        Err(unavailable())
    }
}
