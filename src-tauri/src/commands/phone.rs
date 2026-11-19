//! Pairing a phone that approves SSH-agent signatures, and loading that
//! pairing while the vault is unlocked.
//!
//! The pairing (a Clavix Approve channel: relay, bearer token, channel
//! keys, paired devices) lives in `session.json`, encrypted with the user
//! key, so it is readable only while the vault is unlocked — the only
//! time there are keys to approve anything with. It is per device and
//! never reaches the Vaultwarden server.
//!
//! The commands exist in every build so the front end has one surface;
//! without the `phone-approval` feature they report the feature as
//! unavailable.

use serde::Serialize;
use tauri::State;
use ts_rs::TS;

use crate::state::AppState;
use clavix_core::error::{Error, Result};

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct PhoneStatus {
    /// This build can talk to a relay (`phone-approval` feature).
    pub available: bool,
    /// A pairing is loaded (the vault is unlocked and a phone is paired).
    pub paired: bool,
    /// The loaded pairing predates the current pairing protocol: the
    /// phone no longer honours it, so it is not used. Forget it and pair
    /// again.
    pub outdated: bool,
    /// Names the paired devices gave themselves.
    pub devices: Vec<String>,
    /// Relay of the pairing.
    pub relay: Option<String>,
}

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct PhonePairOffer {
    /// The code to paste in the phone (`cva2-…`, 15 minutes, works once).
    pub code: String,
    /// `clavix-approve://pair?relay=…#<code>`: opens the Clavix Approve
    /// app, which then needs no relay typed in. Never a web page.
    pub link: String,
    /// The link as a QR code, an SVG document.
    pub qr_svg: String,
}

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct PhonePairCandidate {
    /// Six digits the phone shows too; pairing is kept only if they match.
    pub digits: String,
    pub device_name: String,
}

#[cfg_attr(feature = "phone-approval", allow(dead_code))]
fn unavailable() -> Error {
    Error::Storage {
        reason: "this build of Clavix cannot approve on a phone".into(),
    }
}

#[cfg(feature = "phone-approval")]
mod imp {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use parking_lot::Mutex;
    use serde::{Deserialize, Serialize};
    use tokio::sync::Notify;

    use super::*;
    use crate::phone_approval::{NoPhone, PhoneApprover};
    use crate::phone_relay::{ApproveChannel, ApproveOffer, PairedDevice, RelayPhone};
    use clavix_approve_core::pairing::{PairingError, PAIRING_VERSION};
    use clavix_approve_core::relay::{RelayClient, RelayError};
    use clavix_approve_core::requester as rq;
    use clavix_core::crypto::{decrypt_name, encrypt_string};
    use clavix_core::error::PhoneErrorKind;
    use clavix_core::store;

    /// How long `phone_pair_wait` waits: just under the relay's 15 min.
    const PAIR_WAIT: Duration = Duration::from_secs(14 * 60);

    /// A pairing in progress. One at a time.
    struct Pairing {
        offer: Arc<ApproveOffer>,
        /// The relay the offer is open on, to name it when it goes away.
        relay: String,
        /// The channel being extended, for a second phone.
        existing: Option<ApproveChannel>,
        candidate: Option<PairedDevice>,
        cancel: Arc<Notify>,
    }

    static PAIRING: Mutex<Option<Pairing>> = Mutex::new(None);
    /// The loaded channel, kept for status, adding a device and revoking.
    /// Cleared with the approver when the vault locks.
    static CHANNEL: Mutex<Option<ApproveChannel>> = Mutex::new(None);
    /// The loaded channel was paired under an earlier pairing protocol:
    /// kept so it can be shown and forgotten, never asked for approvals.
    static OUTDATED: AtomicBool = AtomicBool::new(false);

    /// The pairing as stored (encrypted) in `session.json`. A pairing
    /// written before the version was recorded is a bare `ApproveChannel`,
    /// and was made with pairing protocol version 1.
    #[derive(Serialize, Deserialize)]
    struct Stored {
        pairing_version: u64,
        channel: ApproveChannel,
    }

    /// The stored pairing and whether it is outdated; `None` when it
    /// cannot be read at all.
    fn read_stored(json: &str) -> Option<(ApproveChannel, bool)> {
        if let Ok(stored) = serde_json::from_str::<Stored>(json) {
            let outdated = stored.pairing_version < PAIRING_VERSION;
            return Some((stored.channel, outdated));
        }
        serde_json::from_str::<ApproveChannel>(json)
            .ok()
            .map(|channel| (channel, true))
    }

    pub(crate) fn phone_error(kind: PhoneErrorKind, reason: impl std::fmt::Display) -> Error {
        Error::Phone {
            kind,
            reason: reason.to_string(),
        }
    }

    /// No pairing in progress (any more): cancelled, expired, replaced.
    pub(crate) fn no_pairing(reason: &str) -> Error {
        phone_error(PhoneErrorKind::NoPairing, reason)
    }

    /// The relay address as `clavix-approve-core` will accept it, or why
    /// not. Checked here, before any call, so that a bad address is
    /// reported as such.
    pub(crate) fn relay_client(relay: &str) -> Result<RelayClient> {
        RelayClient::new(relay).map_err(|e| phone_error(PhoneErrorKind::BadRelayUrl, e))
    }

    /// What a call to the relay failed with, whichever of the crate's
    /// error types reported it.
    pub(crate) enum CallError {
        Relay(RelayError),
        /// The relay no longer knows the pairing.
        Gone,
        /// The pairing code expired unused.
        Expired,
        /// The relay answered something else, or the phone's answer does
        /// not authenticate.
        Other(String),
    }

    impl From<RelayError> for CallError {
        fn from(e: RelayError) -> Self {
            Self::Relay(e)
        }
    }

    impl From<PairingError> for CallError {
        fn from(e: PairingError) -> Self {
            match e {
                PairingError::Relay(e) => Self::Relay(e),
                PairingError::Gone => Self::Gone,
                PairingError::Expired => Self::Expired,
                PairingError::Refused(reason) | PairingError::Invalid(reason) => {
                    Self::Other(reason)
                }
            }
        }
    }

    impl From<rq::Error> for CallError {
        fn from(e: rq::Error) -> Self {
            match e {
                rq::Error::Relay(e) => Self::Relay(e),
                rq::Error::Revoked => Self::Gone,
                // The requester folds a pairing error into text; the one
                // that deserves its own message is recognised by the
                // crate's own wording of it.
                rq::Error::Invalid(reason) if reason == PairingError::Expired.to_string() => {
                    Self::Expired
                }
                rq::Error::Invalid(reason) => Self::Other(reason),
            }
        }
    }

    /// The error of a call to the relay at `relay`:
    /// - no answer at all (DNS, connection refused, TLS, timeout): the
    ///   relay is unreachable, named by its address;
    /// - HTTP 401 or 403: the relay refused the credentials;
    /// - the relay no longer knows the pairing, or the code expired;
    /// - anything else: what the relay answered.
    pub(crate) fn relay_call_error(relay: &str, e: impl Into<CallError>) -> Error {
        match e.into() {
            CallError::Relay(RelayError::Transport(cause)) => Error::RelayUnreachable {
                url: relay.to_string(),
                cause,
            },
            CallError::Relay(e @ RelayError::Status(401 | 403)) => {
                phone_error(PhoneErrorKind::Rejected, e)
            }
            CallError::Relay(e) => phone_error(PhoneErrorKind::Relay, e),
            CallError::Gone => phone_error(PhoneErrorKind::Gone, rq::Error::Revoked),
            CallError::Expired => phone_error(PhoneErrorKind::Expired, PairingError::Expired),
            CallError::Other(reason) => phone_error(PhoneErrorKind::Relay, reason),
        }
    }

    /// As `relay_call_error`, for a channel being created: there is no
    /// pairing the relay could have forgotten, so a 401 (which the
    /// requester reports as a revoked pairing) is the relay refusing the
    /// enrolment secret.
    fn open_error(relay: &str, e: rq::Error) -> Error {
        match e {
            rq::Error::Revoked => phone_error(PhoneErrorKind::Rejected, RelayError::Status(401)),
            e => relay_call_error(relay, e),
        }
    }

    /// The stored pairing is of an earlier pairing protocol.
    pub(crate) fn outdated() -> Error {
        phone_error(
            PhoneErrorKind::Outdated,
            "this pairing predates the current pairing protocol",
        )
    }

    /// Run `f` with the user key, which exists only while unlocked (and
    /// is deliberately not `Clone`).
    fn with_user_key<T>(
        state: &AppState,
        f: impl FnOnce(&clavix_core::crypto::SymmetricKey) -> Result<T>,
    ) -> Result<T> {
        let guard = state.session.lock();
        let session = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        f(&session.user_key)
    }

    fn save_channel(state: &AppState, channel: Option<&ApproveChannel>) -> Result<()> {
        let mut persisted = store::load_session()?.ok_or(Error::NotAuthenticated)?;
        persisted.phone_approval = match channel {
            Some(c) => {
                let stored = Stored {
                    pairing_version: PAIRING_VERSION,
                    channel: c.clone(),
                };
                let json = serde_json::to_string(&stored).map_err(|e| Error::Storage {
                    reason: format!("encode phone pairing: {e}"),
                })?;
                Some(with_user_key(state, |k| encrypt_string(&json, k))?)
            }
            None => None,
        };
        store::save_session(&persisted)
    }

    /// Make `channel` the loaded pairing. An outdated one is kept, to be
    /// shown and forgotten, but nothing is ever asked of its phones.
    fn install(state: &AppState, channel: Option<ApproveChannel>, outdated: bool) {
        let usable = channel.as_ref().filter(|_| !outdated);
        let approver: Arc<dyn PhoneApprover> = match usable.map(RelayPhone::new) {
            Some(Ok(phone)) => phone,
            Some(Err(e)) => {
                eprintln!("[clavix phone] stored pairing unusable: {e}");
                Arc::new(NoPhone)
            }
            None => Arc::new(NoPhone),
        };
        *state.phone_approver.lock() = approver;
        OUTDATED.store(outdated && channel.is_some(), Ordering::SeqCst);
        *CHANNEL.lock() = channel;
    }

    /// Load the stored pairing, if any, now that the vault is unlocked.
    pub fn load(state: &AppState) {
        if CHANNEL.lock().is_some() {
            return;
        }
        let Some(enc) = store::load_session()
            .ok()
            .flatten()
            .and_then(|s| s.phone_approval)
        else {
            return;
        };
        let Ok(decrypted) = with_user_key(state, |k| Ok(decrypt_name(&enc, k).ok())) else {
            return; // locked again meanwhile
        };
        match decrypted.as_deref().and_then(read_stored) {
            Some((channel, outdated)) => {
                if outdated {
                    eprintln!(
                        "[clavix phone] stored pairing predates the current pairing protocol; \
                         forget it and pair again"
                    );
                }
                install(state, Some(channel), outdated);
            }
            None => {
                eprintln!("[clavix phone] stored pairing could not be read; pair again");
                install(state, None, false);
            }
        }
    }

    /// Abandon a pairing in progress. A phone that already answered is
    /// taken off the relay again (best effort, in the background), so
    /// that it does not keep a pairing this computer never accepted: the
    /// whole channel when it was new, that one device otherwise.
    fn discard(pairing: Pairing) {
        pairing.cancel.notify_waiters();
        let Some(candidate) = pairing.candidate else {
            return;
        };
        tauri::async_runtime::spawn(async move {
            let outcome = match pairing.existing {
                Some(mut channel) => channel.forget_device(&candidate.device.id).await,
                None => match Arc::try_unwrap(pairing.offer) {
                    Ok(offer) => offer.into_channel(candidate.device).revoke().await,
                    Err(_) => Err(rq::Error::Invalid("the pairing is still in use".into())),
                },
            };
            if let Err(e) = outcome {
                eprintln!("[clavix phone] could not withdraw the abandoned pairing: {e}");
            }
        });
    }

    /// Drop the pairing from memory (the vault locked).
    pub fn unload(state: &AppState) {
        pair_cancel();
        install(state, None, false);
    }

    pub fn status() -> PhoneStatus {
        let channel = CHANNEL.lock();
        PhoneStatus {
            available: true,
            paired: channel.as_ref().is_some_and(|c| !c.devices.is_empty()),
            outdated: channel.is_some() && OUTDATED.load(Ordering::SeqCst),
            devices: channel
                .as_ref()
                .map(|c| c.devices.iter().map(|d| d.name().to_string()).collect())
                .unwrap_or_default(),
            relay: channel.as_ref().map(|c| c.relay.clone()),
        }
    }

    /// The pairing link as a QR code, an SVG document (no network).
    pub(crate) fn qr_svg(link: &str) -> Result<String> {
        let code = qrcode::QrCode::new(link.as_bytes()).map_err(|e| Error::Storage {
            reason: format!("QR code: {e}"),
        })?;
        Ok(code
            .render::<qrcode::render::svg::Color>()
            .min_dimensions(200, 200)
            .quiet_zone(true)
            .build())
    }

    pub async fn pair_start(
        state: &AppState,
        relay: String,
        enroll_secret: String,
        label: String,
    ) -> Result<PhonePairOffer> {
        with_user_key(state, |_| Ok(()))?; // only while unlocked: stored encrypted
        let existing = CHANNEL.lock().clone();
        if existing.is_some() && OUTDATED.load(Ordering::SeqCst) {
            return Err(outdated());
        }
        let relay = match &existing {
            Some(c) => c.relay.clone(),
            None => relay.trim().to_string(),
        };
        relay_client(&relay)?;
        let offer = match &existing {
            // One more phone on the same channel (and relay).
            Some(c) => ApproveOffer::add_device(c)
                .await
                .map_err(|e| relay_call_error(&relay, e)),
            // The enrolment secret is the relay's own admission secret:
            // empty for a relay with open enrolment.
            None => ApproveOffer::open(&relay, enroll_secret.trim(), label.trim())
                .await
                .map_err(|e| open_error(&relay, e)),
        }?;
        let link = offer.link();
        let out = PhonePairOffer {
            code: offer.code().to_string(),
            qr_svg: qr_svg(&link)?,
            link,
        };
        if let Some(old) = PAIRING.lock().replace(Pairing {
            offer: Arc::new(offer),
            relay,
            existing,
            candidate: None,
            cancel: Arc::new(Notify::new()),
        }) {
            discard(old);
        }
        Ok(out)
    }

    pub async fn pair_wait() -> Result<PhonePairCandidate> {
        let (offer, relay, cancel) = {
            let slot = PAIRING.lock();
            let p = slot
                .as_ref()
                .ok_or_else(|| no_pairing("no pairing in progress"))?;
            (p.offer.clone(), p.relay.clone(), p.cancel.clone())
        };
        let paired = tokio::select! {
            r = offer.wait(PAIR_WAIT) => r.map_err(|e| relay_call_error(&relay, e))?,
            _ = cancel.notified() => return Err(no_pairing("pairing cancelled")),
        };
        let out = PhonePairCandidate {
            digits: paired.digits.clone(),
            device_name: paired.device.name().to_string(),
        };
        // Only for the pairing this wait belongs to: it may have been
        // cancelled, or replaced by a new one, while the phone answered.
        let mut slot = PAIRING.lock();
        match slot.as_mut() {
            Some(p) if Arc::ptr_eq(&p.offer, &offer) => p.candidate = Some(paired),
            _ => return Err(no_pairing("pairing cancelled")),
        }
        drop(slot);
        drop(offer);
        Ok(out)
    }

    /// The user saw the same digits on both screens: keep the device.
    pub fn pair_confirm(state: &AppState) -> Result<PhoneStatus> {
        let pairing = PAIRING
            .lock()
            .take()
            .ok_or_else(|| no_pairing("no pairing in progress"))?;
        let device = pairing
            .candidate
            .ok_or_else(|| no_pairing("no phone answered yet"))?;
        let channel = match pairing.existing {
            // One more phone: added to the channel as it is now, not as
            // it was when the code was shown. If the pairing was
            // forgotten in between, it must not come back.
            Some(snapshot) => {
                let mut current = CHANNEL
                    .lock()
                    .clone()
                    .filter(|c| c.ch == snapshot.ch)
                    .ok_or_else(|| no_pairing("the pairing was forgotten meanwhile"))?;
                current.devices.push(device.device);
                current
            }
            None => Arc::try_unwrap(pairing.offer)
                .map_err(|_| no_pairing("pairing still in use"))?
                .into_channel(device.device),
        };
        save_channel(state, Some(&channel))?;
        install(state, Some(channel), false);
        Ok(status())
    }

    /// Digits differ, or the user gave up. A device that answered is not
    /// kept, here or on the relay (see `discard`).
    pub fn pair_cancel() {
        let pairing = PAIRING.lock().take();
        if let Some(p) = pairing {
            discard(p);
        }
    }

    /// Revoke the pairing on the relay and forget it here. Forgotten
    /// locally even when the relay cannot be reached.
    pub async fn forget(state: &AppState) -> Result<PhoneStatus> {
        // A phone being added to this pairing has nothing left to join.
        pair_cancel();
        let channel = CHANNEL.lock().clone();
        if let Some(c) = &channel {
            if let Err(e) = c.revoke().await {
                eprintln!(
                    "[clavix phone] revoking on the relay failed (forgotten here anyway): {e}"
                );
            }
        }
        save_channel(state, None)?;
        install(state, None, false);
        Ok(status())
    }

    /// Logout deletes `session.json`, and the pairing with it: tell the
    /// relay, in the background, so the phone stops showing this machine.
    /// Only possible when the vault is unlocked at logout (the pairing is
    /// encrypted with the user key); otherwise it just expires unused.
    pub fn revoke_on_logout() {
        pair_cancel();
        let Some(channel) = CHANNEL.lock().clone() else {
            return;
        };
        tauri::async_runtime::spawn(async move {
            if let Err(e) = channel.revoke().await {
                eprintln!("[clavix phone] pairing not revoked on the relay at logout: {e}");
            }
        });
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const RELAY: &str = "https://relay.example";

        #[test]
        fn a_relay_that_never_answered_is_unreachable_not_an_invalid_response() {
            // As the revoke calls, the pairing calls and the requester
            // each report it.
            let transport = RelayError::Transport("error sending request".into());
            let errors: [CallError; 3] = [
                transport.clone().into(),
                PairingError::from(transport.clone()).into(),
                rq::Error::from(transport).into(),
            ];
            for e in errors {
                match relay_call_error(RELAY, e) {
                    Error::RelayUnreachable { url, cause } => {
                        assert_eq!(url, RELAY);
                        assert_eq!(cause, "error sending request");
                    }
                    other => panic!("expected RelayUnreachable, got {other:?}"),
                }
            }
        }

        #[test]
        fn what_the_relay_answered_is_a_phone_error_never_an_invalid_response() {
            use PhoneErrorKind::{Expired, Gone, Rejected, Relay};
            let refused = || PairingError::Refused("the relay did not create the channel".into());
            let answers: [(CallError, PhoneErrorKind); 12] = [
                (RelayError::Status(503).into(), Relay),
                (RelayError::Status(404).into(), Relay),
                (RelayError::Status(429).into(), Relay),
                (RelayError::Protocol("not JSON".into()).into(), Relay),
                (refused().into(), Relay),
                (PairingError::Invalid("bad MAC".into()).into(), Relay),
                (rq::Error::from(refused()).into(), Relay),
                // A wrong enrolment secret.
                (RelayError::Status(401).into(), Rejected),
                (
                    PairingError::Relay(RelayError::Status(403)).into(),
                    Rejected,
                ),
                // The stored pairing is gone from the relay.
                (PairingError::Gone.into(), Gone),
                (rq::Error::Revoked.into(), Gone),
                // Typed by the pairing calls, text through the requester.
                (rq::Error::from(PairingError::Expired).into(), Expired),
            ];
            for (e, expected) in answers {
                match relay_call_error(RELAY, e) {
                    Error::Phone { kind, reason } => {
                        assert_eq!(kind, expected, "{reason}");
                        assert!(!reason.is_empty());
                    }
                    other => panic!("expected a phone error, got {other:?}"),
                }
            }
            assert!(matches!(
                relay_call_error(RELAY, PairingError::Expired),
                Error::Phone { kind: Expired, .. }
            ));
        }

        /// Creating a channel: a 401 is the enrolment secret, not a
        /// pairing the relay forgot.
        #[test]
        fn a_refused_enrolment_secret_is_not_a_forgotten_pairing() {
            assert!(matches!(
                open_error(RELAY, rq::Error::from(RelayError::Status(401))),
                Error::Phone {
                    kind: PhoneErrorKind::Rejected,
                    ..
                }
            ));
            assert!(matches!(
                open_error(RELAY, RelayError::Transport("down".into()).into()),
                Error::RelayUnreachable { .. }
            ));
        }

        fn sample_channel() -> ApproveChannel {
            ApproveChannel {
                relay: RELAY.into(),
                ch: "ab".repeat(16),
                token: "token".into(),
                label: "desk".into(),
                kem_private: "a".into(),
                sig_private: "b".into(),
                devices: Vec::new(),
            }
        }

        /// A pairing stored before the protocol version was recorded was
        /// made with version 1: readable, and outdated.
        #[test]
        fn a_pairing_stored_before_pairing_v2_is_outdated() {
            let channel = sample_channel();
            let bare = serde_json::to_string(&channel).unwrap();
            assert_eq!(read_stored(&bare), Some((channel.clone(), true)));

            let stored = |pairing_version| {
                serde_json::to_string(&Stored {
                    pairing_version,
                    channel: channel.clone(),
                })
                .unwrap()
            };
            assert_eq!(read_stored(&stored(1)), Some((channel.clone(), true)));
            assert_eq!(
                read_stored(&stored(PAIRING_VERSION)),
                Some((channel.clone(), false))
            );
            assert_eq!(read_stored("not json"), None);
            assert_eq!(read_stored("{}"), None);
        }

        /// The QR code opens the app, never a page of the relay.
        #[test]
        fn the_pairing_link_opens_the_app() {
            use clavix_approve_core::pairing::{pairing_url, APP_SCHEME, CODE_PREFIX};
            let link = pairing_url("https://approve.clavix.org", "cva2-abc");
            assert!(link.starts_with(&format!("{APP_SCHEME}://")), "{link}");
            assert!(link.ends_with(&format!("#{CODE_PREFIX}abc")), "{link}");
            assert!(qr_svg(&link).unwrap().contains("<svg"));
        }

        #[test]
        fn a_relay_address_that_cannot_be_used_is_reported_as_such() {
            for bad in ["not a url", "http://relay.example", "ftp://relay.example"] {
                assert!(
                    matches!(
                        relay_client(bad),
                        Err(Error::Phone {
                            kind: PhoneErrorKind::BadRelayUrl,
                            ..
                        })
                    ),
                    "{bad}"
                );
            }
            assert!(relay_client("https://relay.example").is_ok());
            assert!(relay_client("http://127.0.0.1:8080").is_ok());
        }

        /// Nothing listens on the port: the real crate, the real error.
        #[tokio::test]
        async fn pairing_with_a_phone_relay_that_refuses_connections_says_unreachable() {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let relay = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
            drop(listener);
            let Err(e) = ApproveOffer::open(&relay, "", "desk").await else {
                panic!("a closed port cannot have opened a channel");
            };
            assert!(matches!(
                relay_call_error(&relay, e),
                Error::RelayUnreachable { url, .. } if url == relay
            ));
        }
    }
}

#[cfg(feature = "phone-approval")]
pub(crate) use imp::{no_pairing, outdated, phone_error, qr_svg, relay_call_error, relay_client};

/// Logout: revoke the approve-mode pairing on the relay, best effort. A
/// no-op without the feature.
pub(crate) fn revoke_on_logout() {
    #[cfg(feature = "phone-approval")]
    imp::revoke_on_logout();
}

/// Load the stored pairing (vault just unlocked). No-op without the
/// feature.
pub(crate) fn load_paired_phone(_state: &AppState) {
    #[cfg(feature = "phone-approval")]
    imp::load(_state);
}

/// Forget the loaded pairing (vault locked). The stored, encrypted copy
/// stays.
pub(crate) fn unload_paired_phone(state: &AppState) {
    #[cfg(feature = "phone-approval")]
    imp::unload(state);
    #[cfg(not(feature = "phone-approval"))]
    {
        *state.phone_approver.lock() = std::sync::Arc::new(crate::phone_approval::NoPhone);
    }
}

#[tauri::command]
pub fn phone_status() -> PhoneStatus {
    #[cfg(feature = "phone-approval")]
    return imp::status();
    #[cfg(not(feature = "phone-approval"))]
    PhoneStatus {
        available: false,
        paired: false,
        outdated: false,
        devices: Vec::new(),
        relay: None,
    }
}

#[tauri::command]
pub async fn phone_pair_start(
    _state: State<'_, AppState>,
    _relay: String,
    _enroll_secret: String,
    _label: String,
) -> Result<PhonePairOffer> {
    #[cfg(feature = "phone-approval")]
    return imp::pair_start(&_state, _relay, _enroll_secret, _label).await;
    #[cfg(not(feature = "phone-approval"))]
    Err(unavailable())
}

#[tauri::command]
pub async fn phone_pair_wait() -> Result<PhonePairCandidate> {
    #[cfg(feature = "phone-approval")]
    return imp::pair_wait().await;
    #[cfg(not(feature = "phone-approval"))]
    Err(unavailable())
}

#[tauri::command]
pub fn phone_pair_confirm(_state: State<'_, AppState>) -> Result<PhoneStatus> {
    #[cfg(feature = "phone-approval")]
    return imp::pair_confirm(&_state);
    #[cfg(not(feature = "phone-approval"))]
    Err(unavailable())
}

#[tauri::command]
pub fn phone_pair_cancel() {
    #[cfg(feature = "phone-approval")]
    imp::pair_cancel();
}

#[tauri::command]
pub async fn phone_forget(_state: State<'_, AppState>) -> Result<PhoneStatus> {
    #[cfg(feature = "phone-approval")]
    return imp::forget(&_state).await;
    #[cfg(not(feature = "phone-approval"))]
    Err(unavailable())
}
