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
    /// Names the paired devices gave themselves.
    pub devices: Vec<String>,
    /// Relay of the pairing.
    pub relay: Option<String>,
}

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct PhonePairOffer {
    /// The code to type in the phone (`cva1-…`, 15 minutes, works once).
    pub code: String,
    /// `<relay>/#<code>`: opens the relay's page with the code filled in.
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
    use std::sync::Arc;
    use std::time::Duration;

    use parking_lot::Mutex;
    use tokio::sync::Notify;

    use super::*;
    use crate::phone_approval::{NoPhone, PhoneApprover};
    use crate::phone_relay::{ApproveChannel, ApproveOffer, PairedDevice, RelayPhone};
    use clavix_approve_core::relay::{RelayClient, RelayError};
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

    /// The error of a call to the relay at `relay`:
    /// - no answer at all (DNS, connection refused, TLS, timeout): the
    ///   relay is unreachable, named by its address;
    /// - HTTP 401 or 403: the relay refused the credentials;
    /// - anything else: what the relay answered.
    ///
    /// The pairing calls of `clavix-approve-core` return their errors as
    /// text, so the first two are recognised by how the crate words
    /// `RelayError`. The wording is asked from the crate rather than
    /// copied here, so that a crate update cannot silently undo this.
    pub(crate) fn relay_call_error(relay: &str, e: impl std::fmt::Display) -> Error {
        let text = e.to_string();
        let unreachable = RelayError::Transport(String::new()).to_string();
        if let Some(cause) = text.strip_prefix(&unreachable) {
            return Error::RelayUnreachable {
                url: relay.to_string(),
                cause: cause.to_string(),
            };
        }
        let rejected = [401, 403].map(|code| RelayError::Status(code).to_string());
        let kind = if rejected.contains(&text) {
            PhoneErrorKind::Rejected
        } else {
            PhoneErrorKind::Relay
        };
        phone_error(kind, text)
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
                let json = serde_json::to_string(c).map_err(|e| Error::Storage {
                    reason: format!("encode phone pairing: {e}"),
                })?;
                Some(with_user_key(state, |k| encrypt_string(&json, k))?)
            }
            None => None,
        };
        store::save_session(&persisted)
    }

    fn install(state: &AppState, channel: Option<ApproveChannel>) {
        let approver: Arc<dyn PhoneApprover> = match channel.as_ref().map(RelayPhone::new) {
            Some(Ok(phone)) => phone,
            Some(Err(e)) => {
                eprintln!("[clavix phone] stored pairing unusable: {e}");
                Arc::new(NoPhone)
            }
            None => Arc::new(NoPhone),
        };
        *state.phone_approver.lock() = approver;
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
        let channel = decrypted.and_then(|json| serde_json::from_str::<ApproveChannel>(&json).ok());
        if channel.is_none() {
            eprintln!("[clavix phone] stored pairing could not be read; pair again");
        }
        install(state, channel);
    }

    /// Drop the pairing from memory (the vault locked).
    pub fn unload(state: &AppState) {
        if let Some(p) = PAIRING.lock().take() {
            p.cancel.notify_waiters();
        }
        install(state, None);
    }

    pub fn status() -> PhoneStatus {
        let channel = CHANNEL.lock();
        PhoneStatus {
            available: true,
            paired: channel.as_ref().is_some_and(|c| !c.devices.is_empty()),
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
        let relay = match &existing {
            Some(c) => c.relay.clone(),
            None => relay.trim().to_string(),
        };
        relay_client(&relay)?;
        let offer = match &existing {
            // One more phone on the same channel (and relay).
            Some(c) => ApproveOffer::add_device(c).await,
            None => ApproveOffer::open(&relay, enroll_secret.trim(), label.trim()).await,
        }
        .map_err(|e| relay_call_error(&relay, e))?;
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
            old.cancel.notify_waiters();
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
        install(state, Some(channel));
        Ok(status())
    }

    /// Digits differ, or the user gave up. A device that answered is not
    /// kept; on a new channel it stays on the relay unused until it
    /// expires (the relay forgets unpaired channels).
    pub fn pair_cancel() {
        if let Some(p) = PAIRING.lock().take() {
            p.cancel.notify_waiters();
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
        install(state, None);
        Ok(status())
    }

    /// Logout deletes `session.json`, and the pairing with it: tell the
    /// relay, in the background, so the phone stops showing this machine.
    /// Only possible when the vault is unlocked at logout (the pairing is
    /// encrypted with the user key); otherwise it just expires unused.
    pub fn revoke_on_logout() {
        if let Some(p) = PAIRING.lock().take() {
            p.cancel.notify_waiters();
        }
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
        use crate::phone_relay::ApproveOffer;
        use clavix_approve_core::requester as rq;

        const RELAY: &str = "https://relay.example";

        #[test]
        fn a_relay_that_never_answered_is_unreachable_not_an_invalid_response() {
            // Typed, as the revoke calls return it; inside the requester's
            // error; and as the text the pairing calls reduce it to.
            let transport = RelayError::Transport("error sending request".into());
            let as_text = transport.to_string();
            let errors: [Box<dyn std::fmt::Display>; 3] = [
                Box::new(transport.clone()),
                Box::new(rq::Error::from(transport)),
                Box::new(rq::Error::from(as_text)),
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
            use PhoneErrorKind::{Rejected, Relay};
            let answers: [(Box<dyn std::fmt::Display>, PhoneErrorKind); 7] = [
                (Box::new(RelayError::Status(503)), Relay),
                (Box::new(RelayError::Protocol("not JSON".into())), Relay),
                (Box::new(rq::Error::Revoked), Relay),
                (Box::new("nobody entered the pairing code in time"), Relay),
                // A wrong enrolment secret, typed and as the pairing
                // calls word it.
                (Box::new(RelayError::Status(401)), Rejected),
                (Box::new(RelayError::Status(403).to_string()), Rejected),
                (Box::new(RelayError::Status(404)), Relay),
            ];
            for (e, expected) in answers {
                let text = e.to_string();
                match relay_call_error(RELAY, e) {
                    Error::Phone { kind, reason } => {
                        assert_eq!(kind, expected, "{text}");
                        assert_eq!(reason, text);
                    }
                    other => panic!("expected a phone error, got {other:?}"),
                }
            }
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
            let Err(e) = ApproveOffer::open(&relay, "secret", "desk").await else {
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
pub(crate) use imp::{no_pairing, phone_error, qr_svg, relay_call_error, relay_client};

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
