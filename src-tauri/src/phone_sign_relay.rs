//! The phone's own key, through the Clavix Approve relay: the
//! `ssh_agent::PhoneSigner` behind the agent Clavix runs while the vault
//! is locked. Built only with the `phone-approval` feature, on Unix.
//!
//! This is sign mode, the same as the standalone `clavix-agent`: the
//! phone signs with its Secure Enclave key after Face ID, and Clavix holds
//! no private SSH key at all. The crate (`clavix_approve_core::
//! sign_requester`) seals each request for the device holding the key,
//! polls the relay and checks the answer is that device's, for that very
//! request; this adapter translates types, names host keys from
//! `known_hosts` for display, and words the failures for the log.

use std::sync::Arc;
use std::time::Duration;

use clavix_approve_core::bytes::unb64u;
use clavix_approve_core::channel::{Identity, Peer};
use clavix_approve_core::relay::RelayClient;
use clavix_approve_core::sign_requester::{
    self as sr, Caller, SessionBind, SignDevice, SignError, SignRequester,
};
use clavix_approve_core::state::State;

use crate::ssh_agent::{AgentKey, PhoneSignFuture, PhoneSigner, SignRequest};

/// With several phones: one that has not fetched a request after this
/// long is given up on, so that `ssh` moves on to the next phone's key
/// (`clavix-agent run --pickup`, same default).
pub const PICKUP: Duration = Duration::from_secs(20);

pub struct RelayPhoneSigner {
    requester: SignRequester,
}

/// The channel keys recorded at pairing: ours, and each device's.
fn channel_keys(state: &State) -> Result<(Identity, Vec<SignDevice>), String> {
    let field = |text: &str| unb64u(text).ok_or("the saved phone pairing is damaged; pair again");
    let me = Identity::from_secrets(&field(&state.kem_private)?, &field(&state.sig_private)?)?;
    let devices = state
        .signers
        .iter()
        .map(|s| {
            Ok(SignDevice {
                id: s.id.clone(),
                public_key: s.public_key.clone(),
                peer: Peer::new(&field(&s.kem_public)?, &field(&s.sig_public)?)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok((me, devices))
}

impl RelayPhoneSigner {
    /// The signer for a stored sign-mode pairing. Local only: the relay is
    /// first contacted by a sign request.
    pub fn from_state(state: &State) -> Result<Arc<Self>, String> {
        let (me, devices) = channel_keys(state)?;
        let requester = SignRequester::new(
            RelayClient::new(&state.relay)?,
            &state.ch,
            &state.agent_token,
            &state.label,
            me,
            devices,
            sr::DEFAULT_TIMEOUT,
        )
        .map_err(|e| e.to_string())?
        .with_pickup(PICKUP);
        Ok(Arc::new(Self { requester }))
    }

    /// The phones' keys, in the order they are offered to `ssh`.
    pub fn agent_keys(self: &Arc<Self>) -> Result<Vec<AgentKey>, String> {
        self.requester
            .keys()
            .into_iter()
            .map(|k| {
                AgentKey::phone(k.key_blob, k.comment, self.clone() as Arc<dyn PhoneSigner>)
                    .map_err(|e| e.to_string())
            })
            .collect()
    }
}

/// The crate's request for what the agent was asked.
fn to_request(
    req: SignRequest,
    hints: std::collections::BTreeMap<String, String>,
) -> sr::SignRequest {
    let mut out = sr::SignRequest::new(req.key_blob, req.data);
    out.flags = req.flags;
    out.binds = req
        .hops
        .into_iter()
        .map(|h| SessionBind {
            host_key: h.key_blob,
            session_id: h.session_id,
            signature: h.signature,
            forwarded: h.forwarded,
        })
        .collect();
    // A name that could not be read goes out as unknown.
    out.caller = req.caller.map(|c| Caller {
        pid: c.pid,
        name: c.name.unwrap_or_default(),
    });
    out.hints = hints;
    out
}

/// A sign-mode failure as the log shows it, with what to do about it in
/// Clavix.
pub fn describe(e: SignError) -> String {
    match e {
        SignError::Denied => "denied on the phone".into(),
        SignError::Refused(reason) => format!("the phone refused the request ({reason})"),
        SignError::Expired => "no answer from the phone in time".into(),
        SignError::Revoked => "the relay no longer knows this pairing (revoked from the phone?); \
                               pair the phone again in Settings, SSH"
            .into(),
        SignError::UnknownDevice(device) => format!(
            "phone {device} is no longer paired (forgotten on the phone?); \
             forget it in Settings, SSH"
        ),
        SignError::NotPickedUp { device, after } => format!(
            "phone {device} did not pick the request up within {} s; \
             ssh may try the next phone's key",
            after.as_secs()
        ),
        e @ (SignError::BackingOff
        | SignError::Busy
        | SignError::Relay(_)
        | SignError::Invalid(_)) => e.to_string(),
    }
}

impl PhoneSigner for RelayPhoneSigner {
    fn sign(&self, req: SignRequest) -> PhoneSignFuture {
        let hints = crate::commands::ssh::phone_hints(&req.hops);
        let signature = self.requester.sign(&to_request(req, hints));
        Box::pin(async move { signature.await.map_err(describe) })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::ssh_agent::HostHop;
    use clavix_approve_core::bytes::b64u;
    use clavix_approve_core::state::Signer;

    /// An `authorized_keys` line for a real P-256 key, as a phone's.
    fn phone_key_line() -> String {
        let pem = include_str!("../tests/fixtures/ssh/ecdsa-p256");
        let key = ssh_key::PrivateKey::from_openssh(pem).unwrap();
        let line = key.public_key().to_openssh().unwrap();
        let mut fields = line.split_whitespace();
        format!(
            "{} {} iphone",
            fields.next().unwrap(),
            fields.next().unwrap()
        )
    }

    pub(crate) fn sample_state() -> State {
        let me = Identity::generate();
        let phone = Identity::generate();
        let (kem, sig) = me.secrets();
        State {
            relay: "https://relay.invalid".into(),
            ch: "ab".repeat(16),
            agent_token: "token".into(),
            label: "desk".into(),
            kem_private: b64u(&kem),
            sig_private: b64u(&sig),
            signers: vec![Signer {
                id: "cd".repeat(8),
                public_key: phone_key_line(),
                kem_public: b64u(phone.kem_public()),
                sig_public: b64u(&phone.sig_public()),
            }],
        }
    }

    #[test]
    fn a_stored_phone_pairing_gives_the_phones_keys() {
        let signer = RelayPhoneSigner::from_state(&sample_state()).unwrap();
        let keys = signer.agent_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].algorithm, "ecdsa-sha2-nistp256");
        assert_eq!(keys[0].comment, "iphone");
        let expected = ssh_key::PublicKey::from_openssh(&phone_key_line())
            .unwrap()
            .to_bytes()
            .unwrap();
        assert_eq!(keys[0].pub_blob, expected);
    }

    #[test]
    fn a_damaged_phone_pairing_is_an_error() {
        let mut state = sample_state();
        state.kem_private = "not base64url!".into();
        assert!(RelayPhoneSigner::from_state(&state).is_err());
        let mut state = sample_state();
        state.signers.clear();
        assert!(RelayPhoneSigner::from_state(&state).is_err());
    }

    #[test]
    fn phone_requests_map_field_for_field() {
        let req = SignRequest {
            key: crate::ssh_agent::KeyInfo {
                comment: "iphone".into(),
                algorithm: "ecdsa-sha2-nistp256".into(),
                fingerprint: "SHA256:k".into(),
            },
            key_blob: vec![1, 2],
            data: vec![3],
            flags: 4,
            caller: Some(crate::ssh_agent::CallerInfo {
                pid: 42,
                name: None,
            }),
            hops: vec![HostHop {
                key_blob: vec![5],
                fingerprint: "SHA256:h".into(),
                forwarded: true,
                session_id: vec![6],
                signature: vec![7],
            }],
        };
        let hints: std::collections::BTreeMap<_, _> =
            [("SHA256:h".to_string(), "host".to_string())].into();
        let out = to_request(req, hints.clone());
        assert_eq!((out.key, out.data, out.flags), (vec![1, 2], vec![3], 4));
        assert_eq!(
            out.binds,
            vec![SessionBind {
                host_key: vec![5],
                session_id: vec![6],
                signature: vec![7],
                forwarded: true,
            }]
        );
        assert_eq!(
            out.caller,
            Some(Caller {
                pid: 42,
                name: String::new()
            })
        );
        assert_eq!(out.hints, hints);
    }

    #[test]
    fn phone_failures_say_what_to_do() {
        assert_eq!(describe(SignError::Denied), "denied on the phone");
        assert!(describe(SignError::Revoked).contains("pair the phone again"));
        assert!(describe(SignError::UnknownDevice("cdcd".into())).contains("forget it"));
        let late = describe(SignError::NotPickedUp {
            device: "cdcd".into(),
            after: Duration::from_secs(20),
        });
        assert!(late.contains("20 s") && late.contains("next phone"));
        assert!(describe(SignError::Expired).contains("in time"));
    }
}
