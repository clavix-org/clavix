//! The real phone: `PhoneApprover` over the Clavix Approve relay client
//! (`clavix-approve-core`). Built only with the `phone-approval` feature, on Unix.
//!
//! The crate does the protocol work: sealing each request for every paired
//! device, polling the relay, checking the proof under the device's
//! approval key, withdrawing the other devices' copies once one answered.
//! This adapter only translates types and outcomes.

use std::sync::Arc;
use std::time::Duration;

use clavix_approve_core::requester as rq;

use crate::phone_approval::{ApprovalRequest, BoxFuture, PhoneAnswer, PhoneApprover};

pub use rq::{ApproveChannel, ApproveOffer, PairedDevice};

pub struct RelayPhone {
    requester: rq::Requester,
}

impl RelayPhone {
    pub fn new(channel: &ApproveChannel) -> Result<Arc<Self>, rq::Error> {
        Ok(Arc::new(Self {
            requester: rq::Requester::new(channel)?,
        }))
    }
}

fn to_crate(req: ApprovalRequest) -> rq::ApprovalRequest {
    let mut out = rq::ApprovalRequest::new(req.key_blob, req.data);
    out.id = req.id;
    out.ttl = Duration::from_secs(req.ttl_s.into());
    out.agent = Some(req.agent);
    out.key_name = req.key_name;
    out.flags = req.flags;
    out.binds = req
        .binds
        .into_iter()
        .map(|b| rq::SessionBind {
            host_key: b.hostkey,
            session_id: b.sid,
            signature: b.sig,
            forwarded: b.fwd,
        })
        .collect();
    out.caller = req.caller.map(|c| rq::Caller {
        pid: c.pid,
        name: c.name.unwrap_or_default(),
    });
    out.hints = req.hints;
    out
}

/// Only a verified approval becomes `Approved`; anything that is neither
/// an approval nor a refusal leaves the decision to the dialog.
fn to_answer(outcome: Result<rq::Outcome, rq::Error>) -> PhoneAnswer {
    match outcome {
        Ok(rq::Outcome::Approved { .. }) => PhoneAnswer::Approved,
        Ok(rq::Outcome::Denied { reason, .. }) => PhoneAnswer::Denied(reason),
        Ok(rq::Outcome::Expired) => PhoneAnswer::Unavailable("no answer in time".into()),
        Ok(rq::Outcome::Withdrawn) => PhoneAnswer::Unavailable("withdrawn".into()),
        Err(e) => PhoneAnswer::Unavailable(e.to_string()),
    }
}

impl PhoneApprover for RelayPhone {
    fn approve(&self, req: ApprovalRequest) -> BoxFuture<PhoneAnswer> {
        let (_withdraw, outcome) = self.requester.request_approval(&to_crate(req));
        Box::pin(async move {
            let outcome = outcome.await;
            crate::commands::phone::note_request(&outcome);
            let answer = to_answer(outcome);
            if let PhoneAnswer::Unavailable(reason) = &answer {
                eprintln!("[clavix phone] no usable answer from the phone: {reason}");
            }
            answer
        })
    }

    fn withdraw(&self, id: &str) {
        self.requester.withdraw(id);
    }

    fn is_paired(&self) -> bool {
        self.requester.is_paired()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phone_approval::{Bind, Caller};

    #[test]
    fn requests_map_field_for_field() {
        let req = ApprovalRequest {
            id: "ab".repeat(16),
            key_blob: vec![1, 2],
            key_name: "laptop".into(),
            data: vec![3],
            flags: 4,
            binds: vec![Bind {
                hostkey: vec![5],
                sid: vec![6],
                sig: vec![7],
                fwd: true,
            }],
            caller: Some(Caller {
                pid: 42,
                name: None,
            }),
            agent: "desk".into(),
            hints: [("SHA256:x".to_string(), "host".to_string())].into(),
            ttl_s: 90,
        };
        let out = to_crate(req.clone());
        assert_eq!(out.id, req.id);
        assert_eq!(out.ttl, Duration::from_secs(90));
        assert_eq!(out.agent.as_deref(), Some("desk"));
        assert_eq!((out.key, out.data, out.flags), (vec![1, 2], vec![3], 4));
        assert_eq!(out.key_name, "laptop");
        assert_eq!(
            out.binds,
            vec![rq::SessionBind {
                host_key: vec![5],
                session_id: vec![6],
                signature: vec![7],
                forwarded: true,
            }]
        );
        assert_eq!(out.caller.unwrap().pid, 42);
        assert_eq!(out.hints, req.hints);
    }

    #[test]
    fn only_a_verified_approval_approves() {
        let approved = Ok(rq::Outcome::Approved { device: "d".into() });
        assert_eq!(to_answer(approved), PhoneAnswer::Approved);
        let denied = Ok(rq::Outcome::Denied {
            device: "d".into(),
            reason: "user".into(),
        });
        assert_eq!(to_answer(denied), PhoneAnswer::Denied("user".into()));
        for other in [
            Ok(rq::Outcome::Expired),
            Ok(rq::Outcome::Withdrawn),
            Err(rq::Error::Revoked),
            Err(rq::Error::Invalid("bad proof".into())),
        ] {
            assert!(matches!(to_answer(other), PhoneAnswer::Unavailable(_)));
        }
    }
}
