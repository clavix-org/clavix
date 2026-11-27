//! The app's end of `clavix item …` (see `cli` for the other end and for
//! what the command line may and may not do).
//!
//! A unix socket next to the SSH agent's, private to the user, that takes
//! one JSON request per connection and answers with one JSON line. It only
//! exists while "command-line access" is on in the preferences.
//!
//! Two halves, kept apart so each can be tested without the other: the
//! transport ([`start`], which knows nothing about vaults) and the vault
//! logic ([`resolve_item`], [`apply_changes`], …, which know nothing about
//! sockets). `commands::cli` joins them to the running app.

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;

use clavix_core::crypto::{decrypt_name, SymmetricKey};
use clavix_core::models::{Cipher, CipherCreateInput, Folder, LoginInput};
use clavix_core::services::cipher::{item_key, owning_key};

use crate::cli::{Changes, Envelope, ItemKind, NewItem, Reply, Request, PROTOCOL_VERSION};

/// A request is a handful of short fields and at most one note.
const MAX_REQUEST: u64 = 1024 * 1024;
/// The client writes its request at once; a peer that connects and says
/// nothing is not one of ours.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

pub type Handler =
    Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Reply> + Send>> + Send + Sync>;

pub struct CliServerHandle {
    socket_path: PathBuf,
    /// The accept loop. It owns the connection tasks, so aborting it
    /// aborts every request in flight with it.
    task: JoinHandle<()>,
}

impl CliServerHandle {
    pub fn stop(self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Listen on `socket_path` and hand every well-formed request to `handler`.
/// Must be called from inside the Tokio runtime.
///
/// Same rules as the SSH agent's socket: it is 0600 or it does not serve,
/// and every connection is checked against the socket's owner in case the
/// permissions were changed under us.
pub fn start(socket_path: PathBuf, handler: Handler) -> std::io::Result<CliServerHandle> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // Whatever is there belongs to an instance that is gone: the
    // single-instance guard lets only one Clavix get this far.
    match std::fs::remove_file(&socket_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(&socket_path)?;
    let owner_uid = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        .and_then(|()| std::fs::metadata(&socket_path))
        .map(|m| m.uid())
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&socket_path);
        })?;

    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let accepted = tokio::select! {
                accepted = listener.accept() => accepted,
                Some(_) = connections.join_next() => continue,
            };
            match accepted {
                Ok((stream, _)) => {
                    // Unknown credentials are refused too.
                    let peer_uid = stream.peer_cred().ok().map(|c| c.uid());
                    if peer_uid != Some(owner_uid) {
                        eprintln!(
                            "[clavix cli] connection refused: peer uid {peer_uid:?} is not \
                             the user Clavix runs as"
                        );
                        continue;
                    }
                    let handler = handler.clone();
                    connections.spawn(async move {
                        if let Err(e) = serve(stream, handler).await {
                            eprintln!("[clavix cli] connection error: {e}");
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[clavix cli] accept failed: {e}");
                    break;
                }
            }
        }
    });

    Ok(CliServerHandle { socket_path, task })
}

async fn serve(stream: UnixStream, handler: Handler) -> std::io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut line = Vec::new();
    let read = tokio::time::timeout(
        READ_TIMEOUT,
        BufReader::new(read.take(MAX_REQUEST)).read_until(b'\n', &mut line),
    )
    .await;
    let reply = match read {
        Err(_) => Reply::failed("no request received"),
        Ok(Err(e)) => return Err(e),
        Ok(Ok(_)) => match serde_json::from_slice::<Envelope>(&line) {
            // Checked before the request is looked at: a different version
            // may well fail to parse, and the reason is the version.
            _ if version_of(&line).is_some_and(|v| v != PROTOCOL_VERSION) => Reply::failed(
                "this clavix command and the running Clavix are different versions: \
                 quit and restart Clavix",
            ),
            Ok(envelope) => handler(envelope.request).await,
            // The parse error would quote the request, password included.
            Err(_) => Reply::failed("malformed request"),
        },
    };
    let mut out = serde_json::to_vec(&reply).map_err(std::io::Error::other)?;
    out.push(b'\n');
    write.write_all(&out).await?;
    write.shutdown().await
}

fn version_of(line: &[u8]) -> Option<u32> {
    #[derive(serde::Deserialize)]
    struct Version {
        v: u32,
    }
    serde_json::from_slice::<Version>(line).ok().map(|v| v.v)
}

/// Which items a target may name.
#[derive(Clone, Copy, PartialEq)]
pub enum Scope {
    /// Everything outside the trash, archive included.
    Live,
    Trash,
}

/// The key a cipher's fields are under.
pub fn with_field_key<R>(
    cipher: &Cipher,
    user_key: &SymmetricKey,
    org_keys: &HashMap<String, SymmetricKey>,
    f: impl FnOnce(&SymmetricKey) -> R,
) -> R {
    let owner = owning_key(cipher, user_key, org_keys);
    let item = item_key(cipher, owner);
    f(item.as_ref().unwrap_or(owner))
}

/// Find the one item `target` designates: by id first, then by exact name
/// among the items in `scope`.
///
/// A name that several items share is refused rather than guessed at. The
/// error lists their ids, which is all the command line ever says about
/// items it was not given: enough to pick one, nothing a secret hangs on.
pub fn resolve_item<'a>(
    ciphers: &'a [Cipher],
    user_key: &SymmetricKey,
    org_keys: &HashMap<String, SymmetricKey>,
    target: &str,
    scope: Scope,
) -> Result<&'a Cipher, String> {
    let in_scope = |c: &Cipher| c.deleted_date.is_some() == (scope == Scope::Trash);
    if let Some(cipher) = ciphers.iter().find(|c| c.id == target) {
        return if in_scope(cipher) {
            Ok(cipher)
        } else if scope == Scope::Trash {
            Err("this item is not in the trash".into())
        } else {
            Err("this item is in the trash: restore it first".into())
        };
    }
    let named: Vec<&Cipher> = ciphers
        .iter()
        .filter(|c| in_scope(c))
        .filter(|c| {
            with_field_key(c, user_key, org_keys, |key| {
                decrypt_name(&c.name, key).is_ok_and(|name| name == target)
            })
        })
        .collect();
    match named.as_slice() {
        [] if scope == Scope::Trash => Err(format!("no item \"{target}\" in the trash")),
        [] => Err(format!("no item \"{target}\"")),
        [one] => Ok(one),
        many => Err(format!(
            "{} items are named \"{target}\", use an id instead: {}",
            many.len(),
            many.iter()
                .map(|c| c.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// The id of the folder at `path`, as the sidebar shows it. `None` for an
/// empty path, which means "no folder". Folders are never created here: a
/// typo would otherwise leave a stray folder behind on every device.
pub fn resolve_folder(
    folders: &[Folder],
    user_key: &SymmetricKey,
    path: &str,
) -> Result<Option<String>, String> {
    let path = path.trim().trim_matches('/');
    if path.is_empty() {
        return Ok(None);
    }
    folders
        .iter()
        .find(|f| {
            // A folder created or renamed in this session has its
            // plaintext name stamped back in place of the EncString.
            decrypt_name(&f.name, user_key).map_or(f.name == path, |name| name == path)
        })
        .map(|f| Some(f.id.clone()))
        .ok_or_else(|| format!("no folder \"{path}\": create it in Clavix first"))
}

pub fn new_item_input(
    item: NewItem,
    folder_id: Option<String>,
) -> Result<CipherCreateInput, String> {
    let name = item.name.trim().to_string();
    if name.is_empty() {
        return Err("the name cannot be empty".into());
    }
    let (cipher_type, login) = match item.kind {
        ItemKind::Login => (
            1,
            Some(LoginInput {
                username: item.username,
                password: item.password,
                uris: item.uris,
                totp: None,
            }),
        ),
        ItemKind::Note => {
            if item.username.is_some() || item.password.is_some() || !item.uris.is_empty() {
                return Err("a note has no username, password or URL".into());
            }
            (2, None)
        }
    };
    Ok(CipherCreateInput {
        name,
        folder_id,
        favorite: item.favorite,
        notes: item.notes,
        login,
        card: None,
        identity: None,
        ssh_key: None,
        cipher_type,
        organization_id: None,
        collection_ids: Vec::new(),
        fields: Vec::new(),
        reprompt: false,
    })
}

/// Apply `changes` to an item's current content. `folder_id` is the
/// already-resolved folder: `None` leaves it alone, `Some(None)` takes the
/// item out of its folder.
pub fn apply_changes(
    input: &mut CipherCreateInput,
    changes: Changes,
    folder_id: Option<Option<String>>,
) -> Result<(), String> {
    let clearable = |s: String| (!s.is_empty()).then_some(s);

    if let Some(name) = changes.name {
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err("the name cannot be empty".into());
        }
        input.name = name;
    }
    if changes.username.is_some() || changes.password.is_some() || changes.uris.is_some() {
        if input.cipher_type != 1 {
            return Err("only a login has a username, a password or URLs".into());
        }
        let login = input.login.get_or_insert_with(LoginInput::default);
        if let Some(username) = changes.username {
            login.username = clearable(username);
        }
        if let Some(password) = changes.password {
            login.password = clearable(password);
        }
        if let Some(uris) = changes.uris {
            login.uris = uris;
        }
    }
    if let Some(notes) = changes.notes {
        input.notes = clearable(notes);
    }
    if let Some(folder_id) = folder_id {
        input.folder_id = folder_id;
    }
    if let Some(favorite) = changes.favorite {
        input.favorite = favorite;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clavix_core::crypto::encrypt_string;

    fn cipher(id: &str, name: &str, key: &SymmetricKey, deleted: bool) -> Cipher {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "type": 1,
            "name": encrypt_string(name, key).unwrap(),
            "deletedDate": deleted.then_some("2026-01-01T00:00:00Z"),
            "login": { "username": encrypt_string("me", key).unwrap() },
        }))
        .unwrap()
    }

    fn resolve<'a>(
        ciphers: &'a [Cipher],
        key: &SymmetricKey,
        target: &str,
        scope: Scope,
    ) -> Result<&'a str, String> {
        resolve_item(ciphers, key, &HashMap::new(), target, scope).map(|c| c.id.as_str())
    }

    #[test]
    fn an_item_is_found_by_id_or_by_exact_name() {
        let key = SymmetricKey::generate();
        let ciphers = [
            cipher("id-1", "alpha", &key, false),
            cipher("id-2", "beta", &key, false),
        ];
        assert_eq!(resolve(&ciphers, &key, "id-2", Scope::Live), Ok("id-2"));
        assert_eq!(resolve(&ciphers, &key, "alpha", Scope::Live), Ok("id-1"));
        // Exact: no prefix, no case folding.
        assert!(resolve(&ciphers, &key, "alph", Scope::Live).is_err());
        assert!(resolve(&ciphers, &key, "Alpha", Scope::Live).is_err());
    }

    #[test]
    fn a_shared_name_is_refused_with_the_ids_to_choose_from() {
        let key = SymmetricKey::generate();
        let ciphers = [
            cipher("id-1", "twin", &key, false),
            cipher("id-2", "twin", &key, false),
        ];
        let err = resolve(&ciphers, &key, "twin", Scope::Live).unwrap_err();
        assert!(err.contains("2 items"), "{err}");
        assert!(err.contains("id-1") && err.contains("id-2"), "{err}");
    }

    #[test]
    fn the_trash_and_the_vault_do_not_mix() {
        let key = SymmetricKey::generate();
        let ciphers = [
            cipher("id-1", "kept", &key, false),
            cipher("id-2", "binned", &key, true),
            // Same name on both sides: the scope picks.
            cipher("id-3", "both", &key, false),
            cipher("id-4", "both", &key, true),
        ];
        assert!(resolve(&ciphers, &key, "binned", Scope::Live).is_err());
        assert_eq!(resolve(&ciphers, &key, "binned", Scope::Trash), Ok("id-2"));
        assert!(resolve(&ciphers, &key, "kept", Scope::Trash).is_err());
        assert_eq!(resolve(&ciphers, &key, "both", Scope::Live), Ok("id-3"));
        assert_eq!(resolve(&ciphers, &key, "both", Scope::Trash), Ok("id-4"));
        // By id, the mismatch is said rather than reported as "no item".
        let err = resolve(&ciphers, &key, "id-2", Scope::Live).unwrap_err();
        assert!(err.contains("restore it first"), "{err}");
        let err = resolve(&ciphers, &key, "id-1", Scope::Trash).unwrap_err();
        assert!(err.contains("not in the trash"), "{err}");
    }

    #[test]
    fn a_folder_is_found_encrypted_or_stamped_and_never_invented() {
        let key = SymmetricKey::generate();
        let folders = [
            Folder {
                id: "f-1".into(),
                name: encrypt_string("work/servers", &key).unwrap(),
                revision_date: None,
            },
            Folder {
                id: "f-2".into(),
                name: "stamped".into(),
                revision_date: None,
            },
        ];
        assert_eq!(
            resolve_folder(&folders, &key, "work/servers"),
            Ok(Some("f-1".into()))
        );
        assert_eq!(
            resolve_folder(&folders, &key, "/work/servers/"),
            Ok(Some("f-1".into()))
        );
        assert_eq!(
            resolve_folder(&folders, &key, "stamped"),
            Ok(Some("f-2".into()))
        );
        assert_eq!(resolve_folder(&folders, &key, ""), Ok(None));
        assert!(resolve_folder(&folders, &key, "work").is_err());
    }

    fn login_input() -> CipherCreateInput {
        let mut input = new_item_input(
            NewItem {
                kind: ItemKind::Login,
                name: "example".into(),
                username: Some("me".into()),
                password: Some("old".into()),
                uris: vec!["https://a.example".into()],
                notes: Some("note".into()),
                folder: None,
                favorite: true,
            },
            Some("f-1".into()),
        )
        .unwrap();
        // What an existing item may carry and a change must not lose.
        input.login.as_mut().unwrap().totp = Some("SEED".into());
        input.reprompt = true;
        input
    }

    #[test]
    fn a_change_touches_only_what_it_names() {
        let mut input = login_input();
        apply_changes(
            &mut input,
            Changes {
                password: Some("new".into()),
                ..Changes::default()
            },
            None,
        )
        .unwrap();
        let login = input.login.as_ref().unwrap();
        assert_eq!(login.password.as_deref(), Some("new"));
        assert_eq!(login.username.as_deref(), Some("me"));
        assert_eq!(login.uris, ["https://a.example"]);
        assert_eq!(login.totp.as_deref(), Some("SEED"));
        assert_eq!(input.name, "example");
        assert_eq!(input.notes.as_deref(), Some("note"));
        assert_eq!(input.folder_id.as_deref(), Some("f-1"));
        assert!(input.favorite);
        assert!(input.reprompt);
    }

    #[test]
    fn an_empty_value_clears() {
        let mut input = login_input();
        apply_changes(
            &mut input,
            Changes {
                username: Some(String::new()),
                notes: Some(String::new()),
                uris: Some(Vec::new()),
                favorite: Some(false),
                ..Changes::default()
            },
            Some(None),
        )
        .unwrap();
        let login = input.login.as_ref().unwrap();
        assert!(login.username.is_none());
        assert!(login.uris.is_empty());
        assert_eq!(login.password.as_deref(), Some("old"));
        assert!(input.notes.is_none());
        assert!(input.folder_id.is_none());
        assert!(!input.favorite);
    }

    #[test]
    fn login_fields_are_refused_on_anything_else() {
        let mut note = new_item_input(
            NewItem {
                kind: ItemKind::Note,
                name: "memo".into(),
                username: None,
                password: None,
                uris: Vec::new(),
                notes: Some("text".into()),
                folder: None,
                favorite: false,
            },
            None,
        )
        .unwrap();
        assert_eq!(note.cipher_type, 2);
        assert!(note.login.is_none());
        let err = apply_changes(
            &mut note,
            Changes {
                password: Some("x".into()),
                ..Changes::default()
            },
            None,
        )
        .unwrap_err();
        assert!(err.contains("only a login"), "{err}");
        assert!(note.login.is_none());
        // A rename is fine on any type, an empty name on none.
        apply_changes(
            &mut note,
            Changes {
                name: Some(" renamed ".into()),
                ..Changes::default()
            },
            None,
        )
        .unwrap();
        assert_eq!(note.name, "renamed");
        assert!(apply_changes(
            &mut note,
            Changes {
                name: Some("  ".into()),
                ..Changes::default()
            },
            None,
        )
        .is_err());
    }

    fn echo_handler() -> Handler {
        Arc::new(|request| {
            Box::pin(async move {
                match request {
                    Request::Delete { target } => Reply::done(target),
                    _ => Reply::failed("unexpected request"),
                }
            })
        })
    }

    async fn exchange(socket: &std::path::Path, line: &str) -> Reply {
        let mut stream = UnixStream::connect(socket).await.unwrap();
        stream.write_all(line.as_bytes()).await.unwrap();
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).await.unwrap();
        serde_json::from_slice(&answer).unwrap()
    }

    #[tokio::test]
    async fn the_socket_is_private_and_answers_one_request_per_connection() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("cli.sock");
        // A stale file from a dead instance is replaced.
        std::fs::write(&socket, b"").unwrap();
        let handle = start(socket.clone(), echo_handler()).unwrap();
        let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let reply = exchange(&socket, "{\"v\":1,\"op\":\"delete\",\"target\":\"abc\"}\n").await;
        assert_eq!(reply, Reply::done("abc".into()));

        handle.stop();
        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn bad_requests_get_an_answer_that_quotes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("cli.sock");
        let handle = start(socket.clone(), echo_handler()).unwrap();

        let reply = exchange(
            &socket,
            "{\"v\":1,\"op\":\"edit\",\"password\":\"hunter2\"}\n",
        )
        .await;
        assert_eq!(reply, Reply::failed("malformed request"));

        let reply = exchange(&socket, "{\"v\":2,\"op\":\"future\"}\n").await;
        assert!(reply.error.unwrap().contains("different versions"));

        let reply = exchange(&socket, "not json\n").await;
        assert_eq!(reply, Reply::failed("malformed request"));

        handle.stop();
    }
}
