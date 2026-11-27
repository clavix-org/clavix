//! `clavix item …`: change vault items from a terminal.
//!
//! The command line holds no key and never logs in. It is a client of the
//! Clavix that is already running and unlocked: it sends one request over a
//! unix socket (`cli_server`) and prints the answer. The session, the
//! auto-lock and the server connection all stay where they are, in the app.
//!
//! Write-only on purpose. Nothing here can read a secret back out of the
//! vault: there is no "get", and the replies carry an item id or an error,
//! never item content. A process that can reach the socket can add, change,
//! archive and trash items; it cannot learn a password.
//!
//! Off until the user turns it on in the preferences, and Unix only for
//! now: the Windows release binary is a GUI-subsystem program with no
//! console to print to.

use serde::{Deserialize, Serialize};

/// Bumped when a request or reply changes shape. The client and the app
/// are the same binary, but an update can leave an old one in the tray.
pub const PROTOCOL_VERSION: u32 = 1;

/// File name of the socket, next to the SSH agent's.
#[cfg(unix)]
const SOCKET_FILE: &str = "cli.sock";

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ItemKind {
    Login,
    Note,
}

// No `Debug` on the types below: they carry a password, and a derived
// `Debug` is one stray `{:?}` away from a log line.

/// A new item. Empty strings never reach the wire: the parser turns them
/// into `None`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewItem {
    pub kind: ItemKind,
    pub name: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub uris: Vec<String>,
    #[serde(default)]
    pub notes: Option<String>,
    /// Folder path as the sidebar shows it (`work/servers`).
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub favorite: bool,
}

/// What to change on an existing item. `None` leaves a field alone; an
/// empty string (or an empty list) clears it.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Changes {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub uris: Option<Vec<String>>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub favorite: Option<bool>,
}

impl Changes {
    fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.username.is_none()
            && self.password.is_none()
            && self.uris.is_none()
            && self.notes.is_none()
            && self.folder.is_none()
            && self.favorite.is_none()
    }
}

/// `target` is an item id, or the exact name of exactly one item.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase")]
pub enum Request {
    Create {
        item: NewItem,
    },
    Edit {
        target: String,
        changes: Changes,
    },
    Archive {
        target: String,
    },
    Unarchive {
        target: String,
    },
    /// To the trash. There is no permanent delete from the command line.
    Delete {
        target: String,
    },
    Restore {
        target: String,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u32,
    #[serde(flatten)]
    pub request: Request,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reply {
    pub ok: bool,
    /// The item the request created or acted on.
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

impl Reply {
    pub fn done(id: String) -> Self {
        Self {
            ok: true,
            id: Some(id),
            error: None,
        }
    }

    pub fn failed(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            id: None,
            error: Some(error.into()),
        }
    }
}

/// Where the app listens. `None` when the platform offers no directory
/// for it.
///
/// Under Flatpak each `flatpak run` gets its own `$XDG_RUNTIME_DIR`; only
/// `app/<app id>` under it is shared between the running app and a second
/// launch, so that is where the socket has to be.
#[cfg(unix)]
pub fn socket_path() -> Option<std::path::PathBuf> {
    #[cfg(target_os = "linux")]
    if let Some(dir) = crate::flatpak_instance::runtime_dir() {
        return Some(dir.join(SOCKET_FILE));
    }
    let dir = dirs::runtime_dir().or_else(dirs::cache_dir)?;
    Some(dir.join("clavix").join(SOCKET_FILE))
}

pub const USAGE: &str = "\
Usage: clavix item <command> [options]

Changes items of the vault that is open in the running Clavix. Clavix must
be running and unlocked, with \"Command-line access\" turned on in
Preferences > Security.

Commands:
  create              Create an item; prints its id
  edit <item>         Change fields of an item
  archive <item>      Move an item to the archive
  unarchive <item>    Take an item out of the archive
  delete <item>       Move an item to the trash
  restore <item>      Take an item out of the trash

<item> is an item id, or the exact name of exactly one item.

Options for create and edit:
  --name <name>       Item name (required for create)
  --username <text>
  --password-stdin    Read the password from standard input
  --uri <url>         May be given several times; on edit, replaces all URLs
  --notes <text>
  --folder <path>     An existing folder, as shown in the sidebar
  --favorite

Options for create only:
  --type <login|note> Defaults to login

Options for edit only:
  --no-favorite
  --no-folder         Take the item out of its folder
  --no-uri            Remove every URL
  An empty value clears a field: --username \"\"

There is no option that takes the password itself: a command line is
visible to other processes and kept in the shell history.

Examples:
  pwgen -s 24 1 | clavix item create --name example.org \\
      --username me --uri https://example.org --password-stdin
  clavix item edit example.org --folder work --favorite
  clavix item delete example.org
";

pub enum Parsed {
    Help,
    Run {
        request: Request,
        /// Fill the request's password from standard input before sending.
        password_stdin: bool,
    },
}

/// Hands out the value of `--opt value` and `--opt=value` alike.
struct Args<'a> {
    rest: std::slice::Iter<'a, String>,
}

impl<'a> Args<'a> {
    /// The next argument, split into its name and an inline `=value`.
    fn next(&mut self) -> Option<(&'a str, Option<&'a str>)> {
        let arg = self.rest.next()?;
        if arg.starts_with("--") {
            if let Some((name, value)) = arg.split_once('=') {
                return Some((name, Some(value)));
            }
        }
        Some((arg, None))
    }

    fn value(&mut self, name: &str, inline: Option<&'a str>) -> Result<String, String> {
        match inline {
            Some(v) => Ok(v.to_string()),
            None => self
                .rest
                .next()
                .cloned()
                .ok_or_else(|| format!("{name} needs a value")),
        }
    }
}

fn no_value(name: &str, inline: Option<&str>) -> Result<(), String> {
    match inline {
        Some(_) => Err(format!("{name} takes no value")),
        None => Ok(()),
    }
}

/// `None` for an empty string: on create, an empty field is an absent one.
fn non_empty(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

/// Parse what follows `clavix item`.
pub fn parse(args: &[String]) -> Result<Parsed, String> {
    let Some(command) = args.first() else {
        return Ok(Parsed::Help);
    };
    let mut rest = Args {
        rest: args[1..].iter(),
    };
    match command.as_str() {
        "help" | "--help" | "-h" => Ok(Parsed::Help),
        "create" => parse_create(rest),
        "edit" => parse_edit(rest),
        "archive" | "unarchive" | "delete" | "restore" => {
            let mut target = None;
            while let Some((arg, _)) = rest.next() {
                match arg {
                    "--help" | "-h" => return Ok(Parsed::Help),
                    a if a.starts_with('-') => return Err(format!("unknown option {a}")),
                    a => set_target(&mut target, a)?,
                }
            }
            let target = target.ok_or_else(|| format!("{command} needs an item"))?;
            let request = match command.as_str() {
                "archive" => Request::Archive { target },
                "unarchive" => Request::Unarchive { target },
                "delete" => Request::Delete { target },
                _ => Request::Restore { target },
            };
            Ok(Parsed::Run {
                request,
                password_stdin: false,
            })
        }
        other => Err(format!("unknown command \"{other}\"")),
    }
}

fn set_target(slot: &mut Option<String>, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("the item cannot be empty".into());
    }
    if slot.is_some() {
        return Err(format!(
            "unexpected argument \"{value}\": one item at a time"
        ));
    }
    *slot = Some(value.to_string());
    Ok(())
}

fn parse_create(mut args: Args<'_>) -> Result<Parsed, String> {
    let mut item = NewItem {
        kind: ItemKind::Login,
        name: String::new(),
        username: None,
        password: None,
        uris: Vec::new(),
        notes: None,
        folder: None,
        favorite: false,
    };
    let mut password_stdin = false;
    while let Some((arg, inline)) = args.next() {
        match arg {
            "--help" | "-h" => return Ok(Parsed::Help),
            "--name" => item.name = args.value(arg, inline)?,
            "--type" => {
                item.kind = match args.value(arg, inline)?.as_str() {
                    "login" => ItemKind::Login,
                    "note" => ItemKind::Note,
                    other => {
                        return Err(format!("unknown type \"{other}\": expected login or note"))
                    }
                }
            }
            "--username" => item.username = non_empty(args.value(arg, inline)?),
            "--uri" => item.uris.extend(non_empty(args.value(arg, inline)?)),
            "--notes" => item.notes = non_empty(args.value(arg, inline)?),
            "--folder" => item.folder = non_empty(args.value(arg, inline)?),
            "--favorite" => {
                no_value(arg, inline)?;
                item.favorite = true;
            }
            "--password-stdin" => {
                no_value(arg, inline)?;
                password_stdin = true;
            }
            "--password" => return Err(PASSWORD_ON_COMMAND_LINE.into()),
            other => return Err(format!("unknown option {other}")),
        }
    }
    if item.name.trim().is_empty() {
        return Err("create needs --name".into());
    }
    if item.kind == ItemKind::Note
        && (item.username.is_some() || !item.uris.is_empty() || password_stdin)
    {
        return Err("a note has no username, password or URL".into());
    }
    Ok(Parsed::Run {
        request: Request::Create { item },
        password_stdin,
    })
}

const PASSWORD_ON_COMMAND_LINE: &str =
    "there is no --password option, a command line is visible to other processes: \
     pipe the password in and use --password-stdin";

fn parse_edit(mut args: Args<'_>) -> Result<Parsed, String> {
    let mut target = None;
    let mut changes = Changes::default();
    let mut password_stdin = false;
    while let Some((arg, inline)) = args.next() {
        match arg {
            "--help" | "-h" => return Ok(Parsed::Help),
            "--name" => changes.name = Some(args.value(arg, inline)?),
            "--username" => changes.username = Some(args.value(arg, inline)?),
            "--uri" => {
                let uri = args.value(arg, inline)?;
                changes
                    .uris
                    .get_or_insert_with(Vec::new)
                    .extend(non_empty(uri));
            }
            "--no-uri" => {
                no_value(arg, inline)?;
                changes.uris = Some(Vec::new());
            }
            "--notes" => changes.notes = Some(args.value(arg, inline)?),
            "--folder" => changes.folder = Some(args.value(arg, inline)?),
            "--no-folder" => {
                no_value(arg, inline)?;
                changes.folder = Some(String::new());
            }
            "--favorite" => {
                no_value(arg, inline)?;
                changes.favorite = Some(true);
            }
            "--no-favorite" => {
                no_value(arg, inline)?;
                changes.favorite = Some(false);
            }
            "--password-stdin" => {
                no_value(arg, inline)?;
                password_stdin = true;
            }
            "--password" => return Err(PASSWORD_ON_COMMAND_LINE.into()),
            "--type" => return Err("the type of an item cannot be changed".into()),
            a if a.starts_with('-') => return Err(format!("unknown option {a}")),
            a => set_target(&mut target, a)?,
        }
    }
    let target = target.ok_or("edit needs an item")?;
    if changes.name.as_deref().is_some_and(|n| n.trim().is_empty()) {
        return Err("the name cannot be empty".into());
    }
    if changes.is_empty() && !password_stdin {
        return Err("nothing to change".into());
    }
    Ok(Parsed::Run {
        request: Request::Edit { target, changes },
        password_stdin,
    })
}

/// One line of standard input, without its line ending. Whatever else the
/// password contains, spaces included, is kept.
fn password_from(mut input: impl std::io::Read) -> Result<String, String> {
    let mut text = String::new();
    input
        .read_to_string(&mut text)
        .map_err(|e| format!("cannot read the password from standard input: {e}"))?;
    let line = text.split('\n').next().unwrap_or_default();
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.is_empty() {
        return Err("--password-stdin: nothing on standard input".into());
    }
    Ok(line.to_string())
}

fn set_password(request: &mut Request, password: String) {
    match request {
        Request::Create { item } => item.password = Some(password),
        Request::Edit { changes, .. } => changes.password = Some(password),
        _ => {}
    }
}

#[cfg(unix)]
const NOT_REACHABLE: &str = "Clavix is not running, or command-line access is turned off \
     (Preferences > Security > Command-line access)";

#[cfg(unix)]
fn send(request: Request) -> Result<Reply, String> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let path = socket_path().ok_or(NOT_REACHABLE)?;
    let mut stream = UnixStream::connect(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            NOT_REACHABLE.to_string()
        }
        _ => format!("cannot reach Clavix at {}: {e}", path.display()),
    })?;
    // A write goes to the server, which may be refreshing its token first.
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(60)));

    let mut line = serde_json::to_vec(&Envelope {
        v: PROTOCOL_VERSION,
        request,
    })
    .map_err(|e| format!("cannot encode the request: {e}"))?;
    line.push(b'\n');
    stream
        .write_all(&line)
        .map_err(|e| format!("cannot send the request: {e}"))?;

    let mut answer = Vec::new();
    stream
        .take(64 * 1024)
        .read_to_end(&mut answer)
        .map_err(|e| format!("no answer from Clavix: {e}"))?;
    if answer.is_empty() {
        return Err("Clavix closed the connection without answering".into());
    }
    serde_json::from_slice(&answer).map_err(|e| format!("unreadable answer from Clavix: {e}"))
}

#[cfg(not(unix))]
fn send(_request: Request) -> Result<Reply, String> {
    Err("the command line is not available on this platform yet".into())
}

/// Run `clavix item …` and return the exit code: 0 done, 1 refused or
/// failed, 2 the command line itself was wrong.
fn run(args: &[String]) -> i32 {
    let (mut request, password_stdin) = match parse(args) {
        Ok(Parsed::Help) => {
            print!("{USAGE}");
            return 0;
        }
        Ok(Parsed::Run {
            request,
            password_stdin,
        }) => (request, password_stdin),
        Err(e) => {
            eprintln!("clavix: {e}\nTry: clavix item --help");
            return 2;
        }
    };
    if password_stdin {
        match password_from(std::io::stdin().lock()) {
            Ok(password) => set_password(&mut request, password),
            Err(e) => {
                eprintln!("clavix: {e}");
                return 2;
            }
        }
    }
    let created = matches!(request, Request::Create { .. });
    match send(request) {
        Ok(Reply { ok: true, id, .. }) => {
            // Only a creation has something the caller does not know yet.
            if let (true, Some(id)) = (created, id) {
                println!("{id}");
            }
            0
        }
        Ok(Reply { error, .. }) => {
            eprintln!(
                "clavix: {}",
                error.as_deref().unwrap_or("Clavix refused the request")
            );
            1
        }
        Err(e) => {
            eprintln!("clavix: {e}");
            1
        }
    }
}

/// The exit code when this launch is a command-line call, `None` when it
/// is an ordinary start of the app. Called first thing in `main`, before
/// the single-instance guard and before anything graphical is loaded.
pub fn run_if_requested() -> Option<i32> {
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    if args.first().map(String::as_str) != Some("item") {
        return None;
    }
    Some(run(&args[1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_run(list: &[&str]) -> (Request, bool) {
        let args: Vec<String> = list.iter().map(|s| s.to_string()).collect();
        match parse(&args) {
            Ok(Parsed::Run {
                request,
                password_stdin,
            }) => (request, password_stdin),
            Ok(Parsed::Help) => panic!("unexpected help"),
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    fn parse_err(list: &[&str]) -> String {
        let args: Vec<String> = list.iter().map(|s| s.to_string()).collect();
        match parse(&args) {
            Err(e) => e,
            Ok(_) => panic!("expected an error for {list:?}"),
        }
    }

    #[test]
    fn create_reads_every_option_in_both_spellings() {
        let (request, password_stdin) = parse_run(&[
            "create",
            "--name",
            "example",
            "--username=me",
            "--uri",
            "https://a.example",
            "--uri=https://b.example",
            "--notes",
            "two words",
            "--folder",
            "work/servers",
            "--favorite",
            "--password-stdin",
        ]);
        assert!(password_stdin);
        let Request::Create { item } = request else {
            panic!("expected create");
        };
        assert!(item.kind == ItemKind::Login);
        assert_eq!(item.name, "example");
        assert_eq!(item.username.as_deref(), Some("me"));
        assert_eq!(item.uris, ["https://a.example", "https://b.example"]);
        assert_eq!(item.notes.as_deref(), Some("two words"));
        assert_eq!(item.folder.as_deref(), Some("work/servers"));
        assert!(item.favorite);
        // The password is never taken from the arguments.
        assert!(item.password.is_none());
    }

    #[test]
    fn create_refuses_what_it_cannot_honour() {
        assert_eq!(parse_err(&["create"]), "create needs --name");
        assert_eq!(
            parse_err(&["create", "--name", "  "]),
            "create needs --name"
        );
        assert_eq!(parse_err(&["create", "--name"]), "--name needs a value");
        assert!(
            parse_err(&["create", "--name", "x", "--password", "p"]).contains("--password-stdin")
        );
        assert!(parse_err(&["create", "--name", "x", "--type", "card"]).contains("login or note"));
        assert!(
            parse_err(&["create", "--name", "x", "--type", "note", "--username", "u"])
                .contains("a note has no")
        );
        assert_eq!(
            parse_err(&["create", "--name", "x", "--favorite=yes"]),
            "--favorite takes no value"
        );
        assert_eq!(parse_err(&["create", "stray"]), "unknown option stray");
    }

    #[test]
    fn edit_tells_untouched_from_cleared() {
        let (request, password_stdin) =
            parse_run(&["edit", "example", "--username", "", "--no-folder"]);
        assert!(!password_stdin);
        let Request::Edit { target, changes } = request else {
            panic!("expected edit");
        };
        assert_eq!(target, "example");
        assert_eq!(changes.username.as_deref(), Some(""));
        assert_eq!(changes.folder.as_deref(), Some(""));
        assert!(changes.name.is_none());
        assert!(changes.notes.is_none());
        assert!(changes.uris.is_none());
        assert!(changes.favorite.is_none());
    }

    #[test]
    fn edit_uris_replace_or_clear() {
        let (Request::Edit { changes, .. }, _) = parse_run(&["edit", "x", "--uri", "https://a"])
        else {
            panic!("expected edit");
        };
        assert_eq!(
            changes.uris.as_deref(),
            Some(&["https://a".to_string()][..])
        );

        let (Request::Edit { changes, .. }, _) = parse_run(&["edit", "x", "--no-uri"]) else {
            panic!("expected edit");
        };
        assert_eq!(changes.uris.as_deref(), Some(&[][..]));
    }

    #[test]
    fn edit_refuses_what_it_cannot_honour() {
        assert_eq!(parse_err(&["edit", "--favorite"]), "edit needs an item");
        assert_eq!(parse_err(&["edit", "x"]), "nothing to change");
        assert_eq!(
            parse_err(&["edit", "x", "--name", ""]),
            "the name cannot be empty"
        );
        assert!(parse_err(&["edit", "x", "y", "--favorite"]).contains("one item at a time"));
        // A password alone is a change.
        let (_, password_stdin) = parse_run(&["edit", "x", "--password-stdin"]);
        assert!(password_stdin);
    }

    #[test]
    fn the_one_argument_commands() {
        assert!(matches!(
            parse_run(&["delete", "x"]).0,
            Request::Delete { target } if target == "x"
        ));
        assert!(matches!(
            parse_run(&["restore", "x"]).0,
            Request::Restore { target } if target == "x"
        ));
        assert!(matches!(
            parse_run(&["archive", "x"]).0,
            Request::Archive { target } if target == "x"
        ));
        assert!(matches!(
            parse_run(&["unarchive", "x"]).0,
            Request::Unarchive { target } if target == "x"
        ));
        assert_eq!(parse_err(&["delete"]), "delete needs an item");
        assert_eq!(
            parse_err(&["delete", "--force", "x"]),
            "unknown option --force"
        );
        assert_eq!(parse_err(&["purge", "x"]), "unknown command \"purge\"");
    }

    #[test]
    fn help_wherever_it_is_asked() {
        for args in [
            &[][..],
            &["--help"],
            &["create", "-h"],
            &["delete", "--help"],
        ] {
            let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            assert!(matches!(parse(&args), Ok(Parsed::Help)));
        }
    }

    #[test]
    fn the_password_is_one_line_kept_as_typed() {
        assert_eq!(password_from(&b"s3cret\n"[..]).unwrap(), "s3cret");
        assert_eq!(password_from(&b"s3cret\r\n"[..]).unwrap(), "s3cret");
        assert_eq!(password_from(&b"no newline"[..]).unwrap(), "no newline");
        assert_eq!(password_from(&b"  padded  \n"[..]).unwrap(), "  padded  ");
        assert_eq!(password_from(&b"first\nsecond\n"[..]).unwrap(), "first");
        assert!(password_from(&b""[..]).is_err());
        assert!(password_from(&b"\n"[..]).is_err());
    }

    #[test]
    fn requests_survive_the_wire() {
        let (mut request, _) = parse_run(&["edit", "x", "--favorite", "--no-uri"]);
        set_password(&mut request, "pw".into());
        let line = serde_json::to_string(&Envelope {
            v: PROTOCOL_VERSION,
            request,
        })
        .unwrap();
        let back: Envelope = serde_json::from_str(&line).unwrap();
        assert_eq!(back.v, PROTOCOL_VERSION);
        let Request::Edit { target, changes } = back.request else {
            panic!("expected edit");
        };
        assert_eq!(target, "x");
        assert_eq!(changes.password.as_deref(), Some("pw"));
        assert_eq!(changes.favorite, Some(true));
        assert_eq!(changes.uris.as_deref(), Some(&[][..]));
        assert!(changes.username.is_none());
    }
}
