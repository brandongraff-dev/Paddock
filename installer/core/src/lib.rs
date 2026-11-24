//! The testable, platform-independent part of the Paddock Setup app.
//!
//! The Tauri shell (`../src-tauri`) is deliberately thin: it receives a request
//! from the wizard, asks this crate whether it is acceptable and what exact
//! argument list to run, then spawns PowerShell. Everything that decides what
//! may run lives here, with tests, and depends on nothing but `std`.
//!
//! Nothing the wizard sends is ever interpolated into a shell string: the
//! result of [`build_args`] is an argv vector for `std::process::Command`.

use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

/// What the wizard can ask the installer script to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Check this PC, change nothing (`-Doctor`).
    Doctor,
    /// Install, upgrade or start Paddock.
    Install,
    /// Stop the containers; data and `.env` are kept (`-Uninstall`).
    Stop,
    /// Remove containers, data and the install folder (`-Uninstall -Purge -Yes`).
    Remove,
}

impl Action {
    pub fn parse(s: &str) -> Option<Action> {
        match s {
            "doctor" => Some(Action::Doctor),
            "install" => Some(Action::Install),
            "stop" => Some(Action::Stop),
            "remove" => Some(Action::Remove),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub action: Action,
    /// Install folder; `None` lets the script use its default (`%USERPROFILE%\paddock`).
    pub dir: Option<String>,
    /// Also start the active scanner (`-Active`).
    pub active: bool,
    /// Add a Start menu shortcut that opens Paddock (installing only; `-NoShortcut` when false).
    pub shortcut: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionsError {
    EmptyDir,
    NotAbsolute,
    TooLong,
    DriveRoot,
    ParentSegment,
    BadCharacter(char),
    SystemFolder,
    TrailingDotOrSpace,
}

impl std::fmt::Display for OptionsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OptionsError::EmptyDir => write!(f, "Choose a folder."),
            OptionsError::NotAbsolute => write!(
                f,
                "Use a full path that starts with a drive letter, like C:\\Paddock."
            ),
            OptionsError::TooLong => {
                write!(f, "That folder path is too long. Choose a shorter one.")
            }
            OptionsError::DriveRoot => write!(f, "Choose a folder, not a whole drive."),
            OptionsError::ParentSegment => write!(f, "The folder path cannot contain '..'."),
            OptionsError::BadCharacter(c) => write!(f, "The folder path cannot contain '{c}'."),
            OptionsError::SystemFolder => {
                write!(f, "Do not install into a Windows or Program Files folder.")
            }
            OptionsError::TrailingDotOrSpace => {
                write!(f, "The folder name cannot end with a space or a dot.")
            }
        }
    }
}

impl std::error::Error for OptionsError {}

const MAX_DIR_LEN: usize = 180;

/// Characters that are either illegal in Windows paths or that PowerShell,
/// batch files or Docker Compose treat specially. Spaces and non-ASCII letters
/// (a user name with an accent) are fine.
fn bad_path_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '<' | '>'
                | '"'
                | '|'
                | '?'
                | '*'
                | ';'
                | '&'
                | '$'
                | '`'
                | '%'
                | '^'
                | '!'
                | '\''
                | '('
                | ')'
                | '{'
                | '}'
                | ','
                | '='
                | '['
                | ']'
        )
}

/// Validate an install folder. Accepts `C:\Users\Ada\paddock` style paths only.
pub fn validate_dir(dir: &str) -> Result<String, OptionsError> {
    let d = dir.trim();
    if d.is_empty() {
        return Err(OptionsError::EmptyDir);
    }
    if d.chars().count() > MAX_DIR_LEN {
        return Err(OptionsError::TooLong);
    }
    let b = d.as_bytes();
    let drive = b.len() >= 3
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && (b[2] == b'\\' || b[2] == b'/');
    if !drive {
        return Err(OptionsError::NotAbsolute);
    }
    let norm = d.replace('/', "\\");
    let norm = norm.trim_end_matches('\\').to_string();
    let parts: Vec<&str> = norm[3.min(norm.len())..]
        .split('\\')
        .filter(|p| !p.is_empty())
        .collect();
    if parts.is_empty() {
        return Err(OptionsError::DriveRoot);
    }
    // name the real problem first: "Program Files (x86)" is a system folder, not a bad character
    let first = parts[0].to_ascii_lowercase();
    if matches!(
        first.as_str(),
        "windows" | "program files" | "program files (x86)" | "programdata"
    ) {
        return Err(OptionsError::SystemFolder);
    }
    // everything after "C:" may not contain a colon (alternate data streams, device paths)
    if let Some(c) = d[2..].chars().find(|c| *c == ':' || bad_path_char(*c)) {
        return Err(OptionsError::BadCharacter(c));
    }
    if parts.iter().any(|p| *p == ".." || *p == ".") {
        return Err(OptionsError::ParentSegment);
    }
    if parts.iter().any(|p| p.ends_with('.') || p.ends_with(' ')) {
        return Err(OptionsError::TrailingDotOrSpace);
    }
    Ok(norm)
}

/// The argv for `powershell.exe`, given the path of the bundled `install.ps1`.
/// Fixed flags first, then only values this function produced.
pub fn build_args(script: &str, opts: &Options) -> Result<Vec<String>, OptionsError> {
    let mut a: Vec<String> = [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    a.push(script.to_string());
    a.push("-Json".into());
    match opts.action {
        Action::Doctor => a.push("-Doctor".into()),
        Action::Install => {
            if opts.active {
                a.push("-Active".into());
            }
            if !opts.shortcut {
                a.push("-NoShortcut".into());
            }
            a.push("-Yes".into());
            a.push("-Wait".into());
            a.push("600".into());
        }
        Action::Stop => a.push("-Uninstall".into()),
        Action::Remove => {
            a.push("-Uninstall".into());
            a.push("-Purge".into());
            a.push("-Yes".into());
        }
    }
    if let Some(d) = &opts.dir {
        a.push("-Dir".into());
        a.push(validate_dir(d)?);
    }
    Ok(a)
}

/// The folder Paddock installs into when the user does not choose one.
pub fn default_dir(user_profile: &str) -> String {
    format!("{}\\paddock", user_profile.trim_end_matches(['\\', '/']))
}

/// Pages the app may open in the browser: Paddock itself and a few help pages.
pub fn allowed_url(url: &str) -> bool {
    if url.chars().any(|c| c.is_control() || c.is_whitespace())
        || url.contains('@')
        || url.contains('\\')
    {
        return false;
    }
    const PREFIXES: [&str; 6] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://www.docker.com/products/docker-desktop",
        "https://docs.docker.com/",
        "https://learn.microsoft.com/windows/wsl/",
        "https://github.com/brandongraff-dev/paddock",
    ];
    PREFIXES.iter().any(|p| {
        url.strip_prefix(p).is_some_and(|rest| {
            // "http://localhost:3000.evil.com" must not match: the prefix has to end a host/path segment
            p.ends_with('/') || rest.is_empty() || rest.starts_with(['/', '?', '#'])
        })
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InstallInfo {
    pub installed: bool,
    pub version: Option<String>,
}

/// Pure part of detection: is there a compose file, and what does `.env` say?
pub fn install_info(has_compose: bool, env_text: Option<&str>) -> InstallInfo {
    let version = env_text.and_then(|t| {
        t.lines()
            .rev()
            .find_map(|l| {
                l.strip_prefix("PADDOCK_VERSION=")
                    .map(|v| v.trim().to_string())
            })
            .filter(|v| !v.is_empty())
    });
    InstallInfo {
        installed: has_compose,
        version,
    }
}

/// Look at a folder on disk.
pub fn detect_install(dir: &Path) -> InstallInfo {
    let has_compose = dir.join("docker-compose.lite.yml").is_file();
    let env = fs::read_to_string(dir.join(".env")).ok();
    install_info(has_compose, env.as_deref())
}

/// Is something accepting connections on 127.0.0.1:port? (Is Paddock up?)
pub fn port_open(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&addr, Duration::from_millis(400)).is_ok()
}

/// Make a line from the installer safe to forward to the UI: bounded length, no control characters.
pub fn clean_line(line: &str) -> String {
    let t: String = line
        .trim_start_matches('\u{feff}')
        .chars()
        .filter(|c| !c.is_control() || *c == '\t')
        .collect();
    if t.chars().count() > 8000 {
        t.chars().take(8000).collect()
    } else {
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(action: Action) -> Options {
        Options {
            action,
            dir: None,
            active: false,
            shortcut: true,
        }
    }

    #[test]
    fn actions_parse_only_the_four_known_words() {
        for (s, a) in [
            ("doctor", Action::Doctor),
            ("install", Action::Install),
            ("stop", Action::Stop),
            ("remove", Action::Remove),
        ] {
            assert_eq!(Action::parse(s), Some(a));
        }
        for bad in [
            "",
            "Install",
            "uninstall",
            "install -Purge",
            "rm",
            "doctor;calc",
        ] {
            assert_eq!(Action::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn dir_accepts_normal_windows_folders() {
        assert_eq!(
            validate_dir("C:\\Users\\Ada Lovelace\\paddock").unwrap(),
            "C:\\Users\\Ada Lovelace\\paddock"
        );
        assert_eq!(
            validate_dir("  d:/data/paddock/ ").unwrap(),
            "d:\\data\\paddock"
        );
        assert_eq!(
            validate_dir("C:\\Users\\José\\paddock").unwrap(),
            "C:\\Users\\José\\paddock"
        );
        assert_eq!(
            validate_dir("E:\\a-b_c.d\\paddock-2").unwrap(),
            "E:\\a-b_c.d\\paddock-2"
        );
    }

    #[test]
    fn dir_rejects_everything_risky() {
        use OptionsError::*;
        assert_eq!(validate_dir(""), Err(EmptyDir));
        assert_eq!(validate_dir("   "), Err(EmptyDir));
        assert_eq!(validate_dir("paddock"), Err(NotAbsolute));
        assert_eq!(validate_dir("\\\\server\\share\\paddock"), Err(NotAbsolute));
        assert_eq!(validate_dir("-Uninstall"), Err(NotAbsolute));
        assert_eq!(validate_dir("C:"), Err(NotAbsolute));
        assert_eq!(validate_dir("C:\\"), Err(DriveRoot));
        assert_eq!(validate_dir("C:\\\\"), Err(DriveRoot));
        assert_eq!(validate_dir("C:\\a\\..\\b"), Err(ParentSegment));
        assert_eq!(validate_dir("C:\\a\\.\\b"), Err(ParentSegment));
        assert_eq!(validate_dir("C:\\Windows\\paddock"), Err(SystemFolder));
        assert_eq!(
            validate_dir("c:\\program files\\paddock"),
            Err(SystemFolder)
        );
        assert_eq!(
            validate_dir("C:\\Program Files (x86)\\paddock"),
            Err(SystemFolder)
        );
        assert_eq!(
            validate_dir("C:\\paddock "),
            Ok("C:\\paddock".into()),
            "trimmed, not rejected"
        );
        assert_eq!(validate_dir("C:\\pad dock.\\x"), Err(TrailingDotOrSpace));
        for c in [
            '"', '\'', ';', '&', '|', '$', '`', '%', '^', '!', '<', '>', '*', '?', '(', ')', '{',
            '}', ',', '=', '[', ']', ':', '\n', '\u{0}',
        ] {
            let p = format!("C:\\pad{c}dock");
            assert!(
                matches!(validate_dir(&p), Err(BadCharacter(x)) if x == c),
                "{p:?}"
            );
        }
        assert_eq!(
            validate_dir(&format!("C:\\{}", "a".repeat(200))),
            Err(TooLong)
        );
    }

    #[test]
    fn install_args_are_fixed_flags_plus_validated_values() {
        let a = build_args(
            "C:\\t\\install.ps1",
            &Options {
                action: Action::Install,
                dir: Some("D:\\p".into()),
                active: true,
                shortcut: true,
            },
        )
        .unwrap();
        assert_eq!(
            a,
            [
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                "C:\\t\\install.ps1",
                "-Json",
                "-Active",
                "-Yes",
                "-Wait",
                "600",
                "-Dir",
                "D:\\p"
            ]
        );
        let b = build_args("s.ps1", &opts(Action::Install)).unwrap();
        assert!(!b.contains(&"-Active".to_string()) && !b.contains(&"-Dir".to_string()));
        assert!(
            b.contains(&"-Json".to_string()),
            "the wizard only understands -Json output"
        );
    }

    #[test]
    fn the_start_menu_shortcut_is_on_unless_declined_and_only_for_installs() {
        let args = |o: Options| build_args("s.ps1", &o).unwrap();
        let on = args(Options {
            action: Action::Install,
            dir: None,
            active: false,
            shortcut: true,
        });
        assert!(!on.iter().any(|x| x == "-NoShortcut"));
        let off = args(Options {
            action: Action::Install,
            dir: None,
            active: false,
            shortcut: false,
        });
        assert!(off.iter().any(|x| x == "-NoShortcut"));
        for a in [Action::Doctor, Action::Stop, Action::Remove] {
            assert!(
                !args(Options {
                    action: a,
                    dir: None,
                    active: false,
                    shortcut: false
                })
                .iter()
                .any(|x| x == "-NoShortcut"),
                "{a:?}"
            );
        }
    }

    #[test]
    fn each_action_maps_to_exactly_its_flags() {
        let has = |o: Options, f: &str| build_args("s.ps1", &o).unwrap().iter().any(|x| x == f);
        assert!(has(opts(Action::Doctor), "-Doctor"));
        assert!(!has(opts(Action::Doctor), "-Yes") && !has(opts(Action::Doctor), "-Uninstall"));
        assert!(has(opts(Action::Stop), "-Uninstall") && !has(opts(Action::Stop), "-Purge"));
        let rm = build_args("s.ps1", &opts(Action::Remove)).unwrap();
        for f in ["-Uninstall", "-Purge", "-Yes"] {
            assert!(rm.iter().any(|x| x == f), "{f}");
        }
        // -Active only means something when installing
        let stop_active = build_args(
            "s.ps1",
            &Options {
                action: Action::Stop,
                dir: None,
                active: true,
                shortcut: true,
            },
        )
        .unwrap();
        assert!(!stop_active.iter().any(|x| x == "-Active"));
    }

    #[test]
    fn a_bad_dir_stops_the_run_before_any_argument_is_produced() {
        let r = build_args(
            "s.ps1",
            &Options {
                action: Action::Remove,
                dir: Some("C:\\".into()),
                active: false,
                shortcut: true,
            },
        );
        assert_eq!(
            r,
            Err(OptionsError::DriveRoot),
            "Remove must never run against a drive root"
        );
        let r = build_args(
            "s.ps1",
            &Options {
                action: Action::Install,
                dir: Some("x\"; calc; \"".into()),
                active: false,
                shortcut: true,
            },
        );
        assert!(r.is_err());
    }

    #[test]
    fn default_dir_is_under_the_profile() {
        assert_eq!(default_dir("C:\\Users\\Ada"), "C:\\Users\\Ada\\paddock");
        assert_eq!(default_dir("C:\\Users\\Ada\\"), "C:\\Users\\Ada\\paddock");
        assert!(validate_dir(&default_dir("C:\\Users\\Ada")).is_ok());
    }

    #[test]
    fn only_paddock_and_help_pages_can_be_opened() {
        for ok in [
            "http://localhost:3000",
            "http://localhost:3000/",
            "http://localhost:3000/setup?x=1",
            "http://127.0.0.1:3000/#a",
            "https://www.docker.com/products/docker-desktop/",
            "https://docs.docker.com/desktop/setup/install/windows-install/",
            "https://learn.microsoft.com/windows/wsl/install",
            "https://github.com/brandongraff-dev/paddock/releases",
            "https://github.com/brandongraff-dev/paddock/issues/new?title=Setup%20problem&labels=installer",
        ] {
            assert!(allowed_url(ok), "{ok}");
        }
        for bad in [
            "",
            "javascript:alert(1)",
            "file:///C:/Windows/System32/calc.exe",
            "calc.exe",
            "http://localhost:3000.evil.com/",
            "http://localhost:30001/",
            "http://localhost:3000@evil.com/",
            "http://evil.com/http://localhost:3000",
            "https://www.docker.com.evil.com/products/docker-desktop",
            "https://github.com/brandongraff-dev-evil/x",
            "https://github.com/someone-else/paddock",
            "http://localhost:3000/\nx",
            "http://localhost:3000/ a",
            "http://localhost:3000\\..\\x",
            "https://docs.docker.com@evil.com/",
        ] {
            assert!(!allowed_url(bad), "{bad:?}");
        }
    }

    #[test]
    fn install_info_reads_the_pinned_version() {
        assert_eq!(
            install_info(false, None),
            InstallInfo {
                installed: false,
                version: None
            }
        );
        assert_eq!(install_info(true, None).version, None);
        let env = "POSTGRES_PASSWORD=x\nPADDOCK_VERSION=1.2.3\nOTHER=1\n";
        assert_eq!(
            install_info(true, Some(env)),
            InstallInfo {
                installed: true,
                version: Some("1.2.3".into())
            }
        );
        assert_eq!(install_info(true, Some("PADDOCK_VERSION=\n")).version, None);
        assert_eq!(
            install_info(true, Some("PADDOCK_VERSION=1.0.0\nPADDOCK_VERSION=1.1.0\n"))
                .version
                .as_deref(),
            Some("1.1.0"),
            "last one wins like docker compose"
        );
    }

    #[test]
    fn detect_install_looks_at_the_folder() {
        let d = std::env::temp_dir().join(format!("paddock-core-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        assert!(!detect_install(&d).installed);
        fs::write(d.join("docker-compose.lite.yml"), "services: {}\n").unwrap();
        fs::write(d.join(".env"), "PADDOCK_VERSION=4.5.6\n").unwrap();
        assert_eq!(
            detect_install(&d),
            InstallInfo {
                installed: true,
                version: Some("4.5.6".into())
            }
        );
        assert!(!detect_install(&d.join("missing")).installed);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn port_probe_sees_a_listener_and_a_closed_port() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        assert!(port_open(port));
        drop(l);
        assert!(!port_open(port));
    }

    #[test]
    fn lines_are_cleaned_before_reaching_the_ui() {
        assert_eq!(
            clean_line("\u{feff}{\"type\":\"log\"}\r\n"),
            "{\"type\":\"log\"}"
        );
        assert_eq!(clean_line("a\u{1b}[31mb\u{7}"), "a[31mb");
        assert_eq!(clean_line(&"x".repeat(9000)).len(), 8000);
        assert_eq!(clean_line("tab\there"), "tab\there");
    }
}
