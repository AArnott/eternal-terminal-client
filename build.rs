//! Embed Windows PE VERSIONINFO (File Properties → Details).
//!
//! File/Product version numbers come from `Cargo.toml` `[package].version`
//! (`CARGO_PKG_VERSION`). Keep that field in lockstep with git tags `vX.Y.Z`
//! (enforced by the release workflow).

fn main() {
    #[cfg(windows)]
    {
        embed_windows_version_info();
    }
}

#[cfg(windows)]
fn embed_windows_version_info() {
    let version = std::env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION");
    let description = std::env::var("CARGO_PKG_DESCRIPTION").unwrap_or_else(|_| {
        "Eternal Terminal client — reconnectable remote shell".into()
    });
    let repository = std::env::var("CARGO_PKG_REPOSITORY").unwrap_or_else(|_| {
        "https://github.com/AArnott/eternal-terminal-client".into()
    });

    // English (United States) — appears as "Language" in File Properties.
    const LANG_EN_US: u16 = 0x0409;

    let mut res = winresource::WindowsResource::new();
    res.set_language(LANG_EN_US);

    // Standard StringFileInfo keys (Explorer Details pane).
    res.set("FileDescription", &description);
    res.set("ProductName", "Eternal Terminal");
    res.set("ProductVersion", &version);
    res.set("FileVersion", &version);
    res.set("LegalCopyright", "Copyright (c) 2026 Andrew Arnott");
    res.set("CompanyName", "Andrew Arnott");
    res.set("InternalName", "et");
    res.set("OriginalFilename", "et.exe");
    // Comments is a standard key; some UIs surface it more readily than custom keys.
    res.set("Comments", &repository);

    // Custom StringFileInfo entry — valid in PE VERSIONINFO; readable via
    // VerQueryValue / resource viewers. Explorer's default Details tab only
    // shows a fixed set of well-known names, so "Repository" may not appear
    // there even though it is embedded (see release verification step).
    res.set("Repository", &repository);

    // FILEVERSION / PRODUCTVERSION numeric tuples are taken from package.version
    // by winresource unless overridden.
    if let Err(e) = res.compile() {
        // Fail the Windows build if resources cannot be embedded — empty
        // Details pane is exactly what we are fixing.
        panic!("failed to embed Windows version resources: {e}");
    }
}
