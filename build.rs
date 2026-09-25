use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=MILVAGO_EMBED_EXTENSION");
    println!("cargo:rerun-if-changed=extension-ports.json");
    println!("cargo:rerun-if-changed=extension/manifest.json");
    println!("cargo:rerun-if-changed=extension/firefox-version.txt");
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("extension/manifest.json")).unwrap()).unwrap();
    let extension_version = manifest["version"]
        .as_str()
        .expect("extension version missing");
    let firefox_version_text =
        fs::read_to_string(root.join("extension/firefox-version.txt")).unwrap();
    let firefox_version = firefox_version_text.trim();
    for version in [extension_version, firefox_version] {
        let parts: Vec<_> = version.split('.').collect();
        assert!(
            parts.len() == 3
                && parts.iter().all(|p| !p.is_empty()
                    && p.len() <= 5
                    && p.bytes().all(|b| b.is_ascii_digit())),
            "invalid extension release version"
        );
    }
    let commercial = env::var_os("CARGO_FEATURE_ENTERPRISE_EXTENSION").is_some();
    let edition = if commercial {
        "commercial"
    } else {
        "community"
    };
    let ports: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("extension-ports.json")).unwrap()).unwrap();
    let port = ports[edition]
        .as_u64()
        .filter(|p| (1024..=65535).contains(p))
        .expect("invalid fixed extension port");
    let origin = format!("http://127.0.0.1:{port}");
    let firefox_port = ports[format!("firefox_{edition}")]
        .as_u64()
        .filter(|p| (1024..=65535).contains(p))
        .expect("invalid Firefox port");
    let firefox_origin = format!("https://127.0.0.1:{firefox_port}");
    let mut source = format!(
        "pub const EDITION: &str = {edition:?};\npub const ORIGIN: &str = {origin:?};\npub const PORT: u16 = {port};\n"
    );
    source.push_str(&format!("pub const VERSION: &str = {extension_version:?};\npub const FIREFOX_VERSION: &str = {firefox_version:?};\n"));
    source.push_str(&format!("pub const FIREFOX_ORIGIN: &str = {firefox_origin:?};\npub const FIREFOX_PORT: u16 = {firefox_port};\n"));
    // Windows release artifacts cannot silently omit their extension. Development
    // binaries can opt in when explicitly exercising the real distribution path, and a
    // build without the signed packages (a contributor's release build) opts out just as
    // explicitly with MILVAGO_EMBED_EXTENSION=0: the agent then carries no extension.
    let embedded = match env::var("MILVAGO_EMBED_EXTENSION").as_deref() {
        Ok("1") => true,
        Ok("0") => false,
        _ => env::var("PROFILE").unwrap() == "release" && env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows",
    };
    if embedded {
        let dir = root
            .join("../.local/installers/extensions/embedded")
            .join(edition);
        for name in [
            "milvago.crx",
            "extension-id.txt",
            "version.txt",
            "milvago.xpi",
            "firefox-id.txt",
            "firefox-version.txt",
        ] {
            println!("cargo:rerun-if-changed={}", dir.join(name).display());
        }
        let version = fs::read_to_string(dir.join("version.txt"))
            .expect("run scripts/prepare-embedded-extensions.mjs before a release build");
        assert_eq!(
            version.trim(),
            extension_version,
            "embedded extension must match the declared extension release"
        );
        let id = fs::read_to_string(dir.join("extension-id.txt")).unwrap();
        let id = id.trim();
        assert!(id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b)));
        let path = dir.join("milvago.crx").canonicalize().unwrap();
        let crx = fs::read(&path).unwrap();
        assert!(
            crx.len() >= 12 && crx.len() <= 16 * 1024 * 1024 && crx.starts_with(b"Cr24\x03\0\0\0"),
            "invalid embedded CRX3"
        );
        source.push_str(&format!("pub const CHROMIUM_ID: &str = {id:?};\npub static CRX: &[u8] = include_bytes!({:?});\n", path.to_str().unwrap()));
        let prepared_firefox_version = fs::read_to_string(dir.join("firefox-version.txt")).unwrap();
        assert_eq!(
            prepared_firefox_version.trim(),
            firefox_version,
            "embedded Firefox must match the declared Firefox release"
        );
        let firefox_id = fs::read_to_string(dir.join("firefox-id.txt")).unwrap();
        let firefox_id = firefox_id.trim();
        let expected_id = if commercial {
            "browser-enterprise@milvago.app"
        } else {
            "browser-community@milvago.app"
        };
        assert_eq!(firefox_id, expected_id, "wrong Firefox edition");
        let xpi = dir.join("milvago.xpi").canonicalize().unwrap();
        let bytes = fs::read(&xpi).unwrap();
        assert!(bytes.starts_with(b"PK\x03\x04") && bytes.len() <= 16 * 1024 * 1024);
        source.push_str(&format!("pub const FIREFOX_ID: &str = {firefox_id:?};\npub static XPI: &[u8] = include_bytes!({:?});\n", xpi.to_str().unwrap()));
    } else {
        source.push_str("pub const FIREFOX_ID: &str = \"\";\npub static XPI: &[u8] = &[];\n");
        source.push_str("pub const CHROMIUM_ID: &str = \"\";\npub static CRX: &[u8] = &[];\n");
    }
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("extension_bundle.rs"),
        source,
    )
    .unwrap();
}
