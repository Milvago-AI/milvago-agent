//! Per-machine TLS identity for the read-only Firefox update endpoint.
//! The constrained CA key is generated in memory, signs one leaf, and is never
//! persisted. Only the leaf key is stored, protected by machine DPAPI on Windows.
use crate::Result;
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose,
    GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose, NameConstraints};
use rustls::{ServerConfig, pki_types::{CertificateDer, PrivatePkcs8KeyDer}};
use serde::{Deserialize, Serialize};
use std::{fs, path::{Path, PathBuf}, sync::Arc};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    purpose: String,
    edition: String,
    expires: i64,
    ca: Vec<u8>,
    certificate: Vec<u8>,
    key: Vec<u8>,
}
impl Drop for Identity {
    fn drop(&mut self) { self.key.zeroize(); }
}

fn plain_path(path: &Path) -> Result<()> {
    for part in path.ancestors() {
        match fs::symlink_metadata(part) {
            Ok(meta) => {
                if meta.file_type().is_symlink() { return Err("redirected TLS path refused".into()); }
                #[cfg(windows)] {
                    use std::os::windows::fs::MetadataExt;
                    if meta.file_attributes() & 0x400 != 0 { return Err("redirected TLS path refused".into()); }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub fn directory(state: &Path) -> Result<PathBuf> {
    Ok(state.parent().ok_or("TLS parent missing")?.join("tls"))
}

fn generate() -> Result<Identity> {
    let now = OffsetDateTime::now_utc();
    let until = now + Duration::days(5 * 365);
    let mut ca = CertificateParams::default();
    ca.distinguished_name.push(DnType::CommonName,
        format!("Milvago {} local extension CA", crate::extension_update::EDITION));
    ca.not_before = now - Duration::minutes(5);
    ca.not_after = until;
    ca.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    ca.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    ca.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![
            GeneralSubtree::DnsName("localhost".into()),
            GeneralSubtree::IpAddress("127.0.0.1/32".parse().map_err(|_| "invalid loopback subnet")?),
        ],
        excluded_subtrees: vec![],
    });
    let ca_key = KeyPair::generate()?;
    let root = ca.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca, ca_key);
    let leaf_key = KeyPair::generate()?;
    let mut leaf = CertificateParams::new(vec!["127.0.0.1".into(), "localhost".into()])?;
    leaf.distinguished_name.push(DnType::CommonName, "Milvago local extension service");
    leaf.not_before = now - Duration::minutes(5);
    leaf.not_after = until;
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let certificate = leaf.signed_by(&leaf_key, &issuer)?;
    Ok(Identity {
        purpose: "milvago.extension-tls.v1".into(),
        edition: crate::extension_update::EDITION.into(),
        expires: until.unix_timestamp(),
        ca: root.der().to_vec(), certificate: certificate.der().to_vec(),
        key: leaf_key.serialize_der(),
    })
}

fn load(home: &Path) -> Result<Identity> {
    let file = home.join("identity.bin");
    // Prevent path traversal attacks by rejecting paths containing '..'.
    if file.components().any(|c| c == std::path::Component::ParentDir) {
        return Err(format!("Invalid input: {}", file.display()).into());
    }
    plain_path(&file)?;
    if fs::metadata(&file)?.len() > 65536 { return Err("TLS identity too large".into()); }
    let mut plaintext = crate::os_wrap(&fs::read(file)?, false)?;
    let parsed = serde_json::from_slice::<Identity>(&plaintext);
    plaintext.zeroize();
    let identity = parsed?;
    if identity.purpose != "milvago.extension-tls.v1"
        || identity.edition != crate::extension_update::EDITION
        || identity.ca.is_empty() || identity.certificate.is_empty() || identity.key.is_empty() {
        return Err("TLS identity rejected".into());
    }
    Ok(identity)
}

fn config(identity: &Identity) -> Result<Arc<ServerConfig>> {
    Ok(Arc::new(ServerConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(identity.certificate.clone()), CertificateDer::from(identity.ca.clone())],
            PrivatePkcs8KeyDer::from(identity.key.clone()).into())?))
}

/// Called by the privileged installer after applying directory ACLs. Preserve the
/// identity through ordinary upgrades, so already running Firefox trusts the new
/// agent immediately. Renewal changes trust only when within 60 days of expiry.
pub fn prepare(home: &Path) -> Result<serde_json::Value> {
    plain_path(home)?;
    fs::create_dir_all(home)?;
    let identity = if home.join("identity.bin").exists() {
        let current = load(home)?;
        if current.expires > (OffsetDateTime::now_utc() + Duration::days(60)).unix_timestamp() {
            current
        } else { generate()? }
    } else { generate()? };
    config(&identity)?;
    let mut plaintext = serde_json::to_vec(&identity)?;
    let encrypted = crate::os_wrap(&plaintext, true);
    plaintext.zeroize();
    crate::atomic_private(&home.join("identity.bin"), &encrypted?)?;
    crate::atomic_private(&home.join("extension-ca.cer"), &identity.ca)?;
    Ok(serde_json::json!({"ok":true,"expires":identity.expires,
        "ca_sha256": format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(&identity.ca))}))
}

pub fn server_config(home: &Path) -> Result<Arc<ServerConfig>> {
    config(&load(home)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unique_machine_identity_and_repair_preserves_trust() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let first = prepare(a.path()).unwrap();
        assert_eq!(prepare(a.path()).unwrap(), first);
        assert_ne!(prepare(b.path()).unwrap()["ca_sha256"], first["ca_sha256"]);
        let identity = load(a.path()).unwrap();
        assert!(server_config(a.path()).is_ok());
        #[cfg(windows)]
        assert!(!fs::read(a.path().join("identity.bin")).unwrap()
            .windows(identity.key.len()).any(|part| part == identity.key));
    }
    #[test]
    fn damaged_identity_is_not_silently_replaced() {
        let home = tempfile::tempdir().unwrap();
        prepare(home.path()).unwrap();
        let file = home.path().join("identity.bin");
        let mut raw = fs::read(&file).unwrap();
        let end = raw.len() - 1;
        raw[end] ^= 1;
        fs::write(file, raw).unwrap();
        assert!(prepare(home.path()).is_err());
        assert!(server_config(home.path()).is_err());
    }
}
