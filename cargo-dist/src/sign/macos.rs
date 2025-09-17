//! Codesigning using Apple's builtin `codesign` tool.
//! Because Apple's tools are tightly integrated into their
//! ecosystem, there's a couple of considerations here:
//! 1) This can only be run on a Mac, and
//! 2) Apple expects certificates to be located in the Keychain,
//!    a Mac-specific certificate store, which interacts a bit
//!    weirdly with our ephemeral runner setup in CI.
//!
//! Most of this module is actually concerned with ephemeral
//! keychain setup, with the signing section of the code relatively
//! short in comparison. The keychain code will be reused elsewhere
//! in the future.
//!
//! The workflow we follow here is:
//! 1) Create an ephemeral keychain in a temporary directory;
//! 2) Configure it to be usable for signing;
//! 3) Import the certificate specified in the environment;
//! 4) Actually perform the signing;
//! 5) Submit the signed binary in a zip file to Apple for notarization;
//! 6) Let the keychain be deleted when the temporary directory is dropped.
use axoasset::LocalAsset;
use axoprocess::Cmd;
use base64::Engine;
use camino::{Utf8Path, Utf8PathBuf};
use dist_schema::TripleNameRef;
use tempfile::TempDir;
use tracing::warn;

use crate::{create_tmp, DistError, DistResult};

struct Keychain {
    _root: TempDir,
    root_path: Utf8PathBuf,
    password: String,
    pub path: Utf8PathBuf,
}

impl Keychain {
    /// Creates a keychain in a temporary directory, secured
    /// with the provided password.
    pub fn create(password: String) -> DistResult<Self> {
        let (root, root_path) = create_tmp()?;
        let path = root_path.join("signing.keychain-db");

        let mut cmd = Cmd::new("/usr/bin/security", "create keychain");
        cmd.arg("create-keychain");
        cmd.arg("-p").arg(&password);
        cmd.arg(&path);
        cmd.stdout_to_stderr();
        cmd.status()?;

        // This sets a longer timeout so that it remains
        // unlocked by the time we perform the signature;
        // the keychain will be deleted before this
        // lock period expires.
        let mut cmd = Cmd::new("/usr/bin/security", "set timeout");
        cmd.arg("set-keychain-settings");
        cmd.arg("-lut").arg("21600");
        cmd.arg(&path);
        cmd.stdout_to_stderr();
        cmd.status()?;

        // Unlock for use in later commands
        let mut cmd = Cmd::new("/usr/bin/security", "unlock keychain");
        cmd.arg("unlock-keychain");
        cmd.arg("-p").arg(&password);
        cmd.arg(&path);
        cmd.stdout_to_stderr();
        cmd.status()?;

        // Set as the default keychain for subsequent commands
        let mut cmd = Cmd::new("/usr/bin/security", "set keychain as default");
        cmd.arg("default-keychain");
        cmd.arg("-s");
        cmd.arg(&path);
        cmd.stdout_to_stderr();
        cmd.status()?;

        Ok(Self {
            _root: root,
            root_path,
            password,
            path,
        })
    }

    /// Imports certificate `certificate` with passphrase `passphrase`
    /// into the keychain at `self`.
    pub fn import_certificate(&self, certificate: &[u8], passphrase: &str) -> DistResult<()> {
        // Temporarily write `certificate` into `path` for `security`
        let cert_path = self.root_path.join("cert.p12");
        LocalAsset::new(&cert_path, certificate.to_owned())?.write_to_dir(&self.root_path)?;

        let mut cmd = Cmd::new("/usr/bin/security", "import certificate");
        cmd.arg("import");
        cmd.arg(&cert_path);
        cmd.arg("-k").arg(&self.path);
        cmd.arg("-P").arg(passphrase);
        cmd.arg("-t").arg("cert");
        cmd.arg("-f").arg("pkcs12");
        cmd.arg("-A");
        cmd.arg("-T")
            .arg("/usr/bin/codesign")
            .arg("-T")
            .arg("/usr/bin/security")
            .arg("-T")
            .arg("/usr/bin/productsign");
        cmd.stdout_to_stderr();
        cmd.status()?;

        let mut cmd = Cmd::new("/usr/bin/security", "configure certificate for signing");
        cmd.arg("set-key-partition-list");
        cmd.arg("-S").arg("apple-tool:,apple:,codesign:");
        cmd.arg("-k").arg(&self.password);
        cmd.arg(&self.path);
        cmd.stdout_to_stderr();
        cmd.status()?;

        Ok(())
    }
}

/// Configuration for the system macOS codesign(1)
#[derive(Debug)]
pub struct Codesign {
    env: CodesignEnv,
}

struct CodesignEnv {
    pub identity: String,
    pub password: String,
    pub certificate: Vec<u8>,
    pub notarization_apple_id: String,
    pub notarization_password: String,
}

impl CodesignEnv {
    pub fn from(
        identity: &str,
        password: &str,
        raw_certificate: &str,
        notarization_apple_id: &str,
        notarization_password: &str,
    ) -> DistResult<Self> {
        let certificate = base64::prelude::BASE64_STANDARD
            .decode(raw_certificate)
            .map_err(|_| DistError::CertificateDecodeError {})?;

        Ok(Self {
            identity: identity.to_owned(),
            password: password.to_owned(),
            certificate,
            notarization_apple_id: notarization_apple_id.to_owned(),
            notarization_password: notarization_password.to_owned(),
        })
    }
}

impl std::fmt::Debug for CodesignEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodesignEnv")
            .field("identity", &"<hidden>")
            .field("password", &"<hidden>")
            .field("certificate", &"<hidden>")
            .field("notarization_apple_id", &"<hidden>")
            .field("notarization_password", &"<hidden>")
            .finish()
    }
}

impl Codesign {
    pub fn new(host_target: &TripleNameRef) -> DistResult<Option<Self>> {
        if !host_target.is_darwin() {
            return Ok(None);
        }

        if let (
            Some(identity),
            Some(password),
            Some(certificate),
            Some(notarization_apple_id),
            Some(notarization_password),
        ) = (
            Self::var("CODESIGN_IDENTITY"),
            Self::var("CODESIGN_CERTIFICATE_PASSWORD"),
            Self::var("CODESIGN_CERTIFICATE"),
            Self::var("CODESIGN_NOTARIZATION_APPLE_ID"),
            Self::var("CODESIGN_NOTARIZATION_PASSWORD"),
        ) {
            let env = CodesignEnv::from(
                &identity,
                &password,
                &certificate,
                &notarization_apple_id,
                &notarization_password,
            )?;

            Ok(Some(Self { env }))
        } else {
            Ok(None)
        }
    }

    fn var(var: &str) -> Option<String> {
        let val = std::env::var(var).ok();
        if val.is_none() {
            warn!("{var} is missing");
        }
        val
    }

    fn sign_binary(&self, file: &Utf8Path, keychain: &Keychain) -> DistResult<()> {
        let mut cmd = Cmd::new("/usr/bin/codesign", "sign macOS artifacts");
        cmd.arg("--sign").arg(&self.env.identity);
        cmd.arg("--keychain").arg(&keychain.path);
        cmd.arg("--timestamp");
        cmd.arg("--options").arg("runtime");
        cmd.arg(file);
        cmd.stdout_to_stderr();
        cmd.output()?;

        Ok(())
    }

    fn notarize(&self, file: &Utf8Path) -> DistResult<()> {
        let (_root, root_path) = create_tmp()?;
        let mut file_name: Utf8PathBuf = file
            .file_name()
            .expect("path to notarize had no file name")
            .into();
        file_name.set_extension("zip");
        let zip_path = root_path.join(file_name);

        // A bare Mach-O binary cannot be notarized. A package or zip must be sent.
        let mut ditto_cmd = Cmd::new("/usr/bin/ditto", "zip macOS artifacts for notarization");
        ditto_cmd.arg("-c");
        ditto_cmd.arg("-k");
        ditto_cmd.arg("--keepParent");
        ditto_cmd.arg(file);
        ditto_cmd.arg(&zip_path);
        ditto_cmd.stdout_to_stderr();
        ditto_cmd.output()?;

        // xcrun notarytool submit --apple-id will@ox1de.com --team-id 4459W66H65 --password rdus-eanr-deij-wbnc --wait dist.zip
        let mut notarize_cmd = Cmd::new("/usr/bin/xcrun", "notarize macOS artifacts");
        notarize_cmd.arg("notarytool");
        notarize_cmd.arg("submit");
        notarize_cmd
            .arg("--apple-id")
            .arg(&self.env.notarization_apple_id);
        notarize_cmd.arg("--team-id").arg(&self.env.identity);
        notarize_cmd
            .arg("--password")
            .arg(&self.env.notarization_password);
        notarize_cmd.arg(&zip_path);
        notarize_cmd.stdout_to_stderr();
        notarize_cmd.output()?;

        Ok(())
    }

    pub fn sign(&self, file: &Utf8Path) -> DistResult<()> {
        let password = uuid::Uuid::new_v4().as_hyphenated().to_string();
        let keychain = Keychain::create(password)?;
        keychain.import_certificate(&self.env.certificate, &self.env.password)?;

        self.sign_binary(file, &keychain)?;
        self.notarize(file)
    }
}
