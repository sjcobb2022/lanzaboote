use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Write;
use std::iter::repeat_with;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use crate::signature::Signer;

/// The number of random alphanumeric characters in the tempfiles.
const TEMPFILE_RANDOM_LENGTH: usize = 32;

/// Extension for a temporary directory that enables creating secure temporary files in it.
pub trait SecureTempDirExt {
    fn create_secure_file(&self, path: &Path) -> Result<fs::File>;
    fn write_secure_file(&self, contents: impl AsRef<[u8]>) -> Result<PathBuf>;
}

/// This implementation has three useful properties:
///
/// - Files are created with mode 0o600, so that they are only accessible by the current user.
/// - Files are named and not ephemeral (unlike a real temporary file).
/// - The directory and its children are cleaned up (i.e. deleted) when the variable that holds the
///   directory goes out of scope.
///
/// This protects against an attacker _without_ root access from modifying files undetected. It
/// provides no prection against an attacker _with_ root access. Additionally, because the files
/// have named paths, they can be passed to external programs while still being securely deleted
/// after they are not needed anymore.
impl SecureTempDirExt for TempDir {
    /// Create a temporary file that can only be accessed by the current Linux user.
    fn create_secure_file(&self, path: &Path) -> Result<fs::File> {
        fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("Failed to create tempfile: {path:?}"))
    }

    /// Create a temporary file and write a `u8` slice to it.
    fn write_secure_file(&self, contents: impl AsRef<[u8]>) -> Result<PathBuf> {
        let path = self.path().join(tmpname());
        let mut tmpfile = self.create_secure_file(&path)?;

        tmpfile
            .write_all(contents.as_ref())
            .with_context(|| format!("Failed to write to tempfile {path:?}"))?;

        Ok(path)
    }
}

/// Generate a random (but not cryptographically secure) name for a temporary file.
///
/// This is heavily inspired by the way temporary names are generated in the `tempfile` crate.
/// Since the `tempfile` crate does not expose this functionality, we have to recreate it here.
pub fn tmpname() -> OsString {
    let mut buf = OsString::with_capacity(TEMPFILE_RANDOM_LENGTH);
    let mut char_buf = [0u8; 4];
    for c in repeat_with(fastrand::alphanumeric).take(TEMPFILE_RANDOM_LENGTH) {
        buf.push(c.encode_utf8(&mut char_buf));
    }
    buf
}

type Hash = sha2::digest::Output<Sha256>;

/// Compute the SHA 256 hash of a file.
pub fn file_hash(file: &Path) -> Result<Hash> {
    Ok(Sha256::digest(fs::read(file).with_context(|| {
        format!("Failed to read file to hash: {file:?}")
    })?))
}

/// Install a PE file. The PE gets signed in the process.
///
/// If the file already exists at the destination, it is overwritten.
///
/// This is implemented as an atomic write. The file is first written to the destination with a
/// `.tmp` suffix and then renamed to its final name. This is atomic, because a rename is an atomic
/// operation on POSIX platforms.
pub fn install_signed(signer: &impl Signer, from: &Path, to: &Path) -> Result<()> {
    log::debug!("Signing and installing {to:?}...");
    let to_tmp = to.with_extension(".tmp");
    ensure_parent_dir(&to_tmp);
    signer
        .sign_and_copy(from, &to_tmp)
        .with_context(|| format!("Failed to copy and sign file from {from:?} to {to:?}"))?;
    fs::rename(&to_tmp, to).with_context(|| {
        format!("Failed to move temporary file {to_tmp:?} to final location {to:?}")
    })?;
    Ok(())
}

pub fn assemble_kernel_cmdline(init: &Path, kernel_params: Vec<String>) -> Vec<String> {
    let init_string = String::from(
        init.to_str()
            .expect("Failed to convert init path to string"),
    );
    let mut kernel_cmdline: Vec<String> = vec![format!("init={}", init_string)];
    kernel_cmdline.extend(kernel_params);
    kernel_cmdline
}

/// Install an arbitrary file.
///
/// The file is only copied if
///     (1) it doesn't exist at the destination or,
///     (2) the hash of the file at the destination does not match the hash of the source file.
pub fn install(from: &Path, to: &Path) -> Result<()> {
    if !to.exists() || file_hash(from)? != file_hash(to)? {
        force_install(from, to)?;
    }
    Ok(())
}

/// Forcibly install an arbitrary file.
///
/// If the file already exists at the destination, it is overwritten.
///
/// This function is only designed to copy files to the ESP. It sets the permission bits of the
/// file at the destination to 0o755, the expected permissions for a vfat ESP. This is useful for
/// producing file systems trees which can then be converted to a file system image.
pub fn force_install(from: &Path, to: &Path) -> Result<()> {
    log::debug!("Installing {to:?}...");
    ensure_parent_dir(to);
    atomic_copy(from, to)?;
    set_permission_bits(to, 0o755)
        .with_context(|| format!("Failed to set permission bits to 0o755 on file: {to:?}"))?;
    Ok(())
}

/// Atomically copy a file.
///
/// First, the content is written to a temporary file (with a `.tmp` extension).
/// Then, this file is synced, to ensure its data and metadata are fully on disk before continuing.
/// In the last step, the temporary file is renamed to the final destination.
///
/// Due to the deficiencies of FAT32, it is possible for the filesystem to become corrupted after power loss.
/// It is not possible to fully defend against this situation, so this operation is not actually fully atomic.
/// However, in all other cases, the target file is either present with its correct content or not present at all.
pub fn atomic_copy(from: &Path, to: &Path) -> Result<()> {
    let tmp = to.with_extension(".tmp");
    {
        let mut from_file =
            File::open(from).with_context(|| format!("Failed to read the source file {from:?}"))?;
        let mut tmp_file = File::create(&tmp)
            .with_context(|| format!("Failed to create the temporary file {tmp:?}"))?;
        std::io::copy(&mut from_file, &mut tmp_file).with_context(|| {
            format!("Failed to copy from {from:?} to the temporary file {tmp:?}")
        })?;
        tmp_file
            .sync_all()
            .with_context(|| format!("Failed to sync the temporary file {tmp:?}"))?;
    }
    fs::rename(&tmp, to)
        .with_context(|| format!("Failed to move temporary file {tmp:?} to target {to:?}"))
}

/// Set the octal permission bits of the specified file.
pub fn set_permission_bits(path: &Path, permission_bits: u32) -> Result<()> {
    let mut perms = fs::metadata(path)
        .with_context(|| format!("File {path:?} doesn't have any metadata"))?
        .permissions();
    perms.set_mode(permission_bits);
    fs::set_permissions(path, perms)
        .with_context(|| format!("Failed to set permissions on {path:?}"))
}

// Ensures the parent directory of an arbitrary path exists
pub fn ensure_parent_dir(path: &Path) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
}
