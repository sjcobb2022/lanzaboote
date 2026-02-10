use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::net::IpAddr;
use log::{error, warn};
use sha2::{Digest, Sha256};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::network::pxe::{BaseCode, DhcpV4Packet};
use uefi::{CString16, Result, fs::FileSystem, prelude::*};

use crate::common::{boot_linux_unchecked, extract_string, get_cmdline, get_secure_boot_status};
use linux_bootloader::pe_section::pe_section;
use linux_bootloader::uefi_helpers::booted_image_file;

type Hash = sha2::digest::Output<Sha256>;

/// The configuration that is embedded at build time.
///
/// After this stub is built, lzbt needs to embed configuration into the binary by adding PE
/// sections. This struct represents that information.
struct EmbeddedConfiguration {
    /// The filename of the kernel to be booted. This filename is
    /// relative to the root of the volume that contains the
    /// lanzaboote binary.
    kernel_filename: CString16,

    /// The cryptographic hash of the kernel.
    kernel_hash: Hash,

    /// The filename of the initrd to be passed to the kernel. See
    /// `kernel_filename` for how to interpret these filenames.
    initrd_filename: CString16,

    /// The cryptographic hash of the initrd. This hash is computed
    /// over the whole PE binary, not only the embedded initrd.
    initrd_hash: Hash,

    /// The kernel command-line.
    cmdline: CString16,
}

/// Extract a SHA256 hash from a PE section.
fn extract_hash(pe_data: &[u8], section: &str) -> Result<Hash> {
    let array: [u8; 32] = pe_section(pe_data, section)
        .ok_or(Status::INVALID_PARAMETER)?
        .try_into()
        .map_err(|_| Status::INVALID_PARAMETER)?;

    Ok(array.into())
}

impl EmbeddedConfiguration {
    fn new(file_data: &[u8]) -> Result<Self> {
        Ok(Self {
            kernel_filename: extract_string(file_data, ".linux")?,
            kernel_hash: extract_hash(file_data, ".linuxh")?,

            initrd_filename: extract_string(file_data, ".initrd")?,
            initrd_hash: extract_hash(file_data, ".initrdh")?,

            cmdline: extract_string(file_data, ".cmdline")?,
        })
    }
}

/// Verify some data against its expected hash.
///
/// In case of a mismatch:
/// * If Secure Boot is active, an error message is logged, and the SECURITY_VIOLATION error is returned to stop the boot.
/// * If Secure Boot is not active, only a warning is logged, and the boot process is allowed to continue.
fn check_hash(data: &[u8], expected_hash: Hash, name: &str, secure_boot: bool) -> uefi::Result<()> {
    let hash_correct = Sha256::digest(data) == expected_hash;
    if !hash_correct {
        if secure_boot {
            error!("{name} hash does not match!");
            return Err(Status::SECURITY_VIOLATION.into());
        } else {
            warn!("{name} hash does not match! Continuing anyway.");
        }
    }
    Ok(())
}

pub fn boot_linux(handle: Handle, dynamic_initrds: Vec<Vec<u8>>) -> uefi::Result<()> {
    // SAFETY: We get a slice that represents our currently running
    // image and then parse the PE data structures from it. This is
    // safe, because we don't touch any data in the data sections that
    // might conceivably change while we look at the slice.
    let config = unsafe {
        EmbeddedConfiguration::new(booted_image_file().unwrap().as_slice())
            .expect("Failed to extract configuration from binary. Did you run lzbt?")
    };

    let secure_boot_enabled = get_secure_boot_status();

    let kernel_data;
    let mut initrd_data;

    {
        let file_system_result = uefi::boot::get_image_file_system(handle);

        if let Ok(file_system_handle) = file_system_result {
            let mut filesystem = FileSystem::new(file_system_handle);
            (kernel_data, initrd_data) = load_via_fs(
                &mut filesystem,
                &config.kernel_filename,
                &config.initrd_filename,
            )?;
        } else {
            (kernel_data, initrd_data) =
                load_via_tftp(&config.kernel_filename, &config.initrd_filename)?;
        }
    }

    let cmdline = get_cmdline(&config.cmdline, secure_boot_enabled);

    check_hash(
        &kernel_data,
        config.kernel_hash,
        "Kernel",
        secure_boot_enabled,
    )?;
    check_hash(
        &initrd_data,
        config.initrd_hash,
        "Initrd",
        secure_boot_enabled,
    )?;

    // Correctness: dynamic initrds are supposed to be validated by caller,
    // i.e. they are system extension images or credentials
    // that are supposedly measured in TPM2.
    // Therefore, it is normal to not verify their hashes against a configuration.

    // Pad to align
    initrd_data.resize(initrd_data.len().next_multiple_of(4), 0);
    for mut extra_initrd in dynamic_initrds {
        // Uncomment for maximal debugging pleasure.
        // let debug_representation = extra_initrd.as_slice().escape_ascii().collect::<Vec<u8>>();
        // log::warn!("{:?}", String::from_utf8_lossy(&debug_representation));
        initrd_data.append(&mut extra_initrd);
        // Extra initrds ideally should be aligned, but just in case, let's verify this.
        initrd_data.resize(initrd_data.len().next_multiple_of(4), 0);
    }

    boot_linux_unchecked(handle, kernel_data, &cmdline, initrd_data)
}

/// Extract the last component (filename) from a path.
/// Example: "/nix/store/7znxcsd50p2fy18pb25jb3n4ss98dnys-linux-6.12.64/bzImage" -> "bzImage"
fn extract_filename_from_path(path: &CString16) -> Result<CString16> {
    // Convert to string to work with
    let path_str = path.to_string();

    // Split by both forward and backslash to handle different path formats
    let filename = path_str
        .rsplit(['\\', '/'])
        .next()
        .ok_or(Status::INVALID_PARAMETER)?;

    // Convert back to CString16
    CString16::try_from(filename).map_err(|_| Status::INVALID_PARAMETER.into())
}

fn load_via_fs(
    file_system: &mut FileSystem,
    kernel_filename: &CString16,
    initrd_filename: &CString16,
) -> uefi::Result<(Vec<u8>, Vec<u8>)> {
    let kernel_data = file_system
        .read(&**kernel_filename)
        .expect("Failed to read kernel file into memory");
    let initrd_data = file_system
        .read(&**initrd_filename)
        .expect("Failed to read initrd file into memory");

    Ok((kernel_data, initrd_data))
}

/// Load kernel and initrd via TFTP from the network.
fn load_via_tftp(
    kernel_filename: &CString16,
    initrd_filename: &CString16,
) -> uefi::Result<(Vec<u8>, Vec<u8>)> {
    let loaded_image_protocol = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())
        .expect("Cannot perform network boot: loaded image protocol unavailable");

    let device_handle = loaded_image_protocol
        .device()
        .expect("Cannot perform network boot: no device handle available");
    let mut base_code = boot::open_protocol_exclusive::<BaseCode>(device_handle)
        .expect("Cannot perform network boot: PXE BaseCode protocol not found on device");

    assert!(
        base_code.mode().dhcp_ack_received(),
        "Network boot requires DHCP configuration; ensure the system booted via PXE with DHCP enabled"
    );
    let dhcp_ack: &DhcpV4Packet = base_code.mode().dhcp_ack().as_ref();
    let server_ip = dhcp_ack.bootp_si_addr;
    let server_ip = IpAddr::from(server_ip);

    // Extract filenames from the embedded config paths
    let kernel_file = extract_filename_from_path(kernel_filename)
        .expect("Failed to extract kernel filename from path");
    let initrd_file = extract_filename_from_path(initrd_filename)
        .expect("Failed to extract initrd filename from path");

    // Convert to UTF-8 CStr8 for TFTP (prepend "./" for relative path)
    let kernel_path_string = format!("./{}", kernel_file);
    let initrd_path_string = format!("./{}", initrd_file);

    // Convert strings to CStr8 for TFTP API
    // TFTP requires ASCII/UTF-8 filenames
    let kernel_tftp_name = kernel_path_string.as_bytes();
    let initrd_tftp_name = initrd_path_string.as_bytes();

    // Allocate buffers for CStr8 with null terminators
    let mut kernel_tftp_buf = alloc::vec![0u8; kernel_tftp_name.len() + 1];
    let mut initrd_tftp_buf = alloc::vec![0u8; initrd_tftp_name.len() + 1];
    kernel_tftp_buf[..kernel_tftp_name.len()].copy_from_slice(kernel_tftp_name);
    initrd_tftp_buf[..initrd_tftp_name.len()].copy_from_slice(initrd_tftp_name);

    let kernel_cstr =
        uefi::CStr8::from_bytes_with_nul(&kernel_tftp_buf).expect("Failed to create kernel CStr8");
    let initrd_cstr =
        uefi::CStr8::from_bytes_with_nul(&initrd_tftp_buf).expect("Failed to create initrd CStr8");

    let kfile_size = base_code
        .tftp_get_file_size(&server_ip, kernel_cstr)
        .expect("Failed to query kernel file size via TFTP");

    let ifile_size = base_code
        .tftp_get_file_size(&server_ip, initrd_cstr)
        .expect("Failed to query initrd file size via TFTP");

    assert!(
        kfile_size > 0,
        "TFTP kernel file is empty or does not exist"
    );
    assert!(
        ifile_size > 0,
        "TFTP initrd file is empty or does not exist"
    );

    let mut kernel_data = vec![0; kfile_size as usize];
    let mut initrd_data = vec![0; ifile_size as usize];

    let klen = base_code
        .tftp_read_file(&server_ip, kernel_cstr, Some(&mut kernel_data))
        .expect("Failed to read kernel file via TFTP");
    let ilen = base_code
        .tftp_read_file(&server_ip, initrd_cstr, Some(&mut initrd_data))
        .expect("Failed to read initrd file via TFTP");

    assert!(
        klen > 0,
        "TFTP read operation returned 0 bytes for kernel file"
    );
    assert!(
        ilen > 0,
        "TFTP read operation returned 0 bytes for initrd file"
    );

    Ok((kernel_data, initrd_data))
}
