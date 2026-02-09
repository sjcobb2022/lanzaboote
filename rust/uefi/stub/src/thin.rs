use alloc::vec::Vec;
use log::{error, warn};
use sha2::{Digest, Sha256};
use uefi::{CString16, Result, fs::FileSystem, prelude::*};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::network::pxe::{BaseCode, DhcpV4Packet};
use core::net::{IpAddr, Ipv4Addr};

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
            kernel_filename: extract_string(file_data, ".kernelp")?,
            kernel_hash: extract_hash(file_data, ".kernelh")?,

            initrd_filename: extract_string(file_data, ".initrdp")?,
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

/// Load kernel and initrd via TFTP from the network
fn load_via_tftp(_handle: Handle) -> uefi::Result<(Vec<u8>, Vec<u8>)> {
    let loaded_image_protocol = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())
        .expect("Cannot perform network boot: loaded image protocol unavailable");

    let device_handle = loaded_image_protocol.device()
        .expect("Cannot perform network boot: no device handle available");
    let mut base_code = boot::open_protocol_exclusive::<BaseCode>(device_handle)
        .expect("Cannot perform network boot: PXE BaseCode protocol not found on device");

    assert!(
        base_code.mode().dhcp_ack_received(),
        "Network boot requires DHCP configuration; ensure the system booted via PXE with DHCP enabled"
    );
    let dhcp_ack: &DhcpV4Packet = base_code.mode().dhcp_ack().as_ref();
    let server_ip = dhcp_ack.bootp_si_addr;
    let server_ip = IpAddr::V4(Ipv4Addr::from(server_ip));

    // Use hardcoded filenames for TFTP as in netboot branch
    // TODO: Consider using embedded configuration paths for more flexibility
    let kernel_filename = cstr8!("./bzImage");
    let initrd_filename = cstr8!("./initrd");

    let kfile_size = base_code
        .tftp_get_file_size(&server_ip, kernel_filename)
        .expect("Failed to query kernel file size via TFTP");

    let ifile_size = base_code
        .tftp_get_file_size(&server_ip, initrd_filename)
        .expect("Failed to query initrd file size via TFTP");

    assert!(kfile_size > 0, "TFTP kernel file is empty or does not exist");
    assert!(ifile_size > 0, "TFTP initrd file is empty or does not exist");

    let mut kernel_data = Vec::with_capacity(kfile_size as usize);
    kernel_data.resize(kfile_size as usize, 0);
    let mut initrd_data = Vec::with_capacity(ifile_size as usize);
    initrd_data.resize(ifile_size as usize, 0);

    let klen = base_code
        .tftp_read_file(&server_ip, kernel_filename, Some(&mut kernel_data))
        .expect("Failed to read kernel file via TFTP");
    let ilen = base_code
        .tftp_read_file(&server_ip, initrd_filename, Some(&mut initrd_data))
        .expect("Failed to read initrd file via TFTP");

    assert!(klen > 0, "TFTP read operation returned 0 bytes for kernel file");
    assert!(ilen > 0, "TFTP read operation returned 0 bytes for initrd file");

    Ok((kernel_data, initrd_data))
}

pub fn boot_linux(handle: Handle, _dynamic_initrds: Vec<Vec<u8>>) -> uefi::Result<()> {
    // NOTE: Dynamic initrds (system extensions, credentials) are not supported in netboot mode.
    // This matches the netboot branch implementation which removed this functionality.
    // The parameter is kept for API compatibility but is unused.
    // SAFETY: We get a slice that represents our currently running
    // image and then parse the PE data structures from it. This is
    // safe, because we don't touch any data in the data sections that
    // might conceivably change while we look at the slice.
    let config = unsafe {
        EmbeddedConfiguration::new(
            booted_image_file()
                .unwrap()
                .as_slice(),
        )
        .expect("Failed to extract configuration from binary. Did you run lzbt?")
    };

    let secure_boot_enabled = get_secure_boot_status();

    let kernel_data;
    let initrd_data;

    {
        // Try to read from filesystem first
        let file_system_result = uefi::boot::get_image_file_system(handle);
        
        if let Ok(file_system_handle) = file_system_result {
            let mut file_system = FileSystem::new(file_system_handle);
            
            // Try to read kernel and initrd from filesystem
            if let (Ok(kernel), Ok(initrd)) = (
                file_system.read(&*config.kernel_filename),
                file_system.read(&*config.initrd_filename)
            ) {
                // Successfully read from filesystem
                kernel_data = kernel;
                initrd_data = initrd;
            } else {
                // Files not found on filesystem, try network boot
                warn!("Failed to read kernel/initrd from filesystem, attempting network boot via TFTP");
                (kernel_data, initrd_data) = load_via_tftp(handle)?;
            }
        } else {
            // Filesystem unavailable, try network boot
            warn!("Filesystem unavailable, attempting network boot via TFTP");
            (kernel_data, initrd_data) = load_via_tftp(handle)?;
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

    boot_linux_unchecked(handle, kernel_data, &cmdline, initrd_data)
}
