use std::{
    ffi::OsStr,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use base32ct::{Base32Unpadded, Encoding};
use clap::{Parser, Subcommand};
use tempfile::TempDir;

use crate::{
    esp::SystemdEspPaths,
    install::{self},
};
use lanzaboote_tool::{
    architecture::Architecture,
    esp::EspPaths,
    generation::{Generation, GenerationLink},
    os_release::OsRelease,
    pe::StubParameters,
    signature::{EmptyKeyPair, LocalKeyPair, Signer},
    utils::{assemble_kernel_cmdline, file_hash, install as install_to},
};

/// The default log level.
///
/// 2 corresponds to the level INFO.
const DEFAULT_LOG_LEVEL: usize = 2;

#[derive(Parser)]
pub struct Cli {
    /// Silence all output
    #[arg(short, long)]
    quiet: bool,
    /// Verbose mode (-v, -vv, etc.)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    #[clap(subcommand)]
    commands: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Install(InstallCommand),
    Build(BuildCommand),
}

#[derive(Parser)]
struct InstallCommand {
    /// System for lanzaboote binaries, e.g. defines the EFI fallback path
    #[arg(long)]
    system: String,

    /// Systemd path
    #[arg(long)]
    systemd: PathBuf,

    /// Systemd-boot loader config
    #[arg(long)]
    systemd_boot_loader_config: PathBuf,

    /// Allow installing unsigned artifacts
    #[arg(long, num_args = 1)]
    allow_unsigned: bool,

    /// sbsign Public Key
    #[arg(long)]
    public_key: Option<PathBuf>,

    /// sbsign Private Key
    #[arg(long)]
    private_key: Option<PathBuf>,

    /// Configuration limit
    #[arg(long, default_value_t = 1)]
    configuration_limit: usize,

    /// Initial number of boot counting tries, set to zero to disable boot counting
    #[arg(long, default_value_t = 0)]
    bootcounting_initial_tries: u32,

    /// EFI system partition mountpoint (e.g. efiSysMountPoint)
    esp: PathBuf,

    /// List of generation links (e.g. /nix/var/nix/profiles/system-*-link)
    generations: Vec<PathBuf>,
}

#[derive(Parser)]
struct BuildCommand {
    /// System for lanzaboote binaries, e.g. defines the EFI fallback path
    #[arg(long)]
    system: String,

    /// sbsign Public Key
    #[arg(long)]
    public_key: PathBuf,

    /// sbsign Private Key
    #[arg(long)]
    private_key: PathBuf,

    /// Override initrd
    #[arg(long)]
    initrd: PathBuf,

    /// Generation
    generation: PathBuf,
}

impl Cli {
    pub fn call(self, module: &str) {
        stderrlog::new()
            .module(module)
            .show_level(false)
            .quiet(self.quiet)
            .verbosity(DEFAULT_LOG_LEVEL + usize::from(self.verbose))
            .init()
            .expect("Failed to setup logger.");

        if let Err(e) = self.commands.call() {
            log::error!("{e:#}");
            std::process::exit(1);
        };
    }
}

impl Commands {
    pub fn call(self) -> Result<()> {
        match self {
            Commands::Install(args) => install(args),
            Commands::Build(args) => build(args),
        }
    }
}

fn install(args: InstallCommand) -> Result<()> {
    let lanzaboote_stub =
        std::env::var("LANZABOOTE_STUB").context("Failed to read LANZABOOTE_STUB env variable")?;

    let public_key = &args.public_key.expect("Failed to obtain public key");
    let private_key = &args.private_key.expect("Failed to obtain private key");

    let installer_builder = install::InstallerBuilder::new(
        lanzaboote_stub,
        Architecture::from_nixos_system(&args.system)?,
        args.systemd,
        args.systemd_boot_loader_config,
        args.configuration_limit,
        args.bootcounting_initial_tries,
        args.esp,
        args.generations,
    );

    if args.allow_unsigned
        && std::fs::exists(public_key).ok().is_none_or(|b| !b)
        && std::fs::exists(private_key).ok().is_none_or(|b| !b)
    {
        log::warn!("No keys provided. Installing unsigned artifacts.");
        let signer = EmptyKeyPair;
        installer_builder.build(signer).install()
    } else {
        let signer = LocalKeyPair::new(public_key, private_key);
        installer_builder.build(signer).install()
    }
}

fn build(args: BuildCommand) -> Result<()> {
    let lanzaboote_stub = PathBuf::from(
        std::env::var("LANZABOOTE_STUB").context("Failed to read LANZABOOTE_STUB env variable")?,
    );

    let public_key = &args.public_key;
    let private_key = &args.private_key;
    let signer = LocalKeyPair::new(public_key, private_key);

    let link = GenerationLink::from_path(&args.generation).with_context(|| {
        format!(
            "Failed to build generation from link: {0:?}",
            args.generation
        )
    })?;

    let generation = Generation::from_link(&link)?;
    let bootspec = &generation.spec.bootspec.bootspec;

    let tempdir = TempDir::new().context("Failed to create temporary directory")?;
    let os_release = OsRelease::from_generation(&generation)
        .context("Failed to build OsRelease from generation.")?;
    let os_release_contents = os_release.to_string();

    let arch = Architecture::from_nixos_system(&args.system)?;
    let mut esp = crate::esp::SystemdEspPaths::new("/", arch);

    let kernel_cmdline = assemble_kernel_cmdline(&bootspec.init, bootspec.kernel_params.clone());

    let kernel_dirname = bootspec
        .kernel
        .parent()
        .and_then(Path::file_name)
        .and_then(OsStr::to_str)
        .context("Failed to extract the kernel directory name.")?;

    let kernel_version = kernel_dirname
        .rsplit('-')
        .next()
        .context("Failed to extract the kernel version.")?;

    let kernel_target = install_ca(
        &mut esp,
        &bootspec.kernel,
        &format!("kernel-{}", kernel_version),
    )
    .context("Failed to install the kernel.")?;

    let initrd = bootspec
        .initrd
        .clone()
        .expect("Lanzaboote does not support missing initrd yet.");

    let initrd_target = install_ca(&mut esp, &initrd, &format!("initrd-{}", kernel_version))
        .context("Failed to install the initrd.")?;

    let stub_parameters = StubParameters::new(
        lanzaboote_stub.as_path(),
        &bootspec.kernel,
        &initrd,
        &kernel_target,
        &initrd_target,
        &esp.esp,
    )?
    .with_cmdline(&kernel_cmdline)
    .with_os_release_contents(os_release_contents.as_bytes());

    let lzbt_stub = lanzaboote_tool::pe::lanzaboote_image(&tempdir, &stub_parameters)?;

    let to = tempdir.path().join("signed-lzbt-stub.efi");

    signer
        .sign_and_copy(&lzbt_stub, &to)
        .with_context(|| format!("Failed to copy and sign file {lzbt_stub:?} to {to:?}"))?;

    std::io::stdout().write_all(&std::fs::read(to)?)?;

    Ok(())
}

fn install_ca(esp: &mut SystemdEspPaths, from: &Path, label: &str) -> Result<PathBuf> {
    let hash = file_hash(from).context("Failed to read the source file.")?;
    let to = esp.nixos.join(format!(
        "{}-{}.efi",
        label,
        Base32Unpadded::encode_string(&hash)
    ));

    install_to(from, &to)?;
    Ok(to)
}
