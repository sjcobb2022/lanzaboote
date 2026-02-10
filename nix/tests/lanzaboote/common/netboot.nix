{
  pkgs,
  lib,
  lanzabooteModule,
  ...
}:
let
  lanzabooteNetbootFile = "netlanzaboote.efi";

  evalConfig = import (pkgs.path + "/nixos/lib/eval-config.nix");

  lanzabooteNetbootSystem =
    (evalConfig {
      inherit (pkgs) system;
      modules = [
        (
          {
            config,
            pkgs,
            modulesPath,
            ...
          }:
          {
            imports = [
              "${modulesPath}/installer/netboot/netboot.nix"
              lanzabooteModule
            ];

            # We refer to our own NixOS module package rather than pkgs.lzbt
            # which does not exist in general.
            # As the flake.nix defines the package in an ad-hoc fashion
            # rather than using overlays which may not propagate here I guess?
            system.build.netbootStub = pkgs.runCommand "build-netboot-stub" { } ''
              mkdir -p $out
              ln -s ${config.system.build.toplevel} system-1-link
              ${config.boot.lanzaboote.package}/bin/lzbt \
                build \
                --system ${config.boot.kernelPackages.stdenv.hostPlatform.system} \
                --public-key ${../../fixtures/uefi-keys/keys/db/db.pem} \
                --private-key ${../../fixtures/uefi-keys/keys/db/db.key} \
                --initrd ${config.system.build.netbootRamdisk}/initrd \
                system-1-link > $out/${lanzabooteNetbootFile}
            '';
          }
        )
      ];
    }).config.system;

  lanzabooteNetbootTree = pkgs.symlinkJoin {
    name = "pxeBootDir";
    paths = [
      lanzabooteNetbootSystem.build.netbootRamdisk
      lanzabooteNetbootSystem.build.kernel
      # Lanzaboote stub for netboot purposes
      lanzabooteNetbootSystem.build.netbootStub
    ];
  };
  # TODO: REPART CONFIG
in
{
  options.lanzabooteTest = {
    netbootTree = lib.mkOption { };
    netbootFile = lib.mkOption { };
  };

  config = {
    # TODO: Determine if custom options are the best thing for this.
    lanzabooteTest.netbootTree = lanzabooteNetbootTree;
    lanzabooteTest.netbootFile = lanzabooteNetbootFile;

    # TODO: Perhaps disable disk as well. (only tmpfs root).

    virtualisation = {
      diskImage = lib.mkForce null;

      # TFTP settings for netbooting form qemu's built in system.
      qemu.networkingOptions = lib.mkForce [
        "-net nic,netdev=user.0,model=virtio"
        "-netdev user,id=user.0,tftp=${lanzabooteNetbootTree},bootfile=${lanzabooteNetbootFile},\${QEMU_NET_OPTS:+,$QEMU_NET_OPTS}"
      ];
    };
  };
}
