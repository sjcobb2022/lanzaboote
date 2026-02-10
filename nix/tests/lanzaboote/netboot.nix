{
  pkgs,
  lib,
  evalConfig,
  modulesPath,
  ...
}: let
  sortKey = "mySpecialSortKey";
  lanzabooteNetbootFile = "netlanzaboote.efi";

  lanzabooteNetbootSystem =
    (evalConfig {
      inherit (pkgs) system;
      modules = [
        "${modulesPath}/installer/netboot/netboot.nix"
        ({
          config,
          pkgs,
          ...
        }: {
          # We refer to our own NixOS module package rather than pkgs.lzbt
          # which does not exist in general.
          # As the flake.nix defines the package in an ad-hoc fashion
          # rather than using overlays which may not propagate here I guess?
          system.build.netbootStub = pkgs.runCommand "build-netboot-stub" {} ''
            mkdir -p $out
            ${config.boot.lanzaboote.package}/bin/lzbt \
              build \
              --public-key ${../fixtures/uefi-keys/keys/db/db.pem} \
              --private-key ${../fixtures/uefi-keys/keys/db/db.key} \
              --initrd ${config.system.build.netbootRamdisk}/initrd \
              ${config.system.build.toplevel} > $out/${lanzabooteNetbootFile}
          '';
        })
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
in {
  name = "lanzaboote";

  nodes.machine = {
    imports = [
      ./common/lanzaboote.nix
      "${modulesPath}/image/repart.nix"
    ];

    # We don't want a filesystem if netbooting.
    fileSystems = lib.mkForce {};

    # Override repart because we don't need it
    image.repart = lib.mkForce {};

    virtualisation = {
      diskImage = null;

      # TFTP settings for netbooting form qemu's built in system.
      qemu.networkingOptions = lib.mkForce [
        "-net nic,netdev=user.0,model=virtio"
        "-netdev user,id=user.0,tftp=${lanzabooteNetbootTree},bootfile=${lanzabooteNetbootFile},\${QEMU_NET_OPTS:+,$QEMU_NET_OPTS}"
      ];
    };

    boot.lanzaboote = {inherit sortKey;};
  };

  testScript = _: ''
    import os
    os.environ['QEMU_NET_OPTS'] = ','.join(os.environ.get('QEMU_NET_OPTS', "").split(',') + ["tftp=${lanzabooteNetbootTree}", "bootfile=/${lanzabooteNetbootFile}"])

    # We should immediately start and boot from the tftp server with a netbooted image.
    machine.start()
    bootctl_status = machine.succeed("bootctl status")
    print(bootctl_status)
    t.assertIn("Secure Boot: enabled (user)", bootctl_status)
  '';
}
