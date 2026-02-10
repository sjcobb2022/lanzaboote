{
  lanzabooteModule,
  pkgs,
  lib,
  ...
}:
let
  sortKey = "mySpecialSortKey";
in
{
  name = "lanzaboote";

  nodes.machine = {
    imports = [
      (import ./common/netboot.nix { inherit lanzabooteModule pkgs lib; })
      ./common/lanzaboote.nix
    ];

    boot.lanzaboote = { inherit sortKey; };
  };

  testScript =
    { nodes, ... }:
    (import ./common/netboot-helper.nix { inherit (nodes) machine; })
    + ''
      # We should immediately start and boot from the tftp server with a netbooted image.
      machine.start()
      bootctl_status = machine.succeed("bootctl status")
      print(bootctl_status)
      t.assertIn("Secure Boot: enabled (user)", bootctl_status)
    '';
}
