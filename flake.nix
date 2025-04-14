{
  description = "CRIU development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # Dependencies for CRIU
        criuDeps = with pkgs; [
          # Compiler and build essentials
          gcc
          gnumake
          pkg-config

          # Protocol Buffers
          protobuf
          protobufc
          python3Packages.protobuf

          # Other required libraries
          libuuid
          libbsd
          iproute2
          nftables
          libcap
          libnet
          libnl
          libaio
          gnutls
          libdrm

          # ZDTM
          python3Packages.pyyaml
        ];

        # Multilib support for 32-bit compatibility
        # criuDeps32bit = with pkgs; [
        #   glibc.dev
        #   glibc
        #   gcc-unwrapped
        # ];

        devShell = pkgs.mkShell {
          buildInputs = criuDeps; # ++ (if pkgs.stdenv.isx86_64 then criuDeps32bit else []);

          shellHook = ''
            echo "CRIU development environment"
            echo "=============================="
            echo ""
            echo "Useful commands:"
            echo "  make - Build CRIU"
            echo "  make test - Run tests (requires ZDTM dependencies)"
            echo ""
          '';

          # Add proper flags for multilib support
          # NIX_CFLAGS_COMPILE = pkgs.lib.optional pkgs.stdenv.isx86_64 "-m32";

          # Make sure the shell can find headers for multilib
          # PKG_CONFIG_PATH = pkgs.lib.makeSearchPath "lib/pkgconfig" criuDeps;
        };
      in
      {
        # Export the development shell
        devShells.default = devShell;

        # Build CRIU package as well
        packages.default = pkgs.criu;
      }
    );
}
