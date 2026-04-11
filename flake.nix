{
  description = "ebpfview — zero-instrumentation eBPF observability CLI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Go toolchain
            go_1_22

            # BPF toolchain
            clang_17
            llvm_17
            bpftools

            # Code generation
            # bpf2go is installed via `go install` — see Makefile

            # Testing
            qemu

            # Linting
            golangci-lint

            # Utilities
            gnumake
            pkg-config
          ];

          shellHook = ''
            echo "ebpfview dev environment loaded"
            echo "Go: $(go version)"
            echo "Clang: $(clang --version | head -1)"
          '';
        };
      }
    );
}
