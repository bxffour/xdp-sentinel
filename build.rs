fn main() {
    #[cfg(target_os = "linux")]
    bpf::generate();
}

mod bpf {
    use libbpf_cargo::SkeletonBuilder;
    use std::env;
    use std::path::PathBuf;

    const SRC: &str = "src/bpf/xdp_blocker.bpf.c";

    pub fn generate() {
        let out = PathBuf::from(
            env::var_os("CARGO_MANIFEST_DIR")
                .expect("CARGO_MANIFEST_DIR must be set in build script"),
        )
        .join("src")
        .join("bpf")
        .join("xdp_blocker.skel.rs");

        let target_arch = env::var("CARGO_CFG_TARGET_ARCH")
            .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

        if target_arch == "x86_64" {
            SkeletonBuilder::new()
                .source(&SRC)
                .clang_args([
                    "-Isrc/common/bpf/x86_64",
                    "-I/usr/include/x86_64-linux-gnu",
                    "-fno-unwind-tables",
                    "-D__TARGET_ARCH_x86",
                ])
                .build_and_generate(&out)
                .unwrap();
        } else if target_arch == "aarch64" {
            SkeletonBuilder::new()
                .source(&SRC)
                .clang_args([
                    "-Isrc/common/bpf/aarch64",
                    "-I/usr/include/aarch64-linux-gnu",
                    "-fno-unwind-tables",
                    "-D__TARGET_ARCH_arm64",
                ])
                .build_and_generate(&out)
                .unwrap();
        } else {
            panic!("BPF support only available for x86_64 and aarch64 architectures");
        }

        println!("cargo:rerun-if-changed={SRC}");

        // println!("cargo:rerun-if-changed=src/common/bpf/histogram.h");
        println!("cargo:rerun-if-changed=src/common/bpf/vmlinux.h");
    }
}
