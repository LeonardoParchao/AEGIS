use std::path::PathBuf;

fn main() {
    // Tell cargo to invalidate the built crate whenever the eBPF program changes
    println!("cargo:rerun-if-changed=../aegis_ebpf/target/bpfel-unknown-none/release/aegis_ebpf");
    
    // Get the eBPF program path
    let ebpf_path = PathBuf::from("../aegis_ebpf/target/bpfel-unknown-none/release/aegis_ebpf");
    
    if ebpf_path.exists() {
        println!("cargo:rustc-env=EBPF_PATH={}", ebpf_path.display());
    } else {
        println!("cargo:warning=eBPF program not found at {}. Run 'cargo build --release' in aegis_ebpf first.", ebpf_path.display());
    }
}