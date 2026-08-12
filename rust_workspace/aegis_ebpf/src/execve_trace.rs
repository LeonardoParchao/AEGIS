use aya_ebpf::programs::TracePointContext;

// Security: Use a more specific marker to reduce false positives and bypass potential
const AEGIS_MARKER: &[u8] = b"AEGIS-SCAN-MARKER-v1";

#[no_mangle]
pub fn sys_enter_execve(ctx: TracePointContext) -> i32 {
    match try_sys_enter_execve(ctx) {
        Ok(_) => 0,
        Err(_) => 1
    }
}

fn try_sys_enter_execve(ctx: TracePointContext) -> Result<(), i32> {
    // SECURITY NOTE: Fixed offset memory access is architecture-dependent
    // Offset 16 is for x86_64 sys_enter_execve tracepoint. This may need adjustment
    // for other architectures. Consider using aya_ebpf's tracepoint argument bindings
    // for production use to read arguments by name instead of offset.
    let filename = unsafe {
        let ptr = ctx.read_at::<*const u8>(16).map_err(|_| 0)?;
        // Add null pointer check for safety
        if ptr.is_null() {
            return Err(0);
        }
        core::ffi::CStr::from_ptr(ptr as *const i8)
    };

    let filename_bytes = filename.to_bytes();
    
    if contains_substring(filename_bytes, AEGIS_MARKER) {
        // info!(&ctx, "AEGIS marker detected in execve: {}", filename.to_str().unwrap_or("<invalid>"));
    }

    Ok(())
}

fn contains_substring(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }

    for i in 0..=(haystack.len() - needle.len()) {
        let mut match_found = true;
        for j in 0..needle.len() {
            if haystack[i + j] != needle[j] {
                match_found = false;
                break;
            }
        }
        if match_found {
            return true;
        }
    }

    false
}
