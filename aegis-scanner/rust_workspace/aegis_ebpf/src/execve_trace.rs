use aya_ebpf::programs::TracePointContext;

const AEGIS_MARKER: &[u8] = b"AEGIS";

#[no_mangle]
pub fn sys_enter_execve(ctx: TracePointContext) -> i32 {
    match try_sys_enter_execve(ctx) {
        Ok(_) => 0,
        Err(_) => 1
    }
}

fn try_sys_enter_execve(ctx: TracePointContext) -> Result<(), i32> {
    let filename = unsafe {
        let ptr = ctx.read_at::<*const u8>(16).map_err(|_| 0)?;
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
