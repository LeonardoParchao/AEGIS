use aya_ebpf::programs::TracePointContext;

const SUSPICIOUS_IP_RANGES: [&[u8]; 2] = [
    &[10, 0, 0, 0],    // 10.0.0.0/8
    &[192, 168, 0, 0], // 192.168.0.0/16
];

#[no_mangle]
pub fn tcp_v4_connect(ctx: TracePointContext) -> i32 {
    match try_tcp_v4_connect(ctx) {
        Ok(_) => 0,
        Err(_) => 1
    }
}

fn try_tcp_v4_connect(ctx: TracePointContext) -> Result<(), i32> {
    // SECURITY NOTE: Fixed offset memory access is architecture-dependent
    // Offset 16 is for x86_64 tcp_v4_connect tracepoint. This may need adjustment
    // for other architectures. Consider using aya_ebpf's tracepoint argument bindings
    // for production use to read arguments by name instead of offset.
    let sock_addr = unsafe {
        ctx.read_at::<[u8; 16]>(16).map_err(|_| 0)?
    };

    let ip = &sock_addr[4..8];
    
    for suspicious_range in SUSPICIOUS_IP_RANGES.iter() {
        if is_in_subnet(ip, suspicious_range) {
            // info!(&ctx, "SSRF detected: Connecting to internal IP {}.{}.{}.{}", 
            //       ip[0], ip[1], ip[2], ip[3]);
            return Ok(());
        }
    }

    Ok(())
}

fn is_in_subnet(ip: &[u8], subnet_start: &[u8]) -> bool {
    if ip.len() != 4 || subnet_start.len() != 4 {
        return false;
    }

    match subnet_start {
        [10, 0, 0, 0] => ip[0] == 10,
        [192, 168, 0, 0] => ip[0] == 192 && ip[1] == 168,
        _ => false
    }
}
