use aya::{Bpf, maps::RingBuffer, programs::TracePoint};
use anyhow::Result;
use std::fs;

pub struct AyaLoader {
    bpf: Option<Bpf>,
    ring_buffer: Option<RingBuffer>,
}

impl AyaLoader {
    pub fn new() -> Self {
        AyaLoader {
            bpf: None,
            ring_buffer: None,
        }
    }

    pub fn load(&mut self, ebpf_path: &str) -> Result<()> {
        // Load the eBPF bytecode
        let bpf = Bpf::load(ebpf_path)?;
        self.bpf = Some(bpf);
        Ok(())
    }

    pub fn attach_tracepoint(&mut self, category: &str, name: &str) -> Result<()> {
        if let Some(bpf) = &self.bpf {
            let program: &mut TracePoint = bpf.program_mut("aegis_entry")?;
            program.load()?;
            program.attach(category, name)?;
        }
        Ok(())
    }

    pub fn poll_ring_buffer(&mut self, callback: Box<dyn Fn(&[u8])>) -> Result<()> {
        if let Some(bpf) = &self.bpf {
            let mut ring_buffer = RingBuffer::from_iter(bpf.maps_mut().iter())?;
            
            // Poll the ring buffer (simplified - in real implementation this would be async)
            while let Some(data) = ring_buffer.next() {
                callback(data);
            }
            
            self.ring_buffer = Some(ring_buffer);
        }
        Ok(())
    }

    pub fn check_for_marker(&mut self, marker: &[u8]) -> Result<bool> {
        let mut found = false;
        
        if let Some(bpf) = &self.bpf {
            let mut ring_buffer = RingBuffer::from_iter(bpf.maps_mut().iter())?;
            
            while let Some(data) = ring_buffer.next() {
                if data.contains(marker) {
                    found = true;
                    break;
                }
            }
            
            self.ring_buffer = Some(ring_buffer);
        }
        
        Ok(found)
    }

    pub fn unload(&mut self) {
        self.ring_buffer = None;
        self.bpf = None;
    }
}

impl Drop for AyaLoader {
    fn drop(&mut self) {
        self.unload();
    }
}

impl Default for AyaLoader {
    fn default() -> Self {
        Self::new()
    }
}
