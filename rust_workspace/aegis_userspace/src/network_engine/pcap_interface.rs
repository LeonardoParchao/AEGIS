use libpcap::{Capture, Device};
use anyhow::Result;

pub struct PcapInjector {
    device: Device,
    capture: Option<Capture<libpcap::Active>>,
}

impl PcapInjector {
    pub fn new(interface_name: &str) -> Result<Self> {
        let device = Device::lookup()
            .ok_or_else(|| anyhow::anyhow!("No network devices found"))?
            .into_iter()
            .find(|d| d.name == interface_name)
            .ok_or_else(|| anyhow::anyhow!("Interface {} not found", interface_name))?;

        Ok(PcapInjector {
            device,
            capture: None,
        })
    }

    pub fn open(&mut self) -> Result<()> {
        let cap = Capture::from_device(self.device.clone())?
            .promisc(true)
            .snaplen(65535)
            .timeout(1000)
            .open()?;
        
        self.capture = Some(cap);
        Ok(())
    }

    pub fn inject_packet(&mut self, packet_data: &[u8]) -> Result<usize> {
        if let Some(capture) = &mut self.capture {
            capture.sendpacket(packet_data)?;
            Ok(packet_data.len())
        } else {
            Err(anyhow::anyhow!("Capture not opened"))
        }
    }

    pub fn close(&mut self) {
        self.capture = None;
    }
}

impl Drop for PcapInjector {
    fn drop(&mut self) {
        self.close();
    }
}
