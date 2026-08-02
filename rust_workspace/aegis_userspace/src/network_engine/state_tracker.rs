use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

#[derive(Debug, Clone)]
pub struct ConnectionState {
    pub local_addr: SocketAddr,
    pub remote_addr: Option<SocketAddr>,
    pub state: TcpState,
    pub last_activity: u64,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
}

#[derive(Debug)]
pub struct NetworkStateTracker {
    connections: HashMap<String, ConnectionState>,
}

impl NetworkStateTracker {
    pub fn new() -> Self {
        NetworkStateTracker {
            connections: HashMap::new(),
        }
    }

    pub fn track_connection(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: Option<SocketAddr>,
        initial_state: TcpState,
    ) {
        let key = self.connection_key(local_addr, remote_addr);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let state = ConnectionState {
            local_addr,
            remote_addr,
            state: initial_state,
            last_activity: now,
            sequence_number: 0,
            acknowledgment_number: 0,
        };

        self.connections.insert(key, state);
    }

    pub fn update_state(&mut self, local_addr: SocketAddr, remote_addr: Option<SocketAddr>, new_state: TcpState) {
        let key = self.connection_key(local_addr, remote_addr);
        if let Some(state) = self.connections.get_mut(&key) {
            state.state = new_state;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            state.last_activity = now;
        }
    }

    pub fn get_state(&self, local_addr: SocketAddr, remote_addr: Option<SocketAddr>) -> Option<&ConnectionState> {
        let key = self.connection_key(local_addr, remote_addr);
        self.connections.get(&key)
    }

    pub fn cleanup_stale_connections(&mut self, timeout_secs: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.connections.retain(|_, state| {
            now - state.last_activity < timeout_secs
        });
    }

    pub fn detect_state_flaws(&self) -> Vec<String> {
        let mut flaws = Vec::new();

        for (_, state) in &self.connections {
            // Detect connections stuck in non-established states
            match state.state {
                TcpState::SynSent | TcpState::SynReceived => {
                    flaws.push(format!(
                        "Connection {:?} stuck in handshake state: {:?}",
                        state.local_addr, state.state
                    ));
                }
                TcpState::FinWait1 | TcpState::FinWait2 | TcpState::Closing => {
                    flaws.push(format!(
                        "Connection {:?} stuck in termination state: {:?}",
                        state.local_addr, state.state
                    ));
                }
                _ => {}
            }
        }

        flaws
    }

    fn connection_key(&self, local_addr: SocketAddr, remote_addr: Option<SocketAddr>) -> String {
        match remote_addr {
            Some(remote) => format!("{} -> {}", local_addr, remote),
            None => format!("{}", local_addr),
        }
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }
}

impl Default for NetworkStateTracker {
    fn default() -> Self {
        Self::new()
    }
}
