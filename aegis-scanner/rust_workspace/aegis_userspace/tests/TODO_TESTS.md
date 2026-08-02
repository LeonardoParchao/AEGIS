# HTTP Connection Pooling and PCAP Injection Tests

This directory contains comprehensive unit tests for HTTP connection pooling and PCAP injection memory safety.

## Test Implementation

The tests have been implemented in `http_pcap_tests.rs` and cover:

### HTTP Connection Pooling Tests
- Default and custom timeout client creation
- Connection pool configuration validation
- Multiple concurrent client instances
- Thread-safe client creation
- Various timeout value configurations
- Client cloning safety for connection reuse

### PCAP Injection Memory Safety Tests
- Valid and invalid interface name handling
- Drop trait safety and resource cleanup
- Packet injection boundary conditions (empty, large, oversized packets)
- Multiple sequential injections
- Concurrent injector creation
- Interface name edge cases (special characters, null bytes, very long names)
- Memory leak prevention through repeated creation/destruction
- Double drop protection

### Integration Tests
- HTTP client and PCAP injector coexistence
- Multiple HTTP clients with PCAP injector
- Resource cleanup order verification

## Running the Tests

```bash
cargo test --package aegis_userspace
```

## Notes

- Some PCAP tests may fail if network interfaces don't exist on the test system
- The tests are designed to fail gracefully rather than crash on missing resources
- Memory safety is verified through boundary testing and resource cleanup validation
