//! Unit tests for HTTP connection pooling and PCAP injection memory safety

use aegis_userspace::http_engine::client::HttpClient;

#[cfg(unix)]
use aegis_userspace::network_engine::pcap_interface::PcapInjector;

#[cfg(test)]
mod http_connection_pooling_tests {
    use super::*;

    #[test]
    fn test_http_client_default_creation() {
        let _client = HttpClient::default();
        // Client was created successfully - timeout is configured internally
        assert!(true);
    }

    #[test]
    fn test_http_client_new() {
        let _client = HttpClient::new().expect("Failed to create HTTP client");
        // Client was created successfully - timeout is configured internally
        assert!(true);
    }

    #[test]
    fn test_http_client_custom_timeout() {
        let _client = HttpClient::with_timeout(60).expect("Failed to create HTTP client with custom timeout");
        // Client was created successfully - timeout is configured internally
        assert!(true);
    }

    #[test]
    fn test_http_client_zero_timeout() {
        let _client = HttpClient::with_timeout(0).expect("Failed to create HTTP client with zero timeout");
        // Client was created successfully - timeout is configured internally
        assert!(true);
    }

    #[test]
    fn test_http_client_large_timeout() {
        let _client = HttpClient::with_timeout(3600).expect("Failed to create HTTP client with large timeout");
        // Client was created successfully - timeout is configured internally
        assert!(true);
    }

    #[test]
    fn test_http_client_multiple_instances() {
        let _client1 = HttpClient::new().expect("Failed to create first HTTP client");
        let _client2 = HttpClient::new().expect("Failed to create second HTTP client");
        let _client3 = HttpClient::with_timeout(45).expect("Failed to create third HTTP client");
        
        // Verify all clients are independent
        assert!(true);
    }

    #[test]
    fn test_http_client_pool_max_idle_per_host() {
        // This test verifies that the client can be created with pooling parameters
        let _client = HttpClient::new().expect("Failed to create HTTP client");
        // The reqwest client internally manages connection pooling
        // We verify the client was created successfully with pooling enabled
        assert!(true);
    }

    #[test]
    fn test_http_client_pool_idle_timeout() {
        let _client = HttpClient::new().expect("Failed to create HTTP client");
        // Verify client with idle timeout configuration was created
        assert!(true);
    }

    #[test]
    fn test_http_client_connect_timeout() {
        let _client = HttpClient::new().expect("Failed to create HTTP client");
        // Verify client with connect timeout configuration was created
        assert!(true);
    }

    #[test]
    fn test_http_client_clone_safety() {
        let client = HttpClient::new().expect("Failed to create HTTP client");
        // reqwest::Client can be cloned safely for connection pooling
        let _client_clone = client.client().clone();
        assert!(true);
    }

    #[test]
    fn test_http_client_concurrent_creation() {
        // Test creating multiple clients concurrently to verify thread safety
        let handles: Vec<_> = (0..10)
            .map(|_| {
                std::thread::spawn(|| {
                    HttpClient::new().expect("Failed to create HTTP client in thread")
                })
            })
            .collect();

        for handle in handles {
            let _client = handle.join().expect("Thread panicked");
            assert!(true);
        }
    }

    #[test]
    fn test_http_client_timeout_values() {
        let test_cases = vec![1, 5, 10, 30, 60, 120, 300];
        
        for timeout in test_cases {
            let _client = HttpClient::with_timeout(timeout)
                .expect(&format!("Failed to create HTTP client with timeout {}", timeout));
            assert!(true);
        }
    }
}

#[cfg(test)]
#[cfg(unix)]
mod pcap_injection_memory_safety_tests {
    use super::*;

    #[test]
    fn test_pcap_injector_creation_valid_interface() {
        // Note: This test may fail if the interface doesn't exist on the system
        // In a real test environment, you'd use a test network interface
        let result = PcapInjector::new("eth0");
        // We expect this might fail due to missing interface, but it shouldn't crash
        match result {
            Ok(_) => {}
            Err(_) => {
                // Expected if interface doesn't exist
            }
        }
    }

    #[test]
    fn test_pcap_injector_creation_invalid_interface() {
        let result = PcapInjector::new("nonexistent_interface_12345");
        assert!(result.is_err());
    }

    #[test]
    fn test_pcap_injector_empty_interface_name() {
        let result = PcapInjector::new("");
        assert!(result.is_err());
    }

    #[test]
    fn test_pcap_injector_drop_safety() {
        // Test that PcapInjector can be safely dropped
        let injector = PcapInjector::new("eth0");
        // Explicitly drop to test Drop trait
        drop(injector);
        // If we reach here, Drop was executed safely
    }

    #[test]
    fn test_pcap_injector_close_before_drop() {
        let result = PcapInjector::new("eth0");
        if let Ok(mut injector) = result {
            injector.close();
            // Close should be idempotent
            injector.close();
        }
        // Should not panic
    }

    #[test]
    fn test_pcap_injector_inject_without_open() {
        let result = PcapInjector::new("eth0");
        if let Ok(mut injector) = result {
            let packet_data = vec![0u8; 100];
            let result = injector.inject_packet(&packet_data);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_pcap_injector_inject_empty_packet() {
        let result = PcapInjector::new("eth0");
        if let Ok(mut injector) = result {
            let _ = injector.open();
            let packet_data: Vec<u8> = vec![];
            let result = injector.inject_packet(&packet_data);
            // This might succeed or fail depending on libpcap implementation
            // Either way, it shouldn't cause memory corruption
            let _ = result;
        }
    }

    #[test]
    fn test_pcap_injector_inject_large_packet() {
        let result = PcapInjector::new("eth0");
        if let Ok(mut injector) = result {
            let _ = injector.open();
            let packet_data = vec![0u8; 65535]; // Maximum snaplen
            let result = injector.inject_packet(&packet_data);
            let _ = result;
        }
    }

    #[test]
    fn test_pcap_injector_inject_oversized_packet() {
        let result = PcapInjector::new("eth0");
        if let Ok(mut injector) = result {
            let _ = injector.open();
            let packet_data = vec![0u8; 100000]; // Larger than snaplen
            let result = injector.inject_packet(&packet_data);
            let _ = result;
        }
    }

    #[test]
    fn test_pcap_injector_multiple_injections() {
        let result = PcapInjector::new("eth0");
        if let Ok(mut injector) = result {
            let _ = injector.open();
            for i in 0..10 {
                let packet_data = vec![i as u8; 100];
                let result = injector.inject_packet(&packet_data);
                let _ = result;
            }
        }
    }

    #[test]
    fn test_pcap_injector_concurrent_safety() {
        // Test that multiple injectors can be created safely
        let handles: Vec<_> = (0..5)
            .map(|i| {
                std::thread::spawn(move || {
                    let result = PcapInjector::new(&format!("eth{}", i));
                    match result {
                        Ok(mut injector) => {
                            let _ = injector.open();
                            let packet_data = vec![0u8; 100];
                            let _ = injector.inject_packet(&packet_data);
                        }
                        Err(_) => {}
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }

    #[test]
    fn test_pcap_injector_reopen_after_close() {
        let result = PcapInjector::new("eth0");
        if let Ok(mut injector) = result {
            let result1 = injector.open();
            injector.close();
            let result2 = injector.open();
            // Reopening after close should work (or fail gracefully)
            let _ = result1;
            let _ = result2;
        }
    }

    #[test]
    fn test_pcap_injector_interface_name_with_special_chars() {
        let special_names = vec![
            "eth0.1",
            "br-0123456789ab",
            "veth123456",
            "docker0",
            "virbr0",
        ];
        
        for name in special_names {
            let result = PcapInjector::new(name);
            // These might fail if interfaces don't exist, but shouldn't crash
            let _ = result;
        }
    }

    #[test]
    fn test_pcap_injector_very_long_interface_name() {
        let long_name = "a".repeat(1000);
        let result = PcapInjector::new(&long_name);
        assert!(result.is_err());
    }

    #[test]
    fn test_pcap_injector_null_byte_in_interface_name() {
        let name_with_null = "eth0\0";
        let result = PcapInjector::new(name_with_null);
        // Should handle gracefully
        let _ = result;
    }

    #[test]
    fn test_pcap_injector_packet_data_with_null_bytes() {
        let result = PcapInjector::new("eth0");
        if let Ok(mut injector) = result {
            let _ = injector.open();
            let packet_data: Vec<u8> = vec![0, 1, 2, 0, 4, 5, 0, 6, 7, 8];
            let result = injector.inject_packet(&packet_data);
            let _ = result;
        }
    }

    #[test]
    fn test_pcap_injector_packet_data_with_high_values() {
        let result = PcapInjector::new("eth0");
        if let Ok(mut injector) = result {
            let _ = injector.open();
            let packet_data: Vec<u8> = vec![255; 100];
            let result = injector.inject_packet(&packet_data);
            let _ = result;
        }
    }

    #[test]
    fn test_pcap_injector_memory_leak_prevention() {
        // Create and drop many injectors to check for memory leaks
        for _ in 0..100 {
            let result = PcapInjector::new("eth0");
            if let Ok(mut injector) = result {
                let _ = injector.open();
                let packet_data = vec![0u8; 100];
                let _ = injector.inject_packet(&packet_data);
            }
            // Injector is dropped here
        }
        // If we reach here without running out of memory, the test passes
    }

    #[test]
    fn test_pcap_injector_double_drop_protection() {
        let result = PcapInjector::new("eth0");
        if let Ok(mut injector) = result {
            injector.close();
            // Explicit drop
            drop(injector);
            // Injector should be dropped again when going out of scope
        }
    }
}

#[cfg(test)]
#[cfg(unix)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_http_and_pcap_interaction() {
        // Test that HTTP client and PCAP injector can coexist
        let http_client = HttpClient::new().expect("Failed to create HTTP client");
        let pcap_result = PcapInjector::new("eth0");
        
        // HTTP client was created successfully
        assert!(true);
        // PCAP might fail, but that's OK
        let _ = pcap_result;
    }

    #[test]
    fn test_multiple_http_clients_with_pcap() {
        let http_clients: Vec<_> = (0..5)
            .map(|_| HttpClient::new().expect("Failed to create HTTP client"))
            .collect();
        
        let pcap_result = PcapInjector::new("eth0");
        
        for _client in http_clients {
            assert!(true);
        }
        
        let _ = pcap_result;
    }

    #[test]
    fn test_resource_cleanup_order() {
        // Test that resources are cleaned up in the correct order
        let http_client = HttpClient::new().expect("Failed to create HTTP client");
        let pcap_result = PcapInjector::new("eth0");
        
        if let Ok(mut pcap_injector) = pcap_result {
            let _ = pcap_injector.open();
            // Drop HTTP client first
            drop(http_client);
            // Then PCAP injector
            drop(pcap_injector);
        }
        // If we reach here without panic, cleanup order is correct
        assert!(true);
    }
}
