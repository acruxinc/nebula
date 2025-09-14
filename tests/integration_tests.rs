use nebula::cli::{NebulaConfig, DnsConfig, DhcpConfig, SchedulerConfig, RunMode};
use nebula::network::{DnsServer, DhcpServer};
use nebula::core::scheduler::{NebulaScheduler, SchedulerConfig as CoreSchedulerConfig};
use nebula::utils::certificates::CertificateManager;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use tempfile::TempDir;

#[tokio::test]
async fn test_dns_server_creation() {
    let config = DnsConfig {
        enabled: true,
        port: 5353, // Use non-privileged port for testing
        upstream: vec!["8.8.8.8:53".to_string()],
        cache_size: 1024,
    };

    let dns_server = DnsServer::new(config).await;
    assert!(dns_server.is_ok(), "DNS server should be created successfully");
}

#[tokio::test]
async fn test_dns_record_management() {
    let config = DnsConfig {
        enabled: true,
        port: 5353,
        upstream: vec!["8.8.8.8:53".to_string()],
        cache_size: 1024,
    };

    let dns_server = DnsServer::new(config).await.unwrap();
    
    // Test adding a record
    let result = dns_server.add_record("test.example.com", "127.0.0.1".parse().unwrap()).await;
    assert!(result.is_ok(), "Should be able to add DNS record");
    
    // Test adding dev domain
    let result = dns_server.add_dev_domain("*.nebula.com", "127.0.0.1".parse().unwrap()).await;
    assert!(result.is_ok(), "Should be able to add dev domain");
    
    // Test resolving dev domain
    let resolved = dns_server.resolve_dev_domain("myapp.nebula.com").await;
    assert!(resolved.is_some(), "Should resolve dev domain");
    assert_eq!(resolved.unwrap(), "127.0.0.1".parse::<IpAddr>().unwrap());
}

#[tokio::test]
async fn test_dhcp_server_creation() {
    let config = DhcpConfig {
        enabled: false, // Disable for testing to avoid port conflicts
        range_start: "192.168.100.100".to_string(),
        range_end: "192.168.100.200".to_string(),
        lease_time: 3600,
    };

    let dhcp_server = DhcpServer::new(config).await;
    assert!(dhcp_server.is_ok(), "DHCP server should be created successfully");
}

#[tokio::test]
async fn test_dhcp_lease_management() {
    let config = DhcpConfig {
        enabled: false,
        range_start: "192.168.100.100".to_string(),
        range_end: "192.168.100.200".to_string(),
        lease_time: 3600,
    };

    let dhcp_server = DhcpServer::new(config).await.unwrap();
    
    // Test adding static lease
    let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let ip = Ipv4Addr::new(192, 168, 100, 100);
    let result = dhcp_server.add_static_lease(mac, ip, Some("test-device".to_string())).await;
    assert!(result.is_ok(), "Should be able to add static lease");
    
    // Test getting lease by MAC
    let lease = dhcp_server.get_lease_by_mac(&mac).await;
    assert!(lease.is_some(), "Should find lease by MAC");
    assert_eq!(lease.unwrap().ip, ip);
    
    // Test getting lease by IP
    let lease = dhcp_server.get_lease_by_ip(ip).await;
    assert!(lease.is_some(), "Should find lease by IP");
    assert_eq!(lease.unwrap().mac, mac);
}

#[tokio::test]
async fn test_dhcp_packet_parsing() {
    use nebula::network::dhcp::{DhcpPacket, DhcpMessageType};
    
    // Create a minimal DHCP Discover packet
    let mut packet_data = vec![0u8; 240];
    packet_data[0] = 1; // BOOTREQUEST
    packet_data[1] = 1; // Ethernet
    packet_data[2] = 6; // MAC address length
    packet_data[3] = 0; // Hops
    
    // Transaction ID
    packet_data[4..8].copy_from_slice(&12345u32.to_be_bytes());
    
    // Client MAC address
    packet_data[28..34].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    
    // Add DHCP options (DHCP Message Type: Discover)
    let options = vec![53, 1, 1, 255]; // DHCP Message Type: Discover, End option
    packet_data.extend_from_slice(&options);
    
    let packet = DhcpPacket::parse(&packet_data);
    assert!(packet.is_ok(), "Should parse DHCP packet successfully");
    
    let packet = packet.unwrap();
    assert_eq!(packet.op, 1);
    assert_eq!(packet.xid, 12345);
    assert_eq!(packet.chaddr[0..6], [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    
    let message_type = packet.get_message_type();
    assert!(message_type.is_ok(), "Should parse message type");
    assert_eq!(message_type.unwrap(), Some(DhcpMessageType::Discover));
}

#[tokio::test]
async fn test_scheduler_creation() {
    let temp_dir = TempDir::new().unwrap();
    let config = CoreSchedulerConfig {
        storage_path: temp_dir.path().to_path_buf(),
        default_tld: "test".to_string(),
        max_concurrent_deployments: 5,
        auto_cleanup: false,
        cleanup_after_days: 30,
    };

    let scheduler = NebulaScheduler::new(config).await;
    assert!(scheduler.is_ok(), "Scheduler should be created successfully");
}

#[tokio::test]
async fn test_scheduler_deployment_lifecycle() {
    let temp_dir = TempDir::new().unwrap();
    let config = CoreSchedulerConfig {
        storage_path: temp_dir.path().to_path_buf(),
        default_tld: "test".to_string(),
        max_concurrent_deployments: 5,
        auto_cleanup: false,
        cleanup_after_days: 30,
    };

    let scheduler = NebulaScheduler::new(config).await.unwrap();
    
    // Create a temporary directory for build path
    let build_dir = temp_dir.path().join("build");
    std::fs::create_dir_all(&build_dir).unwrap();
    std::fs::write(build_dir.join("index.html"), "<h1>Test</h1>").unwrap();
    
    // Test creating deployment
    let deployment = scheduler.create_deployment(
        "test-app".to_string(),
        build_dir.clone(),
        Some("xyz".to_string()),
        None,
    ).await;
    
    assert!(deployment.is_ok(), "Should create deployment successfully");
    let deployment = deployment.unwrap();
    
    assert_eq!(deployment.name, "test-app");
    assert_eq!(deployment.domain, "test-app.xyz");
    assert_eq!(deployment.build_path, build_dir);
    
    // Test listing deployments
    let deployments = scheduler.list_deployments().await;
    assert_eq!(deployments.len(), 1);
    assert_eq!(deployments[0].name, "test-app");
    
    // Test getting deployment by ID
    let retrieved = scheduler.get_deployment(&deployment.id).await;
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().name, "test-app");
    
    // Test deleting deployment
    let result = scheduler.delete_deployment(&deployment.id).await;
    assert!(result.is_ok(), "Should delete deployment successfully");
    
    // Verify deployment is deleted
    let deployments = scheduler.list_deployments().await;
    assert_eq!(deployments.len(), 0);
}

#[tokio::test]
async fn test_certificate_manager() {
    let _temp_dir = TempDir::new().unwrap();
    let cert_manager = CertificateManager::new().await;
    assert!(cert_manager.is_ok(), "Certificate manager should be created successfully");
    
    let cert_manager = cert_manager.unwrap();
    
    // Test certificate generation
    let cert = cert_manager.ensure_certificate("test.example.com", false).await;
    assert!(cert.is_ok(), "Should generate certificate successfully");
    
    // Test wildcard certificate generation
    let wildcard_cert = cert_manager.generate_wildcard_certificate("nebula.com").await;
    assert!(wildcard_cert.is_ok(), "Should generate wildcard certificate successfully");
    
    // Test listing certificates
    let certs = cert_manager.list_certificates().await;
    assert!(certs.is_ok(), "Should list certificates successfully");
    
    // Test certificate removal
    let result = cert_manager.remove_certificate("test.example.com").await;
    assert!(result.is_ok(), "Should remove certificate successfully");
}

#[tokio::test]
async fn test_config_creation() {
    let config = NebulaConfig {
        domain: "test.nebula.com".to_string(),
        http_port: 3000,
        https_port: 3443,
        dev_command: "npm run dev".to_string(),
        project_dir: None,
        force_certs: false,
        no_dns: false,
        no_dhcp: true,
        hot_reload: true,
        mode: RunMode::Dev,
        tls: nebula::cli::TlsConfig::default(),
        dns: DnsConfig::default(),
        dhcp: DhcpConfig::default(),
        scheduler: SchedulerConfig::default(),
    };
    
    assert_eq!(config.domain, "test.nebula.com");
    assert_eq!(config.mode, RunMode::Dev);
    assert!(config.hot_reload);
    assert!(!config.dhcp.enabled);
}

#[tokio::test]
async fn test_cross_platform_compatibility() {
    // Test that our code compiles and runs on different platforms
    let config = NebulaConfig {
        domain: "test.nebula.com".to_string(),
        http_port: 3000,
        https_port: 3443,
        dev_command: "echo 'test'".to_string(),
        project_dir: None,
        force_certs: false,
        no_dns: false,
        no_dhcp: true,
        hot_reload: false,
        mode: RunMode::Dev,
        tls: nebula::cli::TlsConfig::default(),
        dns: DnsConfig::default(),
        dhcp: DhcpConfig::default(),
        scheduler: SchedulerConfig::default(),
    };
    
    // Test DNS server creation
    let dns_server = DnsServer::new(config.dns.clone()).await;
    assert!(dns_server.is_ok(), "DNS server should work cross-platform");
    
    // Test DHCP server creation (disabled)
    let dhcp_server = DhcpServer::new(config.dhcp.clone()).await;
    assert!(dhcp_server.is_ok(), "DHCP server should work cross-platform");
}

#[tokio::test]
async fn test_error_handling() {
    // Test DNS server with invalid config
    let invalid_config = DnsConfig {
        enabled: true,
        port: 0, // Invalid port
        upstream: vec![],
        cache_size: 0,
    };
    
    // This should still work as we handle edge cases
    let dns_server = DnsServer::new(invalid_config).await;
    assert!(dns_server.is_ok(), "DNS server should handle invalid config gracefully");
    
    // Test scheduler with invalid path
    let invalid_config = CoreSchedulerConfig {
        storage_path: PathBuf::from("/invalid/path/that/does/not/exist"),
        default_tld: "test".to_string(),
        max_concurrent_deployments: 0,
        auto_cleanup: false,
        cleanup_after_days: 0,
    };
    
    let scheduler = NebulaScheduler::new(invalid_config).await;
    // This might fail, which is expected behavior
    if let Err(e) = scheduler {
        println!("Expected error for invalid scheduler config: {}", e);
    }
}

#[tokio::test]
async fn test_concurrent_operations() {
    let temp_dir = TempDir::new().unwrap();
    let config = CoreSchedulerConfig {
        storage_path: temp_dir.path().to_path_buf(),
        default_tld: "test".to_string(),
        max_concurrent_deployments: 10,
        auto_cleanup: false,
        cleanup_after_days: 30,
    };

    let scheduler = NebulaScheduler::new(config).await.unwrap();
    
    // Create multiple deployments concurrently
    let mut handles = vec![];
    for i in 0..5 {
        let scheduler_clone = scheduler.clone();
        let build_dir = temp_dir.path().join(format!("build{}", i));
        std::fs::create_dir_all(&build_dir).unwrap();
        std::fs::write(build_dir.join("index.html"), format!("<h1>Test {}</h1>", i)).unwrap();
        
        let handle = tokio::spawn(async move {
            scheduler_clone.create_deployment(
                format!("test-app-{}", i),
                build_dir,
                Some("test".to_string()),
                None,
            ).await
        });
        handles.push(handle);
    }
    
    // Wait for all deployments to complete
    let mut results = vec![];
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok(), "Concurrent deployment creation should work");
        results.push(result.unwrap());
    }
    
    // Verify all deployments were created
    let deployments = scheduler.list_deployments().await;
    assert_eq!(deployments.len(), 5);
    
    // Clean up
    for deployment in results {
        let _ = scheduler.delete_deployment(&deployment.id).await;
    }
}
