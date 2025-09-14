use anyhow::Result;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, debug, error};
use chrono::{DateTime, Utc};

use crate::cli::DhcpConfig;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl TryFrom<u8> for DhcpMessageType {
    type Error = anyhow::Error;
    
    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(DhcpMessageType::Discover),
            2 => Ok(DhcpMessageType::Offer),
            3 => Ok(DhcpMessageType::Request),
            4 => Ok(DhcpMessageType::Decline),
            5 => Ok(DhcpMessageType::Ack),
            6 => Ok(DhcpMessageType::Nak),
            7 => Ok(DhcpMessageType::Release),
            8 => Ok(DhcpMessageType::Inform),
            _ => Err(anyhow::anyhow!("Invalid DHCP message type: {}", value)),
        }
    }
}

#[derive(Debug)]
pub struct DhcpPacket {
    pub op: u8,           // Message op code
    pub htype: u8,        // Hardware address type
    pub hlen: u8,         // Hardware address length
    pub hops: u8,         // Client sets to zero
    pub xid: u32,         // Transaction ID
    pub secs: u16,        // Seconds elapsed
    pub flags: u16,       // Flags
    pub ciaddr: Ipv4Addr, // Client IP address
    pub yiaddr: Ipv4Addr, // Your IP address
    pub siaddr: Ipv4Addr, // Server IP address
    pub giaddr: Ipv4Addr, // Gateway IP address
    pub chaddr: [u8; 16], // Client hardware address
    pub sname: [u8; 64],  // Server name
    pub file: [u8; 128],  // Boot file name
    pub options: Vec<u8>, // DHCP options
}

impl DhcpPacket {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 240 {
            return Err(anyhow::anyhow!("DHCP packet too short: {} bytes", data.len()));
        }

        let mut chaddr = [0u8; 16];
        chaddr[..6].copy_from_slice(&data[28..34]);
        
        let mut sname = [0u8; 64];
        sname.copy_from_slice(&data[44..108]);
        
        let mut file = [0u8; 128];
        file.copy_from_slice(&data[108..236]);
        
        let options = if data.len() > 240 {
            data[240..].to_vec()
        } else {
            Vec::new()
        };

        Ok(DhcpPacket {
            op: data[0],
            htype: data[1],
            hlen: data[2],
            hops: data[3],
            xid: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            secs: u16::from_be_bytes([data[8], data[9]]),
            flags: u16::from_be_bytes([data[10], data[11]]),
            ciaddr: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
            yiaddr: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
            siaddr: Ipv4Addr::new(data[20], data[21], data[22], data[23]),
            giaddr: Ipv4Addr::new(data[24], data[25], data[26], data[27]),
            chaddr,
            sname,
            file,
            options,
        })
    }

    pub fn get_message_type(&self) -> Result<Option<DhcpMessageType>> {
        // Look for DHCP Message Type option (53)
        let mut i = 0;
        while i < self.options.len() {
            if i + 2 >= self.options.len() {
                break;
            }
            
            let option_type = self.options[i];
            let option_len = self.options[i + 1] as usize;
            
            if option_type == 53 && option_len == 1 && i + 2 < self.options.len() {
                return Ok(Some(DhcpMessageType::try_from(self.options[i + 2])?));
            }
            
            i += 2 + option_len;
        }
        
        Ok(None)
    }

    pub fn get_requested_ip(&self) -> Option<Ipv4Addr> {
        // Look for Requested IP Address option (50)
        let mut i = 0;
        while i < self.options.len() {
            if i + 2 >= self.options.len() {
                break;
            }
            
            let option_type = self.options[i];
            let option_len = self.options[i + 1] as usize;
            
            if option_type == 50 && option_len == 4 && i + 6 < self.options.len() {
                return Some(Ipv4Addr::new(
                    self.options[i + 2],
                    self.options[i + 3],
                    self.options[i + 4],
                    self.options[i + 5],
                ));
            }
            
            i += 2 + option_len;
        }
        
        None
    }

    pub fn get_client_identifier(&self) -> Option<Vec<u8>> {
        // Look for Client Identifier option (61)
        let mut i = 0;
        while i < self.options.len() {
            if i + 2 >= self.options.len() {
                break;
            }
            
            let option_type = self.options[i];
            let option_len = self.options[i + 1] as usize;
            
            if option_type == 61 && i + 2 + option_len <= self.options.len() {
                return Some(self.options[i + 2..i + 2 + option_len].to_vec());
            }
            
            i += 2 + option_len;
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::DhcpConfig;

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
    async fn test_dhcp_message_types() {
        let message_types = vec![
            (1u8, DhcpMessageType::Discover),
            (2u8, DhcpMessageType::Offer),
            (3u8, DhcpMessageType::Request),
            (4u8, DhcpMessageType::Decline),
            (5u8, DhcpMessageType::Ack),
            (6u8, DhcpMessageType::Nak),
            (7u8, DhcpMessageType::Release),
            (8u8, DhcpMessageType::Inform),
        ];

        for (value, expected) in message_types {
            let message_type = DhcpMessageType::try_from(value);
            assert!(message_type.is_ok(), "Should parse message type {}", value);
            assert_eq!(message_type.unwrap(), expected);
        }

        // Test invalid message type
        let invalid = DhcpMessageType::try_from(99);
        assert!(invalid.is_err(), "Should reject invalid message type");
    }

    #[tokio::test]
    async fn test_dhcp_ip_range_generation() {
        let config = DhcpConfig {
            enabled: false,
            range_start: "192.168.100.100".to_string(),
            range_end: "192.168.100.105".to_string(),
            lease_time: 3600,
        };

        let ips = DhcpServer::generate_ip_range(&config).unwrap();
        assert_eq!(ips.len(), 6); // 100, 101, 102, 103, 104, 105
        
        assert_eq!(ips[0], Ipv4Addr::new(192, 168, 100, 100));
        assert_eq!(ips[5], Ipv4Addr::new(192, 168, 100, 105));
    }

    #[tokio::test]
    async fn test_dhcp_invalid_ip_range() {
        let config = DhcpConfig {
            enabled: false,
            range_start: "192.168.100.200".to_string(),
            range_end: "192.168.100.100".to_string(), // End before start
            lease_time: 3600,
        };

        let result = DhcpServer::generate_ip_range(&config);
        assert!(result.is_err(), "Should reject invalid IP range");
    }

    #[tokio::test]
    async fn test_dhcp_lease_state_transitions() {
        let config = DhcpConfig {
            enabled: false,
            range_start: "192.168.100.100".to_string(),
            range_end: "192.168.100.200".to_string(),
            lease_time: 3600,
        };

        let dhcp_server = DhcpServer::new(config).await.unwrap();
        
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ip = Ipv4Addr::new(192, 168, 100, 100);
        
        // Add static lease (should be in Bound state)
        dhcp_server.add_static_lease(mac, ip, Some("test-device".to_string())).await.unwrap();
        
        let lease = dhcp_server.get_lease_by_mac(&mac).await.unwrap();
        assert_eq!(lease.binding_state, LeaseState::Bound);
        assert_eq!(lease.ip, ip);
        assert_eq!(lease.mac, mac);
    }

    #[tokio::test]
    async fn test_dhcp_packet_options() {
        // Create a DHCP packet with various options
        let mut packet_data = vec![0u8; 240];
        packet_data[0] = 1; // BOOTREQUEST
        packet_data[1] = 1; // Ethernet
        packet_data[2] = 6; // MAC address length
        
        // Client MAC address
        packet_data[28..34].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        
        // Add DHCP options
        let options = vec![
            53, 1, 3, // DHCP Message Type: Request
            50, 4, 192, 168, 100, 100, // Requested IP Address
            61, 7, 0, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Client Identifier
            255, // End option
        ];
        packet_data.extend_from_slice(&options);
        
        let packet = DhcpPacket::parse(&packet_data).unwrap();
        
        // Test message type parsing
        let message_type = packet.get_message_type().unwrap();
        assert_eq!(message_type, Some(DhcpMessageType::Request));
        
        // Test requested IP parsing
        let requested_ip = packet.get_requested_ip();
        assert_eq!(requested_ip, Some(Ipv4Addr::new(192, 168, 100, 100)));
        
        // Test client identifier parsing
        let client_id = packet.get_client_identifier();
        assert!(client_id.is_some());
        let client_id = client_id.unwrap();
        assert_eq!(client_id.len(), 7);
        assert_eq!(client_id[0], 0); // Hardware type
        assert_eq!(client_id[1], 1); // Hardware length
        assert_eq!(client_id[2..8], [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // MAC address
    }
}

#[derive(Debug, Clone)]
pub struct DhcpLease {
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
    pub hostname: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub client_id: Option<Vec<u8>>,
    pub binding_state: LeaseState,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LeaseState {
    Free,
    Offered,
    Bound,
    Released,
}

pub struct DhcpServer {
    config: DhcpConfig,
    leases: Arc<RwLock<HashMap<[u8; 6], DhcpLease>>>,
    available_ips: Arc<RwLock<Vec<Ipv4Addr>>>,
}

impl DhcpServer {
    pub async fn new(config: DhcpConfig) -> Result<Self> {
        let available_ips = Self::generate_ip_range(&config)?;
        
        Ok(Self {
            config,
            leases: Arc::new(RwLock::new(HashMap::new())),
            available_ips: Arc::new(RwLock::new(available_ips)),
        })
    }

    pub async fn start(&self) -> Result<()> {
        if !self.config.enabled {
            info!("DHCP server disabled in configuration");
            return Ok(());
        }

        info!("Starting DHCP server...");
        
        let socket = UdpSocket::bind("0.0.0.0:67")?;
        socket.set_broadcast(true)?;
        
        info!("✅ DHCP server started on port 67");
        
        // Start DHCP message processing loop
        let leases = self.leases.clone();
        let available_ips = self.available_ips.clone();
        let config = self.config.clone();
        
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            
            loop {
                match socket.recv_from(&mut buf) {
                    Ok((size, addr)) => {
                        debug!("Received DHCP packet from {}: {} bytes", addr, size);
                        
                        if let Err(e) = Self::handle_dhcp_packet(
                            &buf[..size],
                            addr,
                            &socket,
                            &leases,
                            &available_ips,
                            &config,
                        ).await {
                            warn!("Error handling DHCP packet: {}", e);
                        }
                    }
                    Err(e) => {
                        warn!("DHCP socket error: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        info!("Stopping DHCP server...");
        // DHCP server cleanup
        Ok(())
    }

    fn generate_ip_range(config: &DhcpConfig) -> Result<Vec<Ipv4Addr>> {
        let start: Ipv4Addr = config.range_start.parse()?;
        let end: Ipv4Addr = config.range_end.parse()?;
        
        let start_int = u32::from(start);
        let end_int = u32::from(end);
        
        if start_int >= end_int {
            return Err(anyhow::anyhow!("Invalid IP range"));
        }

        let mut ips = Vec::new();
        for ip_int in start_int..=end_int {
            ips.push(Ipv4Addr::from(ip_int));
        }

        info!("Generated DHCP IP range: {} IPs from {} to {}", 
              ips.len(), start, end);
        
        Ok(ips)
    }

    async fn handle_dhcp_packet(
        packet: &[u8],
        client_addr: SocketAddr,
        socket: &UdpSocket,
        leases: &Arc<RwLock<HashMap<[u8; 6], DhcpLease>>>,
        available_ips: &Arc<RwLock<Vec<Ipv4Addr>>>,
        config: &DhcpConfig,
    ) -> Result<()> {
        let dhcp_packet = DhcpPacket::parse(packet)?;
        let message_type = dhcp_packet.get_message_type()?;
        
        debug!("Received DHCP packet from {}: {:?}", client_addr, message_type);
        
        match message_type {
            Some(DhcpMessageType::Discover) => {
                Self::handle_discover(&dhcp_packet, socket, leases, available_ips, config).await?;
            }
            Some(DhcpMessageType::Request) => {
                Self::handle_request(&dhcp_packet, socket, leases, config).await?;
            }
            Some(DhcpMessageType::Release) => {
                Self::handle_release(&dhcp_packet, leases).await?;
            }
            _ => {
                debug!("Unhandled DHCP message type: {:?}", message_type);
            }
        }
        
        Ok(())
    }

    async fn handle_discover(
        packet: &DhcpPacket,
        socket: &UdpSocket,
        leases: &Arc<RwLock<HashMap<[u8; 6], DhcpLease>>>,
        available_ips: &Arc<RwLock<Vec<Ipv4Addr>>>,
        config: &DhcpConfig,
    ) -> Result<()> {
        let mac = [packet.chaddr[0], packet.chaddr[1], packet.chaddr[2], 
                   packet.chaddr[3], packet.chaddr[4], packet.chaddr[5]];
        
        // Check if we already have a lease for this MAC
        let mut leases_guard = leases.write().await;
        if let Some(lease) = leases_guard.get(&mac) {
            if lease.expires_at > Utc::now() && lease.binding_state == LeaseState::Bound {
                // Send DHCP Offer with existing IP
                Self::send_offer(socket, packet, lease.ip, &mac, config).await?;
                return Ok(());
            }
        }
        
        // Find available IP
        let mut available_ips_guard = available_ips.write().await;
        if let Some(ip) = available_ips_guard.pop() {
            // Create new lease
            let lease = DhcpLease {
                ip,
                mac,
                hostname: None,
                expires_at: Utc::now() + chrono::Duration::seconds(config.lease_time as i64),
                client_id: packet.get_client_identifier(),
                binding_state: LeaseState::Offered,
            };
            
            leases_guard.insert(mac, lease.clone());
            
            // Send DHCP Offer
            Self::send_offer(socket, packet, ip, &mac, config).await?;
            
            info!("Offered IP {} to MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                  ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        } else {
            warn!("No available IPs for DHCP Discover from MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        }
        
        Ok(())
    }

    async fn handle_request(
        packet: &DhcpPacket,
        socket: &UdpSocket,
        leases: &Arc<RwLock<HashMap<[u8; 6], DhcpLease>>>,
        config: &DhcpConfig,
    ) -> Result<()> {
        let mac = [packet.chaddr[0], packet.chaddr[1], packet.chaddr[2], 
                   packet.chaddr[3], packet.chaddr[4], packet.chaddr[5]];
        
        let requested_ip = packet.get_requested_ip();
        let mut leases_guard = leases.write().await;
        
        if let Some(lease) = leases_guard.get_mut(&mac) {
            if let Some(req_ip) = requested_ip {
                if req_ip == lease.ip && lease.binding_state == LeaseState::Offered {
                    // Accept the request
                    lease.binding_state = LeaseState::Bound;
                    lease.expires_at = Utc::now() + chrono::Duration::seconds(config.lease_time as i64);
                    
                    Self::send_ack(socket, packet, lease.ip, &mac, config).await?;
                    
                    info!("ACK'd IP {} to MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                          lease.ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                } else {
                    // Reject the request
                    Self::send_nak(socket, packet).await?;
                    warn!("NAK'd request for IP {} from MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                          req_ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                }
            }
        }
        
        Ok(())
    }

    async fn handle_release(
        packet: &DhcpPacket,
        leases: &Arc<RwLock<HashMap<[u8; 6], DhcpLease>>>,
    ) -> Result<()> {
        let mac = [packet.chaddr[0], packet.chaddr[1], packet.chaddr[2], 
                   packet.chaddr[3], packet.chaddr[4], packet.chaddr[5]];
        
        let mut leases_guard = leases.write().await;
        if let Some(lease) = leases_guard.get_mut(&mac) {
            lease.binding_state = LeaseState::Released;
            info!("Released IP {} from MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                  lease.ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        }
        
        Ok(())
    }

    async fn send_offer(
        socket: &UdpSocket,
        request: &DhcpPacket,
        offered_ip: Ipv4Addr,
        mac: &[u8; 6],
        config: &DhcpConfig,
    ) -> Result<()> {
        let mut response = vec![0u8; 240];
        
        // Basic DHCP header
        response[0] = 2; // BOOTREPLY
        response[1] = 1; // Ethernet
        response[2] = 6; // MAC address length
        response[3] = 0; // Hops
        response[4..8].copy_from_slice(&request.xid.to_be_bytes());
        response[8..10].copy_from_slice(&request.secs.to_be_bytes());
        response[10..12].copy_from_slice(&0u16.to_be_bytes()); // Flags
        response[12..16].copy_from_slice(&[0, 0, 0, 0]); // Client IP
        response[16..20].copy_from_slice(&offered_ip.octets()); // Your IP
        response[20..24].copy_from_slice(&[127, 0, 0, 1]); // Server IP
        response[24..28].copy_from_slice(&[0, 0, 0, 0]); // Gateway IP
        response[28..34].copy_from_slice(mac); // Client MAC
        response[34..44].copy_from_slice(&[0; 10]); // MAC padding
        
        // Add DHCP options
        let mut options = vec![
            53, 1, 2, // DHCP Message Type: Offer
            54, 4, 127, 0, 0, 1, // Server Identifier
            51, 4, // IP Address Lease Time
        ];
        options.extend_from_slice(&config.lease_time.to_be_bytes());
        
        // Subnet mask
        options.extend_from_slice(&[1, 4, 255, 255, 255, 0]);
        
        // End option
        options.push(255);
        
        response.extend_from_slice(&options);
        
        // Send to broadcast address
        let broadcast_addr = SocketAddr::new(Ipv4Addr::new(255, 255, 255, 255).into(), 68);
        socket.send_to(&response, broadcast_addr)?;
        
        Ok(())
    }

    async fn send_ack(
        socket: &UdpSocket,
        request: &DhcpPacket,
        acked_ip: Ipv4Addr,
        mac: &[u8; 6],
        config: &DhcpConfig,
    ) -> Result<()> {
        let mut response = vec![0u8; 240];
        
        // Basic DHCP header
        response[0] = 2; // BOOTREPLY
        response[1] = 1; // Ethernet
        response[2] = 6; // MAC address length
        response[3] = 0; // Hops
        response[4..8].copy_from_slice(&request.xid.to_be_bytes());
        response[8..10].copy_from_slice(&request.secs.to_be_bytes());
        response[10..12].copy_from_slice(&0u16.to_be_bytes()); // Flags
        response[12..16].copy_from_slice(&[0, 0, 0, 0]); // Client IP
        response[16..20].copy_from_slice(&acked_ip.octets()); // Your IP
        response[20..24].copy_from_slice(&[127, 0, 0, 1]); // Server IP
        response[24..28].copy_from_slice(&[0, 0, 0, 0]); // Gateway IP
        response[28..34].copy_from_slice(mac); // Client MAC
        response[34..44].copy_from_slice(&[0; 10]); // MAC padding
        
        // Add DHCP options
        let mut options = vec![
            53, 1, 5, // DHCP Message Type: ACK
            54, 4, 127, 0, 0, 1, // Server Identifier
            51, 4, // IP Address Lease Time
        ];
        options.extend_from_slice(&config.lease_time.to_be_bytes());
        
        // Subnet mask
        options.extend_from_slice(&[1, 4, 255, 255, 255, 0]);
        
        // End option
        options.push(255);
        
        response.extend_from_slice(&options);
        
        // Send to broadcast address
        let broadcast_addr = SocketAddr::new(Ipv4Addr::new(255, 255, 255, 255).into(), 68);
        socket.send_to(&response, broadcast_addr)?;
        
        Ok(())
    }

    async fn send_nak(
        socket: &UdpSocket,
        request: &DhcpPacket,
    ) -> Result<()> {
        let mut response = vec![0u8; 240];
        
        // Basic DHCP header
        response[0] = 2; // BOOTREPLY
        response[1] = 1; // Ethernet
        response[2] = 6; // MAC address length
        response[3] = 0; // Hops
        response[4..8].copy_from_slice(&request.xid.to_be_bytes());
        response[8..10].copy_from_slice(&request.secs.to_be_bytes());
        response[10..12].copy_from_slice(&0u16.to_be_bytes()); // Flags
        response[12..16].copy_from_slice(&[0, 0, 0, 0]); // Client IP
        response[16..20].copy_from_slice(&[0, 0, 0, 0]); // Your IP
        response[20..24].copy_from_slice(&[127, 0, 0, 1]); // Server IP
        response[24..28].copy_from_slice(&[0, 0, 0, 0]); // Gateway IP
        response[28..34].copy_from_slice(&request.chaddr[0..6]); // Client MAC
        response[34..44].copy_from_slice(&[0; 10]); // MAC padding
        
        // Add DHCP options
        let options = vec![
            53, 1, 6, // DHCP Message Type: NAK
            54, 4, 127, 0, 0, 1, // Server Identifier
            255, // End option
        ];
        
        response.extend_from_slice(&options);
        
        // Send to broadcast address
        let broadcast_addr = SocketAddr::new(Ipv4Addr::new(255, 255, 255, 255).into(), 68);
        socket.send_to(&response, broadcast_addr)?;
        
        Ok(())
    }

    pub async fn get_leases(&self) -> HashMap<[u8; 6], DhcpLease> {
        self.leases.read().await.clone()
    }

    pub async fn add_static_lease(&self, mac: [u8; 6], ip: Ipv4Addr, hostname: Option<String>) -> Result<()> {
        let lease = DhcpLease {
            ip,
            mac,
            hostname,
            expires_at: Utc::now() + chrono::Duration::seconds(self.config.lease_time as i64),
            client_id: None,
            binding_state: LeaseState::Bound,
        };

        self.leases.write().await.insert(mac, lease);
        info!("Added static DHCP lease: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} -> {}", 
              mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ip);
        
        Ok(())
    }

    pub async fn cleanup_expired_leases(&self) -> Result<()> {
        let now = Utc::now();
        let mut leases_guard = self.leases.write().await;
        let mut available_ips_guard = self.available_ips.write().await;
        
        let expired_macs: Vec<[u8; 6]> = leases_guard
            .iter()
            .filter(|(_, lease)| lease.expires_at < now)
            .map(|(mac, _)| *mac)
            .collect();
        
        for mac in expired_macs {
            if let Some(lease) = leases_guard.remove(&mac) {
                available_ips_guard.push(lease.ip);
                info!("Cleaned up expired lease: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} -> {}", 
                      mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], lease.ip);
            }
        }
        
        Ok(())
    }

    pub async fn get_lease_by_mac(&self, mac: &[u8; 6]) -> Option<DhcpLease> {
        self.leases.read().await.get(mac).cloned()
    }

    pub async fn get_lease_by_ip(&self, ip: Ipv4Addr) -> Option<DhcpLease> {
        self.leases.read().await
            .values()
            .find(|lease| lease.ip == ip)
            .cloned()
    }
}
