use anyhow::Result;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use tracing::{info, warn, debug, error};
use chrono::{DateTime, Utc, Duration};
use std::time::SystemTime;

use crate::cli::DhcpConfig;
use crate::error::{NebulaError, Result as NebulaResult};

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
    type Error = NebulaError;
    
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DhcpMessageType::Discover),
            2 => Ok(DhcpMessageType::Offer),
            3 => Ok(DhcpMessageType::Request),
            4 => Ok(DhcpMessageType::Decline),
            5 => Ok(DhcpMessageType::Ack),
            6 => Ok(DhcpMessageType::Nak),
            7 => Ok(DhcpMessageType::Release),
            8 => Ok(DhcpMessageType::Inform),
            _ => Err(NebulaError::dhcp(format!("Invalid DHCP message type: {}", value))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DhcpPacket {
    pub op: u8,           // Message op code / message type
    pub htype: u8,        // Hardware address type
    pub hlen: u8,         // Hardware address length
    pub hops: u8,         // Client sets to zero
    pub xid: u32,         // Transaction ID
    pub secs: u16,        // Seconds elapsed since client began address acquisition
    pub flags: u16,       // Flags
    pub ciaddr: Ipv4Addr, // Client IP address
    pub yiaddr: Ipv4Addr, // Your (client) IP address
    pub siaddr: Ipv4Addr, // IP address of next server to use in bootstrap
    pub giaddr: Ipv4Addr, // Relay agent IP address
    pub chaddr: [u8; 16], // Client hardware address
    pub sname: [u8; 64],  // Optional server host name
    pub file: [u8; 128],  // Boot file name
    pub options: Vec<u8>, // Optional parameters field
}

#[derive(Debug, Clone)]
pub struct DhcpLease {
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
    pub hostname: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub lease_time: u32,
    pub client_id: Option<Vec<u8>>,
    pub binding_state: LeaseState,
    pub created_at: DateTime<Utc>,
    pub last_renewal: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LeaseState {
    Free,
    Offered,
    Bound,
    Released,
    Expired,
}

#[derive(Debug, Clone)]
pub struct DhcpStatistics {
    pub discovers_received: u64,
    pub offers_sent: u64,
    pub requests_received: u64,
    pub acks_sent: u64,
    pub naks_sent: u64,
    pub releases_received: u64,
    pub active_leases: usize,
    pub expired_leases: usize,
    pub static_leases: usize,
}

pub struct DhcpServer {
    config: DhcpConfig,
    leases: Arc<RwLock<HashMap<[u8; 6], DhcpLease>>>,
    available_ips: Arc<RwLock<Vec<Ipv4Addr>>>,
    reserved_ips: Arc<RwLock<HashMap<Ipv4Addr, [u8; 6]>>>,
    statistics: Arc<RwLock<DhcpStatistics>>,
    is_running: Arc<RwLock<bool>>,
    server_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl DhcpServer {
    pub async fn new(config: DhcpConfig) -> NebulaResult<Self> {
        let available_ips = Self::generate_ip_range(&config)?;
        let mut reserved_ips = HashMap::new();
        
        // Process static leases
        for static_lease in &config.static_leases {
            let mac = Self::parse_mac_address(&static_lease.mac)?;
            let ip: Ipv4Addr = static_lease.ip.parse()
                .map_err(|_| NebulaError::dhcp(format!("Invalid static lease IP: {}", static_lease.ip)))?;
            reserved_ips.insert(ip, mac);
        }
        
        Ok(Self {
            config,
            leases: Arc::new(RwLock::new(HashMap::new())),
            available_ips: Arc::new(RwLock::new(available_ips)),
            reserved_ips: Arc::new(RwLock::new(reserved_ips)),
            statistics: Arc::new(RwLock::new(DhcpStatistics::default())),
            is_running: Arc::new(RwLock::new(false)),
            server_handle: Arc::new(Mutex::new(None)),
        })
    }

    pub async fn start(&self) -> NebulaResult<()> {
        if !self.config.enabled {
            info!("DHCP server disabled in configuration");
            return Ok(());
        }

        {
            let mut running = self.is_running.write().await;
            if *running {
                return Err(NebulaError::already_exists("DHCP server is already running"));
            }
            *running = true;
        }

        info!("Starting DHCP server...");
        
        // Check if we can bind to the DHCP port (67)
        if !Self::can_bind_dhcp_port() {
            return Err(NebulaError::permission_denied("DHCP server requires root/administrator privileges"));
        }

        // Initialize static leases
        self.initialize_static_leases().await?;

        // Start the server socket
        let server = self.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = server.run_server().await {
                error!("DHCP server error: {}", e);
            }
        });

        {
            let mut server_handle = self.server_handle.lock().await;
            *server_handle = Some(handle);
        }

        // Start lease cleanup task
        let cleanup_server = self.clone();
        tokio::spawn(async move {
            cleanup_server.lease_cleanup_loop().await;
        });

        info!("✅ DHCP server started on port 67");
        Ok(())
    }

    pub async fn stop(&self) -> NebulaResult<()> {
        info!("Stopping DHCP server...");
        
        {
            let mut running = self.is_running.write().await;
            *running = false;
        }

        {
            let mut handle = self.server_handle.lock().await;
            if let Some(server_handle) = handle.take() {
                server_handle.abort();
            }
        }

        info!("✅ DHCP server stopped");
        Ok(())
    }

    pub async fn add_static_lease(&self, mac: [u8; 6], ip: Ipv4Addr, hostname: Option<String>) -> NebulaResult<()> {
        // Validate IP is in our range
        if !self.is_ip_in_range(ip) {
            return Err(NebulaError::dhcp(format!("IP {} is not in DHCP range", ip)));
        }

        // Check if IP is already reserved
        {
            let reserved = self.reserved_ips.read().await;
            if let Some(existing_mac) = reserved.get(&ip) {
                if *existing_mac != mac {
                    return Err(NebulaError::already_exists(format!("IP {} is already reserved for another MAC", ip)));
                }
            }
        }

        let lease = DhcpLease {
            ip,
            mac,
            hostname,
            expires_at: Utc::now() + Duration::seconds(self.config.lease_time as i64),
            lease_time: self.config.lease_time,
            client_id: None,
            binding_state: LeaseState::Bound,
            created_at: Utc::now(),
            last_renewal: Some(Utc::now()),
        };

        {
            let mut leases = self.leases.write().await;
            leases.insert(mac, lease);
        }

        {
            let mut reserved = self.reserved_ips.write().await;
            reserved.insert(ip, mac);
        }

        {
            let mut available = self.available_ips.write().await;
            available.retain(|&x| x != ip);
        }

        info!("Added static DHCP lease: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} -> {}", 
              mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ip);
        
        Ok(())
    }

    pub async fn remove_lease(&self, mac: &[u8; 6]) -> NebulaResult<()> {
        let mut removed_ip = None;

        {
            let mut leases = self.leases.write().await;
            if let Some(lease) = leases.remove(mac) {
                removed_ip = Some(lease.ip);
            }
        }

        if let Some(ip) = removed_ip {
            {
                let mut reserved = self.reserved_ips.write().await;
                reserved.remove(&ip);
            }

            {
                let mut available = self.available_ips.write().await;
                if !available.contains(&ip) {
                    available.push(ip);
                }
            }

            info!("Removed DHCP lease: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ({})", 
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ip);
        }

        Ok(())
    }

    pub async fn get_lease_by_mac(&self, mac: &[u8; 6]) -> Option<DhcpLease> {
        let leases = self.leases.read().await;
        leases.get(mac).cloned()
    }

    pub async fn get_lease_by_ip(&self, ip: Ipv4Addr) -> Option<DhcpLease> {
        let leases = self.leases.read().await;
        leases.values().find(|lease| lease.ip == ip).cloned()
    }

    pub async fn get_all_leases(&self) -> HashMap<[u8; 6], DhcpLease> {
        self.leases.read().await.clone()
    }

    pub async fn get_statistics(&self) -> DhcpStatistics {
        let mut stats = self.statistics.read().await.clone();
        let leases = self.leases.read().await;
        
        stats.active_leases = leases.values()
            .filter(|l| matches!(l.binding_state, LeaseState::Bound) && l.expires_at > Utc::now())
            .count();
        
        stats.expired_leases = leases.values()
            .filter(|l| l.expires_at <= Utc::now())
            .count();

        stats.static_leases = self.reserved_ips.read().await.len();
        
        stats
    }

    pub async fn cleanup_expired_leases(&self) -> NebulaResult<usize> {
        let now = Utc::now();
        let mut expired_macs = Vec::new();
        
        {
            let leases = self.leases.read().await;
            for (mac, lease) in leases.iter() {
                if lease.expires_at < now && lease.binding_state != LeaseState::Released {
                    expired_macs.push(*mac);
                }
            }
        }
        
        let count = expired_macs.len();
        for mac in expired_macs {
            self.remove_lease(&mac).await?;
        }
        
        if count > 0 {
            info!("Cleaned up {} expired DHCP leases", count);
        }
        
        Ok(count)
    }

    pub async fn is_healthy(&self) -> bool {
        *self.is_running.read().await
    }

    // Private implementation methods

    async fn run_server(&self) -> NebulaResult<()> {
        let socket = UdpSocket::bind("0.0.0.0:67")
            .map_err(|e| NebulaError::dhcp(format!("Failed to bind DHCP socket: {}", e)))?;
        
        socket.set_broadcast(true)
            .map_err(|e| NebulaError::dhcp(format!("Failed to set broadcast: {}", e)))?;

        let socket = Arc::new(socket);
        let mut buf = [0u8; 1024];

        info!("DHCP server listening on 0.0.0.0:67");

        loop {
            if !*self.is_running.read().await {
                break;
            }

            match socket.recv_from(&mut buf) {
                Ok((size, addr)) => {
                    debug!("Received DHCP packet from {}: {} bytes", addr, size);
                    
                    if let Err(e) = self.handle_dhcp_packet(&buf[..size], addr, &socket).await {
                        warn!("Error handling DHCP packet from {}: {}", addr, e);
                    }
                }
                Err(e) => {
                    error!("DHCP socket error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_dhcp_packet(
        &self,
        packet_data: &[u8],
        client_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> NebulaResult<()> {
        let packet = DhcpPacket::parse(packet_data)?;
        let message_type = packet.get_message_type()?;
        
        debug!("DHCP packet from {}: {:?} (XID: {})", client_addr, message_type, packet.xid);
        
        match message_type {
            Some(DhcpMessageType::Discover) => {
                self.handle_discover(&packet, socket).await?;
                let mut stats = self.statistics.write().await;
                stats.discovers_received += 1;
            }
            Some(DhcpMessageType::Request) => {
                self.handle_request(&packet, socket).await?;
                let mut stats = self.statistics.write().await;
                stats.requests_received += 1;
            }
            Some(DhcpMessageType::Release) => {
                self.handle_release(&packet).await?;
                let mut stats = self.statistics.write().await;
                stats.releases_received += 1;
            }
            Some(DhcpMessageType::Decline) => {
                self.handle_decline(&packet).await?;
            }
            Some(DhcpMessageType::Inform) => {
                self.handle_inform(&packet, socket).await?;
            }
            _ => {
                debug!("Unhandled DHCP message type: {:?}", message_type);
            }
        }
        
        Ok(())
    }

    async fn handle_discover(&self, packet: &DhcpPacket, socket: &UdpSocket) -> NebulaResult<()> {
        let mac = Self::extract_mac_from_packet(packet);
        
        debug!("DHCP Discover from MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        // Check if we already have a lease for this MAC
        let offered_ip = if let Some(existing_lease) = self.get_lease_by_mac(&mac).await {
            if existing_lease.expires_at > Utc::now() {
                existing_lease.ip
            } else {
                self.allocate_ip_for_mac(&mac).await?
            }
        } else {
            self.allocate_ip_for_mac(&mac).await?
        };

        // Create or update lease in OFFERED state
        let lease = DhcpLease {
            ip: offered_ip,
            mac,
            hostname: packet.get_hostname(),
            expires_at: Utc::now() + Duration::seconds(self.config.lease_time as i64),
            lease_time: self.config.lease_time,
            client_id: packet.get_client_identifier(),
            binding_state: LeaseState::Offered,
            created_at: Utc::now(),
            last_renewal: None,
        };

        {
            let mut leases = self.leases.write().await;
            leases.insert(mac, lease);
        }

        // Send DHCP Offer
        self.send_offer(packet, offered_ip, &mac, socket).await?;
        
        let mut stats = self.statistics.write().await;
        stats.offers_sent += 1;

        info!("Offered IP {} to MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
              offered_ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        Ok(())
    }

    async fn handle_request(&self, packet: &DhcpPacket, socket: &UdpSocket) -> NebulaResult<()> {
        let mac = Self::extract_mac_from_packet(packet);
        let requested_ip = packet.get_requested_ip();
        let server_id = packet.get_server_identifier();

        debug!("DHCP Request from MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, requested IP: {:?}", 
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], requested_ip);

        // Check if this is for us (server identifier should match our IP)
        if let Some(server_ip) = server_id {
            let our_ip = self.get_server_ip();
            if server_ip != our_ip {
                debug!("DHCP Request not for us (server ID: {}, our IP: {})", server_ip, our_ip);
                return Ok(());
            }
        }

        let mut should_ack = false;
        let mut response_ip = None;

        if let Some(mut lease) = self.get_lease_by_mac(&mac).await {
            if let Some(req_ip) = requested_ip {
                if req_ip == lease.ip && lease.binding_state == LeaseState::Offered {
                    // Accept the request
                    lease.binding_state = LeaseState::Bound;
                    lease.last_renewal = Some(Utc::now());
                    lease.expires_at = Utc::now() + Duration::seconds(self.config.lease_time as i64);
                    
                    {
                        let mut leases = self.leases.write().await;
                        leases.insert(mac, lease.clone());
                    }
                    
                    should_ack = true;
                    response_ip = Some(lease.ip);
                }
            } else if packet.ciaddr != Ipv4Addr::UNSPECIFIED && packet.ciaddr == lease.ip {
                // Renewing existing lease
                lease.binding_state = LeaseState::Bound;
                lease.last_renewal = Some(Utc::now());
                lease.expires_at = Utc::now() + Duration::seconds(self.config.lease_time as i64);
                
                {
                    let mut leases = self.leases.write().await;
                    leases.insert(mac, lease.clone());
                }
                
                should_ack = true;
                response_ip = Some(lease.ip);
            }
        }

        if should_ack {
            self.send_ack(packet, response_ip.unwrap(), &mac, socket).await?;
            
            let mut stats = self.statistics.write().await;
            stats.acks_sent += 1;
            
            info!("ACK'd IP {} to MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                  response_ip.unwrap(), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        } else {
            self.send_nak(packet, socket).await?;
            
            let mut stats = self.statistics.write().await;
            stats.naks_sent += 1;
            
            warn!("NAK'd request from MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        }

        Ok(())
    }

    async fn handle_release(&self, packet: &DhcpPacket) -> NebulaResult<()> {
        let mac = Self::extract_mac_from_packet(packet);
        
        {
            let mut leases = self.leases.write().await;
            if let Some(lease) = leases.get_mut(&mac) {
                lease.binding_state = LeaseState::Released;
                info!("Released IP {} from MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                      lease.ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            }
        }

        Ok(())
    }

    async fn handle_decline(&self, packet: &DhcpPacket) -> NebulaResult<()> {
        let mac = Self::extract_mac_from_packet(packet);
        let declined_ip = packet.get_requested_ip();
        
        if let Some(ip) = declined_ip {
            warn!("Client declined IP {}, marking as unusable", ip);
            // In a full implementation, you'd mark this IP as unusable for a period
        }

        // Remove the lease
        self.remove_lease(&mac).await?;
        
        Ok(())
    }

    async fn handle_inform(&self, packet: &DhcpPacket, socket: &UdpSocket) -> NebulaResult<()> {
        // DHCP Inform is used by clients that have a static IP but want other config
        self.send_inform_response(packet, socket).await?;
        Ok(())
    }

    async fn allocate_ip_for_mac(&self, mac: &[u8; 6]) -> NebulaResult<Ipv4Addr> {
        // Check if this MAC has a static reservation
        {
            let reserved = self.reserved_ips.read().await;
            for (ip, reserved_mac) in reserved.iter() {
                if reserved_mac == mac {
                    return Ok(*ip);
                }
            }
        }

        // Allocate from available pool
        {
            let mut available = self.available_ips.write().await;
            if let Some(ip) = available.pop() {
                return Ok(ip);
            }
        }

        Err(NebulaError::dhcp("No available IP addresses in DHCP pool"))
    }

    async fn send_offer(&self, request: &DhcpPacket, offered_ip: Ipv4Addr, mac: &[u8; 6], socket: &UdpSocket) -> NebulaResult<()> {
        let response = self.create_dhcp_response(request, offered_ip, DhcpMessageType::Offer)?;
        self.send_dhcp_response(&response, socket).await
    }

    async fn send_ack(&self, request: &DhcpPacket, acked_ip: Ipv4Addr, mac: &[u8; 6], socket: &UdpSocket) -> NebulaResult<()> {
        let response = self.create_dhcp_response(request, acked_ip, DhcpMessageType::Ack)?;
        self.send_dhcp_response(&response, socket).await
    }

    async fn send_nak(&self, request: &DhcpPacket, socket: &UdpSocket) -> NebulaResult<()> {
        let response = self.create_dhcp_response(request, Ipv4Addr::UNSPECIFIED, DhcpMessageType::Nak)?;
        self.send_dhcp_response(&response, socket).await
    }

    async fn send_inform_response(&self, request: &DhcpPacket, socket: &UdpSocket) -> NebulaResult<()> {
        // For INFORM, we respond with the client's current IP
        let response = self.create_dhcp_response(request, request.ciaddr, DhcpMessageType::Ack)?;
        self.send_dhcp_response(&response, socket).await
    }

    fn create_dhcp_response(&self, request: &DhcpPacket, ip: Ipv4Addr, message_type: DhcpMessageType) -> NebulaResult<Vec<u8>> {
        let mut response = vec![0u8; 240]; // Minimum DHCP packet size

        // DHCP header
        response[0] = 2; // BOOTREPLY
        response[1] = request.htype;
        response[2] = request.hlen;
        response[3] = 0; // Hops
        response[4..8].copy_from_slice(&request.xid.to_be_bytes());
        response[8..10].copy_from_slice(&request.secs.to_be_bytes());
        response[10..12].copy_from_slice(&request.flags.to_be_bytes());
        response[12..16].copy_from_slice(&request.ciaddr.octets()); // Client IP
        response[16..20].copy_from_slice(&ip.octets()); // Your IP
        response[20..24].copy_from_slice(&self.get_server_ip().octets()); // Server IP
        response[24..28].copy_from_slice(&request.giaddr.octets()); // Gateway IP
        response[28..44].copy_from_slice(&request.chaddr); // Client hardware address

        // DHCP magic cookie
        let mut options = vec![99, 130, 83, 99]; // DHCP magic cookie

        // DHCP Message Type
        options.extend_from_slice(&[53, 1, message_type as u8]);

        // Server Identifier
        options.extend_from_slice(&[54, 4]);
        options.extend_from_slice(&self.get_server_ip().octets());

        if message_type != DhcpMessageType::Nak {
            // Lease Time
            options.extend_from_slice(&[51, 4]);
            options.extend_from_slice(&self.config.lease_time.to_be_bytes());

            // Renewal Time (T1)
            options.extend_from_slice(&[58, 4]);
            options.extend_from_slice(&self.config.renewal_time.to_be_bytes());

            // Rebinding Time (T2)
            options.extend_from_slice(&[59, 4]);
            options.extend_from_slice(&self.config.rebinding_time.to_be_bytes());

            // Subnet Mask
            let subnet_mask: Ipv4Addr = self.config.subnet_mask.parse()
                .map_err(|_| NebulaError::dhcp("Invalid subnet mask in config"))?;
            options.extend_from_slice(&[1, 4]);
            options.extend_from_slice(&subnet_mask.octets());

            // Router (Gateway)
            if let Some(ref router) = self.config.router {
                let router_ip: Ipv4Addr = router.parse()
                    .map_err(|_| NebulaError::dhcp("Invalid router IP in config"))?;
                options.extend_from_slice(&[3, 4]);
                options.extend_from_slice(&router_ip.octets());
            }

            // DNS Servers
            if !self.config.dns_servers.is_empty() {
                let dns_count = std::cmp::min(self.config.dns_servers.len(), 3); // Max 3 DNS servers
                options.extend_from_slice(&[6, (dns_count * 4) as u8]);
                
                for dns_server in self.config.dns_servers.iter().take(dns_count) {
                    let dns_ip: Ipv4Addr = dns_server.parse()
                        .map_err(|_| NebulaError::dhcp("Invalid DNS server IP in config"))?;
                    options.extend_from_slice(&dns_ip.octets());
                }
            }

            // Domain Name
            if let Some(ref domain) = self.config.domain_name {
                let domain_bytes = domain.as_bytes();
                options.extend_from_slice(&[15, domain_bytes.len() as u8]);
                options.extend_from_slice(domain_bytes);
            }
        }

        // End option
        options.push(255);

        // Pad to minimum length if necessary
        while options.len() < 64 {
            options.push(0);
        }

        response.extend_from_slice(&options);

        Ok(response)
    }

    async fn send_dhcp_response(&self, response: &[u8], socket: &UdpSocket) -> NebulaResult<()> {
        let broadcast_addr = SocketAddr::from(([255, 255, 255, 255], 68));
        
        socket.send_to(response, broadcast_addr)
            .map_err(|e| NebulaError::dhcp(format!("Failed to send DHCP response: {}", e)))?;
        
        Ok(())
    }

    fn get_server_ip(&self) -> Ipv4Addr {
        // In a real implementation, you'd determine the actual server IP
        // For now, use localhost
        Ipv4Addr::new(127, 0, 0, 1)
    }

    fn generate_ip_range(config: &DhcpConfig) -> NebulaResult<Vec<Ipv4Addr>> {
        let start: Ipv4Addr = config.range_start.parse()
            .map_err(|_| NebulaError::dhcp(format!("Invalid range start IP: {}", config.range_start)))?;
        let end: Ipv4Addr = config.range_end.parse()
            .map_err(|_| NebulaError::dhcp(format!("Invalid range end IP: {}", config.range_end)))?;
        
        let start_int = u32::from(start);
        let end_int = u32::from(end);
        
        if start_int >= end_int {
            return Err(NebulaError::dhcp("DHCP range start must be less than end"));
        }

        let mut ips = Vec::new();
        for ip_int in start_int..=end_int {
            ips.push(Ipv4Addr::from(ip_int));
        }

        info!("Generated DHCP IP range: {} IPs from {} to {}", ips.len(), start, end);
        Ok(ips)
    }

    fn parse_mac_address(mac_str: &str) -> NebulaResult<[u8; 6]> {
        let parts: Vec<&str> = mac_str.split(':').collect();
        if parts.len() != 6 {
            return Err(NebulaError::dhcp(format!("Invalid MAC address format: {}", mac_str)));
        }

        let mut mac = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            mac[i] = u8::from_str_radix(part, 16)
                .map_err(|_| NebulaError::dhcp(format!("Invalid MAC address: {}", mac_str)))?;
        }

        Ok(mac)
    }

    fn extract_mac_from_packet(packet: &DhcpPacket) -> [u8; 6] {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&packet.chaddr[0..6]);
        mac
    }

    fn can_bind_dhcp_port() -> bool {
        match UdpSocket::bind("0.0.0.0:67") {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    fn is_ip_in_range(&self, ip: Ipv4Addr) -> bool {
        let start: Ipv4Addr = self.config.range_start.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
        let end: Ipv4Addr = self.config.range_end.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
        
        let ip_int = u32::from(ip);
        let start_int = u32::from(start);
        let end_int = u32::from(end);
        
        ip_int >= start_int && ip_int <= end_int
    }

    async fn initialize_static_leases(&self) -> NebulaResult<()> {
        for static_lease in &self.config.static_leases {
            let mac = Self::parse_mac_address(&static_lease.mac)?;
            let ip: Ipv4Addr = static_lease.ip.parse()
                .map_err(|_| NebulaError::dhcp(format!("Invalid static lease IP: {}", static_lease.ip)))?;
            
            self.add_static_lease(mac, ip, static_lease.hostname.clone()).await?;
        }
        
        Ok(())
    }

    async fn lease_cleanup_loop(&self) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // Every 5 minutes
        
        loop {
            interval.tick().await;
            
            if !*self.is_running.read().await {
                break;
            }

            if let Err(e) = self.cleanup_expired_leases().await {
                warn!("Lease cleanup failed: {}", e);
            }
        }
    }
}

impl DhcpPacket {
    pub fn parse(data: &[u8]) -> NebulaResult<Self> {
        if data.len() < 240 {
            return Err(NebulaError::dhcp(format!("DHCP packet too short: {} bytes", data.len())));
        }

        let mut chaddr = [0u8; 16];
        chaddr[..16].copy_from_slice(&data[28..44]);
        
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

    pub fn get_message_type(&self) -> NebulaResult<Option<DhcpMessageType>> {
        self.get_option(53).map(|data| {
            if !data.is_empty() {
                Some(DhcpMessageType::try_from(data[0]).ok()?)
            } else {
                None
            }
        }).unwrap_or(Ok(None))
    }

    pub fn get_requested_ip(&self) -> Option<Ipv4Addr> {
        self.get_option(50).and_then(|data| {
            if data.len() == 4 {
                Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
            } else {
                None
            }
        })
    }

    pub fn get_server_identifier(&self) -> Option<Ipv4Addr> {
        self.get_option(54).and_then(|data| {
            if data.len() == 4 {
                Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
            } else {
                None
            }
        })
    }

    pub fn get_client_identifier(&self) -> Option<Vec<u8>> {
        self.get_option(61).map(|data| data.to_vec())
    }

    pub fn get_hostname(&self) -> Option<String> {
        self.get_option(12).and_then(|data| {
            String::from_utf8(data.to_vec()).ok()
        })
    }

    fn get_option(&self, option_type: u8) -> Option<&[u8]> {
        let mut i = 0;
        while i < self.options.len() {
            if i + 1 >= self.options.len() {
                break;
            }
            
            let opt_type = self.options[i];
            let opt_len = self.options[i + 1] as usize;
            
            if opt_type == option_type && i + 2 + opt_len <= self.options.len() {
                return Some(&self.options[i + 2..i + 2 + opt_len]);
            }
            
            if opt_type == 255 { // End option
                break;
            }
            
            i += 2 + opt_len;
        }
        
        None
    }
}

impl Default for DhcpStatistics {
    fn default() -> Self {
        Self {
            discovers_received: 0,
            offers_sent: 0,
            requests_received: 0,
            acks_sent: 0,
            naks_sent: 0,
            releases_received: 0,
            active_leases: 0,
            expired_leases: 0,
            static_leases: 0,
        }
    }
}

impl Clone for DhcpStatistics {
    fn clone(&self) -> Self {
        Self {
            discovers_received: self.discovers_received,
            offers_sent: self.offers_sent,
            requests_received: self.requests_received,
            acks_sent: self.acks_sent,
            naks_sent: self.naks_sent,
            releases_received: self.releases_received,
            active_leases: self.active_leases,
            expired_leases: self.expired_leases,
            static_leases: self.static_leases,
        }
    }
}
