# Network API Reference

This document provides a comprehensive reference for Nebula's network services API, including DNS, DHCP, and HTTP/HTTPS functionality.

## DNS Server API

### DnsServer

The built-in DNS server implementation.

```rust
pub struct DnsServer {
    config: DnsConfig,
    zones: Arc<RwLock<HashMap<String, DnsZone>>>,
    cache: Arc<RwLock<DnsCache>>,
    upstream_clients: Vec<AsyncClient>,
}

impl DnsServer {
    pub async fn new(config: DnsConfig) -> Result<Self>;
    pub async fn start(&self) -> Result<()>;
    pub async fn stop(&self) -> Result<()>;
    pub async fn add_zone(&self, zone: DnsZone) -> Result<()>;
    pub async fn remove_zone(&self, zone_name: &str) -> Result<()>;
    pub async fn add_record(&self, zone_name: &str, record: DnsRecord) -> Result<()>;
    pub async fn remove_record(&self, zone_name: &str, name: &str) -> Result<()>;
    pub async fn query(&self, question: &Question) -> Result<Vec<Record>>;
    pub fn get_stats(&self) -> DnsStats;
}
```

### DNS Configuration

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub enabled: bool,
    pub port: u16,
    pub bind_address: IpAddr,
    pub cache_size: usize,
    pub cache_ttl: u32,
    pub upstream: Vec<String>,
    pub forwarding: bool,
    pub recursion: bool,
    pub custom_records: HashMap<String, String>,
}
```

### DNS Zone Management

```rust
#[derive(Debug, Clone)]
pub struct DnsZone {
    pub name: String,
    pub records: HashMap<String, Vec<DnsRecord>>,
    pub soa: DnsRecord,
    pub ns: Vec<DnsRecord>,
}

impl DnsZone {
    pub fn new(name: String) -> Self;
    pub fn add_record(&mut self, name: String, record: DnsRecord) -> Result<()>;
    pub fn remove_record(&mut self, name: &str, record_type: RecordType) -> Result<()>;
    pub fn get_records(&self, name: &str) -> Vec<&DnsRecord>;
    pub fn resolve(&self, name: &str, record_type: RecordType) -> Vec<&DnsRecord>;
}
```

### DNS Record Types

```rust
#[derive(Debug, Clone)]
pub enum DnsRecord {
    A { name: String, ip: Ipv4Addr, ttl: u32 },
    AAAA { name: String, ip: Ipv6Addr, ttl: u32 },
    CNAME { name: String, target: String, ttl: u32 },
    MX { name: String, priority: u16, target: String, ttl: u32 },
    NS { name: String, target: String, ttl: u32 },
    TXT { name: String, text: String, ttl: u32 },
    SRV { name: String, priority: u16, weight: u16, port: u16, target: String, ttl: u32 },
    PTR { name: String, target: String, ttl: u32 },
}

impl DnsRecord {
    pub fn new_a(name: String, ip: Ipv4Addr) -> Self;
    pub fn new_aaaa(name: String, ip: Ipv6Addr) -> Self;
    pub fn new_cname(name: String, target: String) -> Self;
    pub fn new_mx(name: String, priority: u16, target: String) -> Self;
    pub fn new_ns(name: String, target: String) -> Self;
    pub fn new_txt(name: String, text: String) -> Self;
    pub fn new_srv(name: String, priority: u16, weight: u16, port: u16, target: String) -> Self;
    pub fn new_ptr(name: String, target: String) -> Self;
    
    pub fn get_name(&self) -> &str;
    pub fn get_ttl(&self) -> u32;
    pub fn set_ttl(&mut self, ttl: u32);
    pub fn to_trust_dns_record(&self) -> Result<Record>;
}
```

### DNS Cache

```rust
pub struct DnsCache {
    entries: HashMap<String, CacheEntry>,
    max_size: usize,
    default_ttl: u32,
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub records: Vec<Record>,
    pub expires_at: Instant,
    pub hit_count: u64,
}

impl DnsCache {
    pub fn new(max_size: usize, default_ttl: u32) -> Self;
    pub fn get(&self, key: &str) -> Option<Vec<Record>>;
    pub fn set(&mut self, key: String, records: Vec<Record>, ttl: u32);
    pub fn remove(&mut self, key: &str);
    pub fn clear(&mut self);
    pub fn cleanup_expired(&mut self);
    pub fn get_stats(&self) -> CacheStats;
}
```

### DNS Statistics

```rust
#[derive(Debug, Clone, Default)]
pub struct DnsStats {
    pub queries_total: u64,
    pub queries_successful: u64,
    pub queries_failed: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub upstream_queries: u64,
    pub upstream_failures: u64,
    pub zones_count: u32,
    pub records_count: u32,
    pub uptime: Duration,
}

impl DnsStats {
    pub fn increment_queries(&mut self);
    pub fn increment_successful(&mut self);
    pub fn increment_failed(&mut self);
    pub fn increment_cache_hits(&mut self);
    pub fn increment_cache_misses(&mut self);
    pub fn increment_upstream_queries(&mut self);
    pub fn increment_upstream_failures(&mut self);
}
```

## DHCP Server API

### DhcpServer

The built-in DHCP server implementation.

```rust
pub struct DhcpServer {
    config: DhcpConfig,
    leases: Arc<RwLock<HashMap<MacAddress, DhcpLease>>>,
    pool: IpPool,
    stats: Arc<RwLock<DhcpStats>>,
}

impl DhcpServer {
    pub async fn new(config: DhcpConfig) -> Result<Self>;
    pub async fn start(&self) -> Result<()>;
    pub async fn stop(&self) -> Result<()>;
    pub async fn handle_packet(&self, packet: DhcpPacket) -> Result<Option<DhcpPacket>>;
    pub fn get_lease(&self, mac: &MacAddress) -> Option<DhcpLease>;
    pub fn add_static_lease(&self, mac: MacAddress, ip: Ipv4Addr) -> Result<()>;
    pub fn remove_static_lease(&self, mac: &MacAddress) -> Result<()>;
    pub fn get_stats(&self) -> DhcpStats;
}
```

### DHCP Configuration

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpConfig {
    pub enabled: bool,
    pub range_start: Ipv4Addr,
    pub range_end: Ipv4Addr,
    pub lease_time: u32,
    pub renewal_time: u32,
    pub rebinding_time: u32,
    pub subnet_mask: Ipv4Addr,
    pub dns_servers: Vec<Ipv4Addr>,
    pub domain_name: String,
    pub router: Option<Ipv4Addr>,
    pub static_leases: HashMap<String, Ipv4Addr>,
}
```

### DHCP Packet Handling

```rust
#[derive(Debug, Clone)]
pub struct DhcpPacket {
    pub message_type: DhcpMessageType,
    pub transaction_id: u32,
    pub client_mac: MacAddress,
    pub client_ip: Option<Ipv4Addr>,
    pub server_ip: Option<Ipv4Addr>,
    pub options: HashMap<u8, Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DhcpMessageType {
    Discover,
    Offer,
    Request,
    Ack,
    Nak,
    Release,
    Decline,
    Inform,
}

impl DhcpPacket {
    pub fn from_bytes(data: &[u8]) -> Result<Self>;
    pub fn to_bytes(&self) -> Result<Vec<u8>>;
    pub fn get_option(&self, option: DhcpOption) -> Option<&Vec<u8>>;
    pub fn set_option(&mut self, option: DhcpOption, value: Vec<u8>);
    pub fn remove_option(&mut self, option: DhcpOption);
}

#[derive(Debug, Clone, Copy)]
pub enum DhcpOption {
    SubnetMask = 1,
    Router = 3,
    DnsServer = 6,
    DomainName = 15,
    LeaseTime = 51,
    MessageType = 53,
    ServerIdentifier = 54,
    RequestedIpAddress = 50,
    ClientIdentifier = 61,
}
```

### DHCP Lease Management

```rust
#[derive(Debug, Clone)]
pub struct DhcpLease {
    pub mac_address: MacAddress,
    pub ip_address: Ipv4Addr,
    pub hostname: Option<String>,
    pub state: LeaseState,
    pub expires_at: DateTime<Utc>,
    pub renewal_at: DateTime<Utc>,
    pub rebinding_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LeaseState {
    Offered,
    Active,
    Renewing,
    Rebinding,
    Expired,
    Released,
}

impl DhcpLease {
    pub fn new(mac: MacAddress, ip: Ipv4Addr, lease_time: u32) -> Self;
    pub fn is_expired(&self) -> bool;
    pub fn is_renewable(&self) -> bool;
    pub fn is_rebinding(&self) -> bool;
    pub fn extend_lease(&mut self, additional_time: u32);
    pub fn release(&mut self);
    pub fn update_last_seen(&mut self);
}
```

### IP Address Pool

```rust
pub struct IpPool {
    range_start: Ipv4Addr,
    range_end: Ipv4Addr,
    allocated: HashSet<Ipv4Addr>,
    available: VecDeque<Ipv4Addr>,
}

impl IpPool {
    pub fn new(range_start: Ipv4Addr, range_end: Ipv4Addr) -> Self;
    pub fn allocate_ip(&mut self) -> Option<Ipv4Addr>;
    pub fn deallocate_ip(&mut self, ip: Ipv4Addr) -> bool;
    pub fn is_allocated(&self, ip: &Ipv4Addr) -> bool;
    pub fn get_available_count(&self) -> usize;
    pub fn get_allocated_count(&self) -> usize;
    pub fn reserve_ip(&mut self, ip: Ipv4Addr) -> bool;
    pub fn release_ip(&mut self, ip: Ipv4Addr) -> bool;
}
```

### DHCP Statistics

```rust
#[derive(Debug, Clone, Default)]
pub struct DhcpStats {
    pub packets_received: u64,
    pub packets_sent: u64,
    pub discover_packets: u64,
    pub offer_packets: u64,
    pub request_packets: u64,
    pub ack_packets: u64,
    pub nak_packets: u64,
    pub release_packets: u64,
    pub active_leases: u32,
    pub total_leases: u32,
    pub pool_utilization: f64,
    pub uptime: Duration,
}
```

## HTTP/HTTPS Server API

### HttpServer

The HTTP/HTTPS server implementation.

```rust
pub struct HttpServer {
    config: ServerConfig,
    tls_config: Option<ServerConfig>,
    cert_manager: Arc<CertificateManager>,
    stats: Arc<RwLock<HttpStats>>,
}

impl HttpServer {
    pub async fn new(config: ServerConfig, tls_config: Option<ServerConfig>) -> Result<Self>;
    pub async fn start(&self) -> Result<()>;
    pub async fn stop(&self) -> Result<()>;
    pub fn add_route<F>(&mut self, path: &str, handler: F) -> Result<()>
    where
        F: HttpHandler + Send + Sync + 'static;
    pub fn add_middleware<F>(&mut self, middleware: F) -> Result<()>
    where
        F: Middleware + Send + Sync + 'static;
    pub fn get_stats(&self) -> HttpStats;
}
```

### HTTP Request/Response

```rust
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub version: Version,
    pub remote_addr: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub version: Version,
}

pub trait HttpHandler: Send + Sync {
    async fn handle(&self, request: HttpRequest) -> Result<HttpResponse>;
}

pub trait Middleware: Send + Sync {
    async fn process(&self, request: &mut HttpRequest, response: &mut HttpResponse) -> Result<()>;
}
```

### HTTP Statistics

```rust
#[derive(Debug, Clone, Default)]
pub struct HttpStats {
    pub requests_total: u64,
    pub requests_successful: u64,
    pub requests_failed: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub active_connections: u32,
    pub max_connections: u32,
    pub average_response_time: Duration,
    pub status_codes: HashMap<u16, u64>,
    pub methods: HashMap<String, u64>,
    pub uptime: Duration,
}
```

## Network Utilities

### Port Management

```rust
pub mod port_utils {
    pub fn is_port_available(port: u16) -> bool;
    pub fn find_available_port(start: u16, end: u16) -> Option<u16>;
    pub fn find_available_ports(count: usize, start: u16, end: u16) -> Vec<u16>;
    pub fn bind_port(port: u16) -> Result<TcpListener>;
    pub fn test_port_connection(host: &str, port: u16) -> Result<()>;
}
```

### Network Interface Management

```rust
pub mod interface_utils {
    pub fn get_local_interfaces() -> Result<Vec<NetworkInterface>>;
    pub fn get_interface_by_name(name: &str) -> Result<NetworkInterface>;
    pub fn get_interface_by_ip(ip: IpAddr) -> Result<NetworkInterface>;
    pub fn get_local_ip() -> Result<IpAddr>;
    pub fn is_interface_up(name: &str) -> bool;
}

#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub index: u32,
    pub ip_addresses: Vec<IpAddr>,
    pub mac_address: Option<MacAddress>,
    pub is_up: bool,
    pub is_loopback: bool,
}
```

### Socket Utilities

```rust
pub mod socket_utils {
    pub fn create_udp_socket(addr: &SocketAddr) -> Result<UdpSocket>;
    pub fn create_tcp_socket(addr: &SocketAddr) -> Result<TcpListener>;
    pub fn set_socket_reuseaddr(socket: &impl AsRawFd) -> Result<()>;
    pub fn set_socket_reuseport(socket: &impl AsRawFd) -> Result<()>;
    pub fn set_socket_nonblocking(socket: &impl AsRawFd) -> Result<()>;
    pub fn set_socket_buffer_size(socket: &impl AsRawFd, size: usize) -> Result<()>;
}
```

## API Usage Examples

### DNS Server Setup

```rust
use nebula::network::dns::{DnsServer, DnsConfig, DnsZone, DnsRecord};

async fn setup_dns_server() -> Result<()> {
    let config = DnsConfig {
        enabled: true,
        port: 53,
        bind_address: "127.0.0.1".parse()?,
        cache_size: 1024,
        cache_ttl: 300,
        upstream: vec!["8.8.8.8:53".to_string(), "1.1.1.1:53".to_string()],
        forwarding: true,
        recursion: true,
        custom_records: HashMap::new(),
    };
    
    let mut server = DnsServer::new(config).await?;
    
    // Create a zone
    let mut zone = DnsZone::new("nebula.com".to_string());
    zone.add_record("app".to_string(), DnsRecord::new_a("app.nebula.com".to_string(), "127.0.0.1".parse()?))?;
    zone.add_record("api".to_string(), DnsRecord::new_a("api.nebula.com".to_string(), "127.0.0.1".parse()?))?;
    
    server.add_zone(zone).await?;
    server.start().await?;
    
    Ok(())
}
```

### DHCP Server Setup

```rust
use nebula::network::dhcp::{DhcpServer, DhcpConfig};

async fn setup_dhcp_server() -> Result<()> {
    let config = DhcpConfig {
        enabled: true,
        range_start: "192.168.100.100".parse()?,
        range_end: "192.168.100.200".parse()?,
        lease_time: 86400,
        renewal_time: 43200,
        rebinding_time: 75600,
        subnet_mask: "255.255.255.0".parse()?,
        dns_servers: vec!["127.0.0.1".parse()?],
        domain_name: "nebula.local".to_string(),
        router: Some("192.168.100.1".parse()?),
        static_leases: HashMap::new(),
    };
    
    let server = DhcpServer::new(config).await?;
    server.start().await?;
    
    Ok(())
}
```

### Custom DNS Handler

```rust
use nebula::network::dns::{DnsHandler, DnsRequest, DnsResponse};

struct CustomDnsHandler;

impl DnsHandler for CustomDnsHandler {
    async fn handle_query(&self, request: &DnsRequest) -> Result<DnsResponse> {
        match request.question().name() {
            name if name.ends_with(".custom") => {
                // Handle custom domain
                let response = DnsResponse::new(request.id());
                response.add_answer(DnsRecord::new_a(
                    name.to_string(),
                    "127.0.0.1".parse()?
                ));
                Ok(response)
            }
            _ => {
                // Forward to upstream
                self.forward_query(request).await
            }
        }
    }
}
```

### HTTP Route Handler

```rust
use nebula::network::http::{HttpServer, HttpHandler, HttpRequest, HttpResponse};

struct ApiHandler;

impl HttpHandler for ApiHandler {
    async fn handle(&self, request: HttpRequest) -> Result<HttpResponse> {
        match request.uri.path() {
            "/api/status" => {
                let response = HttpResponse {
                    status: StatusCode::OK,
                    headers: HeaderMap::new(),
                    body: b"{\"status\":\"ok\"}".to_vec(),
                    version: Version::HTTP_11,
                };
                Ok(response)
            }
            _ => {
                let response = HttpResponse {
                    status: StatusCode::NOT_FOUND,
                    headers: HeaderMap::new(),
                    body: b"Not Found".to_vec(),
                    version: Version::HTTP_11,
                };
                Ok(response)
            }
        }
    }
}

async fn setup_http_server() -> Result<()> {
    let mut server = HttpServer::new(config).await?;
    server.add_route("/api/*", ApiHandler)?;
    server.start().await?;
    
    Ok(())
}
```

## Next Steps

- **Explore [Certificate API](certificates.md)** for TLS management
- **Read [Core API](core.md)** for main server functionality
- **Check [Scheduler API](scheduler.md)** for production deployment
- **Review [Configuration API](configuration.md)** for config management
