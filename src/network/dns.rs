use anyhow::Result;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tokio::net::UdpSocket;
use tracing::{info, warn, debug, error};
use trust_dns_server::{
    authority::{Authority, LookupError, MessageRequest, UpdateResult, ZoneType},
    proto::{
        op::{Header, MessageType, OpCode, ResponseCode},
        rr::{
            domain::Name, rdata::SOA, record_type::RecordType, resource::Record, DNSClass, RData,
        },
        serialize::binary::{BinEncodable, BinEncoder},
        xfer::{DnsRequest, DnsRequestOptions, DnsResponse},
    },
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    ServerFuture,
};

use crate::cli::DnsConfig;
use crate::error::{NebulaError, Result as NebulaResult};
use crate::network::NetworkUtils;

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: RecordType,
    pub data: String,
    pub ttl: u32,
    pub created_at: SystemTime,
}

#[derive(Debug, Clone)]
pub struct DnsZone {
    pub name: String,
    pub records: HashMap<String, Vec<DnsRecord>>,
    pub soa: SoaRecord,
}

#[derive(Debug, Clone)]
pub struct SoaRecord {
    pub primary_ns: String,
    pub admin_email: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

#[derive(Debug, Clone)]
pub struct DnsCache {
    entries: Arc<RwLock<HashMap<String, CachedEntry>>>,
    max_size: usize,
}

#[derive(Debug, Clone)]
struct CachedEntry {
    records: Vec<DnsRecord>,
    expires_at: SystemTime,
}

#[derive(Debug, Clone)]
pub struct DnsStatistics {
    pub queries_total: u64,
    pub queries_success: u64,
    pub queries_failed: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub upstream_queries: u64,
    pub zones_count: usize,
    pub records_count: usize,
}

pub struct DnsServer {
    config: DnsConfig,
    zones: Arc<RwLock<HashMap<String, DnsZone>>>,
    cache: DnsCache,
    upstream_client: trust_dns_client::client::AsyncClient,
    statistics: Arc<RwLock<DnsStatistics>>,
    is_running: Arc<RwLock<bool>>,
    server_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

pub struct NebulaRequestHandler {
    zones: Arc<RwLock<HashMap<String, DnsZone>>>,
    cache: DnsCache,
    upstream_client: trust_dns_client::client::AsyncClient,
    statistics: Arc<RwLock<DnsStatistics>>,
}

impl DnsServer {
    pub async fn new(config: DnsConfig) -> NebulaResult<Self> {
        if config.enabled && config.port < 1024 && !Self::is_privileged() {
            warn!("DNS server requires privileged access for port {}", config.port);
        }

        // Create upstream client
        let upstream_addr = config.upstream.first()
            .ok_or_else(|| NebulaError::dns("No upstream DNS servers configured"))?;
        
        let upstream_socket: SocketAddr = upstream_addr.parse()
            .map_err(|_| NebulaError::dns(format!("Invalid upstream DNS server: {}", upstream_addr)))?;

        let (upstream_client, bg) = trust_dns_client::udp::UdpClientStream::new(upstream_socket);
        let mut upstream_client = trust_dns_client::client::AsyncClient::new(upstream_client, bg, None)
            .await
            .map_err(|e| NebulaError::dns(format!("Failed to create upstream client: {}", e)))?;

        // Start the background task
        tokio::spawn(async move {
            if let Err(e) = upstream_client.await {
                error!("Upstream DNS client error: {}", e);
            }
        });

        let cache = DnsCache::new(config.cache_size);
        let zones = Arc::new(RwLock::new(HashMap::new()));
        
        // Create default zones
        Self::create_default_zones(&zones).await?;

        Ok(Self {
            config,
            zones,
            cache,
            upstream_client: upstream_client.clone(),
            statistics: Arc::new(RwLock::new(DnsStatistics::default())),
            is_running: Arc::new(RwLock::new(false)),
            server_handle: Arc::new(RwLock::new(None)),
        })
    }

    pub async fn start(&self) -> NebulaResult<()> {
        if !self.config.enabled {
            info!("DNS server disabled in configuration");
            return Ok(());
        }

        {
            let mut running = self.is_running.write().await;
            if *running {
                return Err(NebulaError::already_exists("DNS server is already running"));
            }
            *running = true;
        }

        info!("Starting DNS server on {}:{}", self.config.bind_address, self.config.port);

        let bind_addr = SocketAddr::new(self.config.bind_address, self.config.port);
        
        // Create socket with SO_REUSEADDR
        let socket = socket2::Socket::new(
            if bind_addr.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 },
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        ).map_err(|e| NebulaError::dns(format!("Failed to create socket: {}", e)))?;

        socket.set_reuse_address(true)
            .map_err(|e| NebulaError::dns(format!("Failed to set SO_REUSEADDR: {}", e)))?;

        #[cfg(not(windows))]
        socket.set_reuse_port(true)
            .map_err(|e| NebulaError::dns(format!("Failed to set SO_REUSEPORT: {}", e)))?;

        socket.bind(&bind_addr.into())
            .map_err(|e| NebulaError::dns(format!("Failed to bind to {}: {}", bind_addr, e)))?;

        let std_socket: std::net::UdpSocket = socket.into();
        std_socket.set_nonblocking(true)
            .map_err(|e| NebulaError::dns(format!("Failed to set non-blocking: {}", e)))?;

        let udp_socket = UdpSocket::from_std(std_socket)
            .map_err(|e| NebulaError::dns(format!("Failed to create tokio socket: {}", e)))?;

        // Create request handler
        let handler = NebulaRequestHandler {
            zones: self.zones.clone(),
            cache: self.cache.clone(),
            upstream_client: self.upstream_client.clone(),
            statistics: self.statistics.clone(),
        };

        // Start DNS server
        let mut server = ServerFuture::new(handler);
        
        let server_handle = tokio::spawn(async move {
            if let Err(e) = server.register_socket(udp_socket).await {
                error!("DNS server error: {}", e);
            }
        });

        {
            let mut handle = self.server_handle.write().await;
            *handle = Some(server_handle);
        }

        info!("✅ DNS server started successfully on {}", bind_addr);
        Ok(())
    }

    pub async fn stop(&self) -> NebulaResult<()> {
        info!("Stopping DNS server...");

        {
            let mut running = self.is_running.write().await;
            *running = false;
        }

        {
            let mut handle = self.server_handle.write().await;
            if let Some(server_handle) = handle.take() {
                server_handle.abort();
            }
        }

        info!("✅ DNS server stopped");
        Ok(())
    }

    pub async fn add_record(&self, domain: &str, record_type: &str, data: &str, ttl: u32) -> NebulaResult<()> {
        NetworkUtils::validate_domain_name(domain)?;

        let record_type = RecordType::from_str(record_type)
            .map_err(|_| NebulaError::dns(format!("Invalid record type: {}", record_type)))?;

        // Validate data based on record type
        Self::validate_record_data(&record_type, data)?;

        let normalized_domain = NetworkUtils::normalize_domain(domain);
        let zone_name = Self::find_zone_name(&normalized_domain);

        // Ensure zone exists
        self.ensure_zone_exists(&zone_name).await?;

        let record = DnsRecord {
            name: normalized_domain.clone(),
            record_type,
            data: data.to_string(),
            ttl,
            created_at: SystemTime::now(),
        };

        {
            let mut zones = self.zones.write().await;
            if let Some(zone) = zones.get_mut(&zone_name) {
                zone.records.entry(normalized_domain.clone())
                    .or_insert_with(Vec::new)
                    .push(record);
            }
        }

        // Invalidate cache
        self.cache.invalidate(&normalized_domain).await;

        info!("Added DNS record: {} {} {}", domain, record_type, data);
        Ok(())
    }

    pub async fn remove_record(&self, domain: &str) -> NebulaResult<()> {
        let normalized_domain = NetworkUtils::normalize_domain(domain);
        let zone_name = Self::find_zone_name(&normalized_domain);

        {
            let mut zones = self.zones.write().await;
            if let Some(zone) = zones.get_mut(&zone_name) {
                zone.records.remove(&normalized_domain);
            }
        }

        // Invalidate cache
        self.cache.invalidate(&normalized_domain).await;

        info!("Removed DNS record: {}", domain);
        Ok(())
    }

    pub async fn remove_all_records(&self, domain: &str) -> NebulaResult<()> {
        let normalized_domain = NetworkUtils::normalize_domain(domain);
        let zone_name = Self::find_zone_name(&normalized_domain);

        {
            let mut zones = self.zones.write().await;
            if let Some(zone) = zones.get_mut(&zone_name) {
                // Remove all records matching the domain or subdomains
                zone.records.retain(|name, _| {
                    !name.ends_with(&format!(".{}", normalized_domain)) && 
                    *name != normalized_domain
                });
            }
        }

        // Invalidate cache for domain and all subdomains
        self.cache.invalidate_pattern(&normalized_domain).await;

        info!("Removed all DNS records for: {}", domain);
        Ok(())
    }

    pub async fn add_dev_domain(&self, pattern: &str, ip: IpAddr) -> NebulaResult<()> {
        // Add wildcard record for development domains
        let record_type = if ip.is_ipv4() { RecordType::A } else { RecordType::AAAA };
        
        self.add_record(pattern, &record_type.to_string(), &ip.to_string(), 300).await?;
        
        // If it's a wildcard, also add the base domain
        if pattern.starts_with("*.") {
            let base_domain = &pattern[2..];
            self.add_record(base_domain, &record_type.to_string(), &ip.to_string(), 300).await?;
        }

        info!("Added dev domain pattern: {} -> {}", pattern, ip);
        Ok(())
    }

    pub async fn list_records(&self, filter: Option<&str>) -> NebulaResult<HashMap<String, Vec<DnsRecord>>> {
        let zones = self.zones.read().await;
        let mut all_records = HashMap::new();

        for zone in zones.values() {
            for (name, records) in &zone.records {
                if let Some(filter) = filter {
                    if !name.contains(filter) {
                        continue;
                    }
                }
                all_records.insert(name.clone(), records.clone());
            }
        }

        Ok(all_records)
    }

    pub async fn test_resolution(&self, domain: &str, server: Option<&str>, record_type: &str) -> NebulaResult<Vec<String>> {
        let record_type = RecordType::from_str(record_type)
            .map_err(|_| NebulaError::dns(format!("Invalid record type: {}", record_type)))?;

        let domain_name = Name::from_str(domain)
            .map_err(|e| NebulaError::dns(format!("Invalid domain: {}", e)))?;

        // Use specified server or default upstream
        let server_addr = if let Some(server) = server {
            server.parse::<SocketAddr>()
                .map_err(|_| NebulaError::dns(format!("Invalid server address: {}", server)))?
        } else {
            self.config.upstream.first()
                .ok_or_else(|| NebulaError::dns("No upstream servers configured"))?
                .parse()?
        };

        // Create temporary client
        let (client_stream, bg) = trust_dns_client::udp::UdpClientStream::new(server_addr);
        let mut client = trust_dns_client::client::AsyncClient::new(client_stream, bg, None)
            .await
            .map_err(|e| NebulaError::dns(format!("Failed to create test client: {}", e)))?;

        // Start background task
        tokio::spawn(async move {
            if let Err(e) = client.await {
                debug!("Test client background task error: {}", e);
            }
        });

        let response = client.query(domain_name, DNSClass::IN, record_type)
            .await
            .map_err(|e| NebulaError::dns(format!("Query failed: {}", e)))?;

        let results: Vec<String> = response.answers()
            .iter()
            .map(|record| {
                match record.data() {
                    Some(RData::A(addr)) => addr.to_string(),
                    Some(RData::AAAA(addr)) => addr.to_string(),
                    Some(RData::CNAME(name)) => name.to_string(),
                    Some(RData::MX(mx)) => format!("{} {}", mx.preference(), mx.exchange()),
                    Some(RData::TXT(txt)) => txt.to_string(),
                    Some(data) => format!("{:?}", data),
                    None => "No data".to_string(),
                }
            })
            .collect();

        Ok(results)
    }

    pub async fn flush_cache(&self) -> NebulaResult<()> {
        self.cache.clear().await;
        info!("DNS cache flushed");
        Ok(())
    }

    pub async fn get_statistics(&self) -> NebulaResult<DnsStatistics> {
        let stats = self.statistics.read().await;
        let zones = self.zones.read().await;
        
        let mut records_count = 0;
        for zone in zones.values() {
            for records in zone.records.values() {
                records_count += records.len();
            }
        }

        Ok(DnsStatistics {
            zones_count: zones.len(),
            records_count,
            ..stats.clone()
        })
    }

    pub async fn is_healthy(&self) -> bool {
        *self.is_running.read().await
    }

    pub async fn resolve_dev_domain(&self, domain: &str) -> Option<IpAddr> {
        let normalized = NetworkUtils::normalize_domain(domain);
        let zones = self.zones.read().await;

        for zone in zones.values() {
            // Check exact match
            if let Some(records) = zone.records.get(&normalized) {
                for record in records {
                    if let Ok(ip) = record.data.parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }

            // Check wildcard patterns
            for (pattern, records) in &zone.records {
                if pattern.starts_with("*.") {
                    let suffix = &pattern[2..];
                    if normalized.ends_with(suffix) {
                        for record in records {
                            if let Ok(ip) = record.data.parse::<IpAddr>() {
                                return Some(ip);
                            }
                        }
                    }
                }
            }
        }

        None
    }

    // Private helper methods

    fn is_privileged() -> bool {
        #[cfg(unix)]
        {
            unsafe { libc::geteuid() == 0 }
        }
        #[cfg(windows)]
        {
            // On Windows, check if running as administrator
            // This is a simplified check
            true
        }
    }

    async fn create_default_zones(zones: &Arc<RwLock<HashMap<String, DnsZone>>>) -> NebulaResult<()> {
        let default_zones = vec![
            "dev",
            "nebula.com", 
            "localhost",
            "local",
        ];

        let mut zones_map = zones.write().await;
        for zone_name in default_zones {
            let soa = SoaRecord {
                primary_ns: format!("ns1.{}", zone_name),
                admin_email: format!("admin.{}", zone_name),
                serial: 1,
                refresh: 3600,
                retry: 1800,
                expire: 604800,
                minimum: 86400,
            };

            let zone = DnsZone {
                name: zone_name.to_string(),
                records: HashMap::new(),
                soa,
            };

            zones_map.insert(zone_name.to_string(), zone);
        }

        Ok(())
    }

    fn find_zone_name(domain: &str) -> String {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() >= 2 {
            parts[parts.len()-2..].join(".")
        } else {
            domain.to_string()
        }
    }

    async fn ensure_zone_exists(&self, zone_name: &str) -> NebulaResult<()> {
        let mut zones = self.zones.write().await;
        if !zones.contains_key(zone_name) {
            let soa = SoaRecord {
                primary_ns: format!("ns1.{}", zone_name),
                admin_email: format!("admin.{}", zone_name),
                serial: 1,
                refresh: 3600,
                retry: 1800,
                expire: 604800,
                minimum: 86400,
            };

            let zone = DnsZone {
                name: zone_name.to_string(),
                records: HashMap::new(),
                soa,
            };

            zones.insert(zone_name.to_string(), zone);
            info!("Created DNS zone: {}", zone_name);
        }
        Ok(())
    }

    fn validate_record_data(record_type: &RecordType, data: &str) -> NebulaResult<()> {
        match record_type {
            RecordType::A => {
                data.parse::<Ipv4Addr>()
                    .map_err(|_| NebulaError::dns(format!("Invalid IPv4 address: {}", data)))?;
            }
            RecordType::AAAA => {
                data.parse::<Ipv6Addr>()
                    .map_err(|_| NebulaError::dns(format!("Invalid IPv6 address: {}", data)))?;
            }
            RecordType::CNAME => {
                NetworkUtils::validate_domain_name(data)?;
            }
            RecordType::MX => {
                // MX format: "priority hostname"
                let parts: Vec<&str> = data.split_whitespace().collect();
                if parts.len() != 2 {
                    return Err(NebulaError::dns("MX record must be in format: 'priority hostname'"));
                }
                parts[0].parse::<u16>()
                    .map_err(|_| NebulaError::dns("Invalid MX priority"))?;
                NetworkUtils::validate_domain_name(parts[1])?;
            }
            RecordType::TXT => {
                // TXT records can contain any text
            }
            _ => {
                return Err(NebulaError::dns(format!("Unsupported record type: {}", record_type)));
            }
        }
        Ok(())
    }
}

impl DnsCache {
    fn new(max_size: usize) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            max_size,
        }
    }

    async fn get(&self, domain: &str) -> Option<Vec<DnsRecord>> {
        let entries = self.entries.read().await;
        if let Some(entry) = entries.get(domain) {
            if entry.expires_at > SystemTime::now() {
                return Some(entry.records.clone());
            }
        }
        None
    }

    async fn insert(&self, domain: String, records: Vec<DnsRecord>, ttl: Duration) {
        let mut entries = self.entries.write().await;
        
        // Simple LRU eviction
        if entries.len() >= self.max_size {
            if let Some(oldest_key) = entries.keys().next().cloned() {
                entries.remove(&oldest_key);
            }
        }

        entries.insert(domain, CachedEntry {
            records,
            expires_at: SystemTime::now() + ttl,
        });
    }

    async fn invalidate(&self, domain: &str) {
        let mut entries = self.entries.write().await;
        entries.remove(domain);
    }

    async fn invalidate_pattern(&self, pattern: &str) {
        let mut entries = self.entries.write().await;
        entries.retain(|domain, _| !domain.contains(pattern));
    }

    async fn clear(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();
    }
}

#[async_trait::async_trait]
impl RequestHandler for NebulaRequestHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let mut stats = self.statistics.write().await;
        stats.queries_total += 1;
        drop(stats);

        debug!("DNS query: {:?}", request.query());

        let response = match self.process_request(request).await {
            Ok(response) => {
                let mut stats = self.statistics.write().await;
                stats.queries_success += 1;
                response
            }
            Err(e) => {
                debug!("DNS query failed: {}", e);
                let mut stats = self.statistics.write().await;
                stats.queries_failed += 1;
                drop(stats);

                let mut header = Header::response_from_request(request.header());
                header.set_response_code(ResponseCode::ServFail);
                
                trust_dns_server::proto::op::Message::new()
                    .set_header(header)
                    .clone()
            }
        };

        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(e) => {
                error!("Failed to send DNS response: {}", e);
                ResponseInfo::default()
            }
        }
    }
}

impl NebulaRequestHandler {
    async fn process_request(&self, request: &Request) -> NebulaResult<trust_dns_server::proto::op::Message> {
        let query = request.query();
        let domain = query.name().to_string().trim_end_matches('.').to_lowercase();
        
        debug!("Processing DNS query for: {} type: {:?}", domain, query.query_type());

        // Check cache first
        if let Some(cached_records) = self.cache.get(&domain).await {
            let mut stats = self.statistics.write().await;
            stats.cache_hits += 1;
            drop(stats);

            return Ok(self.create_response_from_records(request, &cached_records));
        }

        let mut stats = self.statistics.write().await;
        stats.cache_misses += 1;
        drop(stats);

        // Check local zones
        if let Some(records) = self.lookup_in_zones(&domain, query.query_type()).await {
            // Cache the result
            let ttl = Duration::from_secs(records.first().map(|r| r.ttl as u64).unwrap_or(300));
            self.cache.insert(domain, records.clone(), ttl).await;
            
            return Ok(self.create_response_from_records(request, &records));
        }

        // Forward to upstream if not found locally and forwarding is enabled
        if self.should_forward_query(&domain) {
            let mut stats = self.statistics.write().await;
            stats.upstream_queries += 1;
            drop(stats);

            match self.forward_to_upstream(request).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    debug!("Upstream query failed: {}", e);
                }
            }
        }

        // Return NXDOMAIN
        let mut header = Header::response_from_request(request.header());
        header.set_response_code(ResponseCode::NXDomain);
        
        Ok(trust_dns_server::proto::op::Message::new()
            .set_header(header)
            .clone())
    }

    async fn lookup_in_zones(&self, domain: &str, query_type: RecordType) -> Option<Vec<DnsRecord>> {
        let zones = self.zones.read().await;
        
        for zone in zones.values() {
            // Check exact match
            if let Some(records) = zone.records.get(domain) {
                let matching_records: Vec<DnsRecord> = records.iter()
                    .filter(|r| r.record_type == query_type || query_type == RecordType::ANY)
                    .cloned()
                    .collect();
                
                if !matching_records.is_empty() {
                    return Some(matching_records);
                }
            }

            // Check wildcard patterns
            for (pattern, records) in &zone.records {
                if pattern.starts_with("*.") {
                    let suffix = &pattern[2..];
                    if domain.ends_with(suffix) {
                        let matching_records: Vec<DnsRecord> = records.iter()
                            .filter(|r| r.record_type == query_type || query_type == RecordType::ANY)
                            .cloned()
                            .collect();
                        
                        if !matching_records.is_empty() {
                            return Some(matching_records);
                        }
                    }
                }
            }
        }

        None
    }

    fn should_forward_query(&self, domain: &str) -> bool {
        // Don't forward queries for local development domains
        !NetworkUtils::is_dev_domain(domain)
    }

    async fn forward_to_upstream(&self, request: &Request) -> NebulaResult<trust_dns_server::proto::op::Message> {
        let query = request.query();
        let domain_name = query.name().clone();
        
        let response = self.upstream_client.query(domain_name, query.query_class(), query.query_type())
            .await
            .map_err(|e| NebulaError::dns(format!("Upstream query failed: {}", e)))?;

        // Convert the response to our format
        let mut message = trust_dns_server::proto::op::Message::new();
        let mut header = Header::response_from_request(request.header());
        header.set_response_code(ResponseCode::NoError);
        message.set_header(header);
        
        // Add answers
        for answer in response.answers() {
            message.add_answer(answer.clone());
        }

        Ok(message)
    }

    fn create_response_from_records(&self, request: &Request, records: &[DnsRecord]) -> trust_dns_server::proto::op::Message {
        let mut message = trust_dns_server::proto::op::Message::new();
        let mut header = Header::response_from_request(request.header());
        header.set_response_code(ResponseCode::NoError);
        message.set_header(header);

        for dns_record in records {
            if let Ok(rdata) = self.dns_record_to_rdata(dns_record) {
                let record = Record::from_rdata(
                    request.query().name().clone(),
                    dns_record.ttl,
                    rdata,
                );
                message.add_answer(record);
            }
        }

        message
    }

    fn dns_record_to_rdata(&self, record: &DnsRecord) -> Result<RData, NebulaError> {
        match record.record_type {
            RecordType::A => {
                let addr = record.data.parse::<Ipv4Addr>()
                    .map_err(|_| NebulaError::dns("Invalid A record data"))?;
                Ok(RData::A(addr.into()))
            }
            RecordType::AAAA => {
                let addr = record.data.parse::<Ipv6Addr>()
                    .map_err(|_| NebulaError::dns("Invalid AAAA record data"))?;
                Ok(RData::AAAA(addr.into()))
            }
            RecordType::CNAME => {
                let name = Name::from_str(&record.data)
                    .map_err(|_| NebulaError::dns("Invalid CNAME record data"))?;
                Ok(RData::CNAME(name.into()))
            }
            RecordType::TXT => {
                Ok(RData::TXT(trust_dns_server::proto::rr::rdata::TXT::new(vec![record.data.clone()])))
            }
            _ => Err(NebulaError::dns(format!("Unsupported record type: {}", record.record_type)))
        }
    }
}

impl Default for DnsStatistics {
    fn default() -> Self {
        Self {
            queries_total: 0,
            queries_success: 0,
            queries_failed: 0,
            cache_hits: 0,
            cache_misses: 0,
            upstream_queries: 0,
            zones_count: 0,
            records_count: 0,
        }
    }
}

impl Clone for DnsStatistics {
    fn clone(&self) -> Self {
        Self {
            queries_total: self.queries_total,
            queries_success: self.queries_success,
            queries_failed: self.queries_failed,
            cache_hits: self.cache_hits,
            cache_misses: self.cache_misses,
            upstream_queries: self.upstream_queries,
            zones_count: self.zones_count,
            records_count: self.records_count,
        }
    }
}
