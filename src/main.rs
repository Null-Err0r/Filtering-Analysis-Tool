use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use serde::{Serialize, Deserialize};
use serde_json;
use chrono::prelude::*;
use std::fs::File;
use std::io::Write;
use std::env;
use log::{info, error};
use env_logger;

const FILTERED_DOMAINS: [&str; 5] = ["youtube.com", "telegram.org", "twitter.com", "facebook.com", "instagram.com"];
const DOH_PATTERNS: [&[u8]; 2] = [b"/dns-query", b"application/dns-message"];

#[derive(Serialize, Deserialize)]
struct AnalysisResult {
    timestamp: String,
    layer3: Layer3Data,
    layer4: Layer4Data,
    layer7: Layer7Data,
}

#[derive(Serialize, Deserialize)]
struct Layer3Data {
    src: String,
    dst: String,
}

#[derive(Serialize, Deserialize)]
struct Layer4Data {
    dst_port: Option<u16>,
    flags: Option<String>,
    reset: Option<bool>,
    syn_ack: Option<bool>,
    possible_rst_injection: Option<bool>,
}

#[derive(Serialize, Deserialize)]
struct Layer7Data {
    sni: Option<String>,
    sni_filtered: Option<bool>,
    doh_detected: Option<bool>,
    http2_detected: Option<bool>,
    quic_detected: Option<bool>,
    doq_detected: Option<bool>,
    http3_detected: Option<bool>,
    dns_query: Option<String>,
    dns_filtered: Option<bool>,
}

fn extract_sni_tls(payload: &[u8]) -> Option<String> {
    if payload.len() < 5 || payload[0] != 0x16 || payload[5] != 0x01 {
        return None;
    }

    let mut idx = 43; 


    if idx >= payload.len() { return None; }
    let session_id_length = payload[idx] as usize;
    idx += 1;
    if idx + session_id_length > payload.len() { return None; }
    idx += session_id_length;


    if idx + 2 > payload.len() { return None; }
    let cipher_suites_length = u16::from_be_bytes([payload[idx], payload[idx + 1]]) as usize;
    idx += 2;
    if idx + cipher_suites_length > payload.len() { return None; }
    idx += cipher_suites_length;


    if idx >= payload.len() { return None; }
    let compression_methods_length = payload[idx] as usize;
    idx += 1;
    if idx + compression_methods_length > payload.len() { return None; }
    idx += compression_methods_length;


    if idx + 2 > payload.len() { return None; }
    let extensions_length = u16::from_be_bytes([payload[idx], payload[idx + 1]]) as usize;
    idx += 2;

    let end_extensions = idx + extensions_length;
    while idx + 4 <= end_extensions && idx + 4 <= payload.len() {
        let ext_type = u16::from_be_bytes([payload[idx], payload[idx + 1]]);
        let ext_len = u16::from_be_bytes([payload[idx + 2], payload[idx + 3]]) as usize;
        idx += 4; 

        if ext_type == 0 { 
            if idx + 2 > payload.len() || idx + 2 + ext_len > payload.len() { return None; }
            let sni_list_len = u16::from_be_bytes([payload[idx], payload[idx + 1]]) as usize;
            idx += 2;
            let sni_list_end = idx + sni_list_len;
            while idx + 3 <= sni_list_end && idx + 3 <= payload.len() {
                let name_type = payload[idx]; 
                let name_len = u16::from_be_bytes([payload[idx + 1], payload[idx + 2]]) as usize; 
                idx += 3;
                if name_type == 0 { 
                    if idx + name_len > payload.len() { return None; }
                    let sni = String::from_utf8_lossy(&payload[idx..idx + name_len]).into_owned();
                    return Some(sni);
                }
                idx += name_len;
            }
        } else {
            idx += ext_len; 
        }
    }
    None
}

fn detect_http2(payload: &[u8]) -> bool {
    payload.windows(24).any(|window| window == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
}

fn detect_rst_injection(tcp: &TcpPacket) -> bool {
    tcp.get_flags() & 0x04 != 0 && tcp.payload().is_empty()
}

fn detect_doq(payload: &[u8]) -> bool {
    payload.to_ascii_lowercase().windows(3).any(|window| window == b"doq")
}

fn detect_http3(payload: &[u8]) -> bool {
    let known_versions: Vec<&[u8]> = vec![ 
        b"\x00\x00\x00\x01",
        b"Q043",
        b"Q046",
        b"Q050",
        b"h3-",
    ];
    known_versions.iter().any(|&v| payload.windows(v.len()).any(|window| window == v))
}

fn analyze_packet(packet: &EthernetPacket) -> Option<AnalysisResult> {
    let mut result = AnalysisResult {
        timestamp: Utc::now().to_rfc3339(),
        layer3: Layer3Data { src: String::new(), dst: String::new() },
        layer4: Layer4Data { dst_port: None, flags: None, reset: None, syn_ack: None, possible_rst_injection: None },
        layer7: Layer7Data {
            sni: None,
            sni_filtered: None,
            doh_detected: None,
            http2_detected: None,
            quic_detected: None,
            doq_detected: None,
            http3_detected: None,
            dns_query: None,
            dns_filtered: None,
        },
    };

    if let Some(ipv4) = Ipv4Packet::new(packet.payload()) {
        result.layer3.src = ipv4.get_source().to_string();
        result.layer3.dst = ipv4.get_destination().to_string();

        match ipv4.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                    result.layer4.dst_port = Some(tcp.get_destination());
                    let flags = tcp.get_flags();
                    result.layer4.flags = Some(format!("{:x}", flags));
                    result.layer4.reset = Some(flags & 0x04 != 0);
                    result.layer4.syn_ack = Some(flags & 0x12 == 0x12);
                    result.layer4.possible_rst_injection = Some(detect_rst_injection(&tcp));

                    let payload = tcp.payload();
                    if tcp.get_destination() == 443 { 
                        if let Some(sni) = extract_sni_tls(payload) {
                            result.layer7.sni = Some(sni.clone());
                            result.layer7.sni_filtered = Some(FILTERED_DOMAINS.iter().any(|&domain| sni.to_lowercase().contains(domain)));
                        }
                    }

                    if DOH_PATTERNS.iter().any(|&pat| payload.windows(pat.len()).any(|window| window == pat)) {
                        result.layer7.doh_detected = Some(true);
                    }

                    if detect_http2(payload) {
                        result.layer7.http2_detected = Some(true);
                    }
                }
            },
            IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                    result.layer4.dst_port = Some(udp.get_destination()); 
                    let payload = udp.payload(); 
                    if udp.get_destination() == 443 { 
                        if payload.windows(4).any(|window| window == b"quic") {
                            result.layer7.quic_detected = Some(true);
                        }
                        if detect_doq(payload) {
                            result.layer7.doq_detected = Some(true);
                        }
                        if detect_http3(payload) {
                            result.layer7.http3_detected = Some(true);
                        }
                    } else if udp.get_destination() == 53 { 
                        if payload.len() > 12 { 
                            let mut dns_idx = 12; 
                            let mut qname = Vec::new();
                            while dns_idx < payload.len() {
                                let len = payload[dns_idx] as usize;
                                if len == 0 {
                                    break;
                                }
                                if dns_idx + 1 + len > payload.len() { break; }
                                qname.extend_from_slice(&payload[dns_idx + 1..dns_idx + 1 + len]);
                                dns_idx += 1 + len;
                                if dns_idx < payload.len() && payload[dns_idx] != 0 { 
                                    qname.push(b'.');
                                }
                            }
                            if !qname.is_empty() {
                                if let Ok(query_str) = String::from_utf8(qname) {
                                    result.layer7.dns_query = Some(query_str.clone());
                                    result.layer7.dns_filtered = Some(FILTERED_DOMAINS.iter().any(|&domain| query_str.to_lowercase().contains(domain)));
                                }
                            }
                        }
                    }
                }
            },
            _ => {
                // Handle other protocols if necessary, or just ignore
            }
        }
    }

    Some(result)
}

fn get_default_interface() -> Option<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback() && iface.ips.iter().any(|ip| ip.is_ipv4()))
}

fn main() {
    env_logger::init();
    let interfaces = datalink::interfaces();
    let interface = match env::args().nth(1) {
        Some(name) => interfaces.into_iter().find(|iface| iface.name == name),
        None => get_default_interface(),
    };

    let interface = match interface {
        Some(iface) => iface,
        None => {
            error!("No valid interface found");
            return;
        }
    };

    info!("Sniffing started on {}...", interface.name);
    let count = 100;
    let mut results = Vec::new();

    let config = datalink::Config {
        promiscuous: true,
        ..Default::default()
    };

    let mut rx = match datalink::channel(&interface, config) {
        Ok(Channel::Ethernet(_, rx)) => rx,
        Ok(_) => {
            error!("Unsupported channel type");
            return;
        }
        Err(e) => {
            error!("Error creating channel: {}", e);
            return;
        }
    };

    let filter_ports = [53, 80, 443];
    let mut packet_count = 0;

    while packet_count < count {
        match rx.next() { // Fix: Use rx.next()
            Ok(packet) => {
                if let Some(eth) = EthernetPacket::new(packet) {
                    if eth.get_ethertype() == EtherTypes::Ipv4 {
                        if let Some(result) = analyze_packet(&eth) { 
                            if result.layer4.dst_port.map_or(false, |port| filter_ports.contains(&port)) {
                                println!("{}", serde_json::to_string_pretty(&result).unwrap());
                                results.push(result);
                                packet_count += 1;
                            }
                        }
                    }
                }
            }
            Err(e) => error!("Error receiving packet: {}", e),
        }
    }

    let output = serde_json::to_string_pretty(&results).unwrap();
    if let Ok(mut file) = File::create("filter_analysis_results.json") {
        if let Err(e) = file.write_all(output.as_bytes()) {
            error!("Error writing to file: {}", e);
        }
    }
}
