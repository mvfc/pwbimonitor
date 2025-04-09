use dns_lookup::lookup_host;
use std::net::{IpAddr, Ipv4Addr};
use etherparse::{PacketHeaders, TransportHeader};
use pcap::{ConnectionStatus, Device, IfFlags, Packet};
use httparse::Request;

fn parse_dns(hostname: &str) -> Vec<IpAddr> {
    let ips: Vec<std::net::IpAddr> = lookup_host(hostname).unwrap();
    return ips;
}

fn parse_packet_origin(pcap_packet: &Packet) -> [u8; 4] {
    let mut source_ip_addr: [u8; 4] = [0,0,0,0];
    match PacketHeaders::from_ethernet_slice(&pcap_packet) {
        Ok(value) => {
            if let Some(ip) = value.net
            {
                match ip {
                    etherparse::NetHeaders::Ipv4(v4, _) => {
                        // println!("IPv4 Packet: {:#?} -> {:#?}", v4.source, v4.destination);
                        source_ip_addr = v4.source;
                    }
                    _ => {
                        // Ignore ARP and IPv6 packages
                    }
                }
            }
        }
        Err(e) => {
            println!("Parse error: {:?}", e);
        }
    }
    return source_ip_addr;
}

// Finds active device that's accessing your LAN and the internet
fn find_device_index(device_list: &[Device]) -> Option<usize> {
    for (index, device) in device_list.iter().enumerate() {
        let flags = &device.flags;
        let if_flags = flags.if_flags;
        let status = &flags.connection_status;
        let address_list = &device.addresses;

        if if_flags.contains(IfFlags::UP)
            && if_flags.contains(IfFlags::RUNNING)
            && *status == ConnectionStatus::Connected
        {
            if !address_list.is_empty() {
                for address in address_list.iter() {
                    let ip_addr = address.addr;
                    if ip_addr.to_string().contains("192.168.")
                        || address.netmask == Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))) { 
                            return Some(index);
                    }
                }
            }
        }
    }
    None
}

fn parse_payload(pcap_packet: &Packet) {
    let packet_data = pcap_packet.data;
    match PacketHeaders::from_ethernet_slice(packet_data) {
        Ok(headers) => {
            // Make sure we only parse TCP packets
            match headers.transport {
                Some(TransportHeader::Tcp(tcp)) => {
                    // Get the payload slice (no need to unwrap an Option anymore)
                    let payload: &[u8] = headers.payload.slice();

                    // Prepare a buffer to hold parsed headers
                    let mut headers_buf = [httparse::EMPTY_HEADER; 16];
                    let mut request = Request::new(&mut headers_buf);

                    match request.parse(payload) {
                        Ok(httparse::Status::Complete(_)) => {
                            println!("--- HTTP Request Parsed ---");
                            println!("Method: {:?}", request.method);
                            println!("Path: {:?}", request.path);
                            for header in request.headers.iter() {
                                println!("Header: {} = {:?}", header.name, String::from_utf8_lossy(header.value));
                            }
                        }
                        Ok(httparse::Status::Partial) => {
                            println!("Incomplete HTTP request");
                        }
                        Err(e) => {
                            println!("HTTP parse error: {:?}", e);
                        }
                    }
                }
                _ => {
                    // Not TCP (could be UDP, etc.), skip
                }
            }
        }
        Err(e) => {
            println!("Failed to parse packet headers: {:?}", e);
        }
    }
}

fn main() {
    // gets a device list from pcap (all network devices are returned)
    let device_list = Device::list().expect("No devices found");
    // gets powerbi service endpoint ip address from hostname
    let ip_list: Vec<IpAddr> = parse_dns("pbipweu1-westeurope.pbidedicated.windows.net");

    // opens the device and starts an active capture
    let mut cap = device_list[find_device_index(&device_list)
        .expect("No up and running internet connected device found.")]
        .clone()
        .open()
        .expect("Failed to open device")
        .filter("tcp port 443", true)
        .expect("Failed to set filter");

    // iterates over captured packets
    while let Ok(packet) = cap.next_packet() {
        // grabs source ip from packet if Ipv4
        let packet_origin: [u8; 4] = parse_packet_origin(&packet);
        // deconstructs packet
        let [x, y, v, z] = packet_origin;
        // checks if source ip is from PowerBI host
        if ip_list.contains(&IpAddr::V4(Ipv4Addr::new(x, y, v, z))) {
            parse_payload(&packet);
        } 
    }
}
