use pcap::{ConnectionStatus, Device, IfFlags};

fn main() {
    let device_list = Device::list().expect("No devices found");

    let mut cap = device_list[find_device_index(&device_list)
        .expect("No up and running internet connected device found.")]
        .clone()
        .open()
        .expect("Failed to open device");

    while let Ok(packet) = cap.next_packet() {
        println!("received packet! {:?}", packet);
    }
}

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
            for address in address_list.iter() {
                let ip_addr = address.addr;
                if ip_addr.to_string().contains("192.168.") { 
                    return Some(index);
                }
            }
        }
    }
    None
}
