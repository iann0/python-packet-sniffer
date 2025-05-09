import socket
import struct

def eth_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return (
        get_mac(dest_mac),
        get_mac(src_mac),
        socket.htons(proto),
        data[14:]
    )

def get_mac(bytes_addr):
    return ':'.join('%02x' % b for b in bytes_addr)

def ipv4_packet(data):
    version_header_len = data[0]
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', data[:20])
    return (
        ttl,
        proto,
        ipv4(src),
        ipv4(target),
        data[header_len:]
    )

def ipv4(addr):
    return '.'.join(map(str, addr))

def tcp_segment(data):
    (src_port, dest_port) = struct.unpack('!HH', data[:4])
    return src_port, dest_port

def udp_segment(data):
    (src_port, dest_port) = struct.unpack('!HH', data[:4])
    return src_port, dest_port

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print("Sniffer started...\nPress Ctrl+C to stop.\n")

    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = eth_frame(raw_data)

            if eth_proto == 8:  # IPv4
                ttl, proto, src_ip, dest_ip, data = ipv4_packet(data)

                if proto == 6:  # TCP
                    src_port, dest_port = tcp_segment(data)
                    print(f"[TCP] {src_ip}:{src_port} → {dest_ip}:{dest_port}")
                elif proto == 17:  # UDP
                    src_port, dest_port = udp_segment(data)
                    print(f"[UDP] {src_ip}:{src_port} → {dest_ip}:{dest_port}")
                else:
                    print(f"[IPv4] {src_ip} → {dest_ip} (Protocol: {proto})")
    except KeyboardInterrupt:
        print("\nSniffer stopped.")

if __name__ == "__main__":
    main()