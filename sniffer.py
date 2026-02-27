import socket
import struct
import argparse
import datetime
from collections import defaultdict

traffic_stats = defaultdict(int)

def main():
    parser = argparse.ArgumentParser(description="Advanced Python Network Sniffer")
    parser.add_argument("--protocol", help="Filter by protocol (TCP, UDP, ICMP)")
    parser.add_argument("--port", type=int, help="Filter by port number")
    parser.add_argument("--log", help="Log output to file")
    args = parser.parse_args()

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print("[+] Sniffer Started... Press Ctrl+C to stop\n")

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        if eth_proto == 8:  # IPv4
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)

            protocol_name = get_protocol_name(proto)

            if args.protocol and args.protocol.upper() != protocol_name:
                continue

            output = f"\n[{datetime.datetime.now()}] {protocol_name} Packet: {src} -> {target}"

            if proto == 6:  # TCP
                src_port, dest_port, sequence, acknowledgment, flags, data = tcp_segment(data)

                if args.port and args.port not in (src_port, dest_port):
                    continue

                flag_list = decode_tcp_flags(flags)
                output += f"\n   TCP Ports: {src_port} -> {dest_port}"
                output += f"\n   Flags: {flag_list}"

            elif proto == 17:  # UDP
                src_port, dest_port, size = udp_segment(data)

                if args.port and args.port not in (src_port, dest_port):
                    continue

                output += f"\n   UDP Ports: {src_port} -> {dest_port}"

                if src_port == 53 or dest_port == 53:
                    dns_info = parse_dns(data)
                    output += f"\n   DNS Query: {dns_info}"

            elif proto == 1:  # ICMP
                icmp_type, code, checksum, data = icmp_packet(data)
                output += f"\n   ICMP Type: {icmp_type}, Code: {code}"

            traffic_stats[protocol_name] += 1
            traffic_stats["Total"] += 1

            print(output)

            if args.log:
                with open(args.log, "a") as f:
                    f.write(output + "\n")

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return get_mac(dest_mac), get_mac(src_mac), socket.htons(proto), data[14:]

def get_mac(bytes_addr):
    return ':'.join(format(b, '02x') for b in bytes_addr)

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('!HHLLH', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x01FF
    return src_port, dest_port, sequence, acknowledgment, flags, data[offset:]

def decode_tcp_flags(flags):
    flag_names = []
    if flags & 1: flag_names.append("FIN")
    if flags & 2: flag_names.append("SYN")
    if flags & 4: flag_names.append("RST")
    if flags & 8: flag_names.append("PSH")
    if flags & 16: flag_names.append("ACK")
    if flags & 32: flag_names.append("URG")
    return flag_names

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('!HH2xH', data[:8])
    return src_port, dest_port, size

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
    return icmp_type, code, checksum, data[4:]

def parse_dns(data):
    try:
        query = data[12:]
        domain = ""
        i = 0
        length = query[i]
        while length != 0:
            domain += query[i+1:i+1+length].decode() + "."
            i += length + 1
            length = query[i]
        return domain
    except:
        return "Unable to parse"

def get_protocol_name(proto):
    if proto == 1:
        return "ICMP"
    elif proto == 6:
        return "TCP"
    elif proto == 17:
        return "UDP"
    else:
        return "OTHER"

if __name__ == "__main__":
    main()