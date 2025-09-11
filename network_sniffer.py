import socket
import struct
import platform

def sniff_packets():
    system_os = platform.system()  # Detect OS (Windows / Linux / Mac)

    if system_os == "Windows":
        # ==================== WINDOWS RAW SOCKET ====================
        # Create raw socket with AF_INET
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

        # Bind to all available interfaces
        sniffer.bind(("0.0.0.0", 0))

        # Include IP headers in captured packets
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Enable promiscuous mode (capture ALL packets, not just destined for us)
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    else:
        # ==================== LINUX / UNIX RAW SOCKET ====================
        # Use AF_PACKET at Ethernet level
        # socket.ntohs(0x0003) means capture ALL Ethernet protocols
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    print(f"Sniffing started on {system_os}... Press Ctrl+C to stop")

    try:
        while True:
            raw_packet, addr = sniffer.recvfrom(65565)

            # On Linux, the packet starts with Ethernet header (14 bytes) → skip it
            if system_os != "Windows":
                raw_packet = raw_packet[14:]

            # Extract IP header (first 20 bytes of the packet)
            ip_header = raw_packet[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]
            version = version_ihl >> 4       # Extract IP version (4 = IPv4, 6 = IPv6)
            ihl = version_ihl & 0xF          # IP header length
            iph_length = ihl * 4             # Convert to bytes

            ttl = iph[5]                     # Time-to-live
            protocol = iph[6]                # Protocol (1=ICMP, 6=TCP, 17=UDP)
            src_addr = socket.inet_ntoa(iph[8])  # Source IP
            dst_addr = socket.inet_ntoa(iph[9])  # Destination IP

            # Print packet info
            print(f"IP Version: {version}, Header Length: {ihl}, TTL: {ttl}")
            print(f"Protocol: {protocol}, Source: {src_addr}, Destination: {dst_addr}")
            print("-" * 50)

    except KeyboardInterrupt:
        print("\nSniffing stopped")

    # ==================== WINDOWS ONLY: Disable promiscuous mode ====================
    if system_os == "Windows":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == "__main__":
    sniff_packets()
