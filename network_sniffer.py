import socket
import struct
import platform

def get_local_ip():
    """
    Get the actual local IP address (not 127.0.0.1)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    return local_ip


def sniff_packets():
    system_os = platform.system()

    if system_os == "Windows":
        print("Running on Windows...")

        host = get_local_ip()  # IMPORTANT FIX

        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer.bind((host, 0))  # Bind to real IP

        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Enable promiscuous mode
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    elif system_os == "Linux":
        print("Running on Linux...")

        sniffer = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.ntohs(0x0003)
        )

    else:
        print("Unsupported OS")
        return

    print(f"Sniffing started on {system_os}... Press Ctrl+C to stop")

    try:
        while True:
            raw_packet, addr = sniffer.recvfrom(65565)

            # On Linux remove Ethernet header
            if system_os == "Linux":
                raw_packet = raw_packet[14:]

            # Ensure packet is long enough
            if len(raw_packet) < 20:
                continue

            # Unpack IP header
            ip_header = raw_packet[:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            ttl = iph[5]
            protocol = iph[6]
            src_addr = socket.inet_ntoa(iph[8])
            dst_addr = socket.inet_ntoa(iph[9])

            print(f"IP Version: {version} | TTL: {ttl} | Protocol: {protocol}")
            print(f"Source: {src_addr} → Destination: {dst_addr}")
            print("-" * 60)

    except KeyboardInterrupt:
        print("\nSniffing stopped.")

    finally:
        if system_os == "Windows":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


if __name__ == "__main__":
    sniff_packets()
