from utils import get_protocol, get_ip
def ip_deco(ip_packet):

    version = ip_packet[0] >> 4
    ihl = ip_packet[0] & 0x0F
    h_size = ihl * 4

    ip_header = ip_packet[:h_size]

    tos = ip_header[1]
    ttl = ip_header[8]
    prot = ip_header[9]
    hc = ip_header[10:12]
    src = ip_header[12:16]
    dest = ip_header[16:20]

    print("\n----------------IP Header --------------- Layer 2 ")
    print("Version         :", version)
    print("IHL             :", ihl)
    print("TOS             :", tos)
    print("TTL             :", ttl)
    print("Protocol        :", get_protocol(prot))
    print("Header Checksum :", hc.hex())
    print("Source Ip       :", get_ip(src))
    print("Destination Ip  :", get_ip(dest))

    transport_payload = ip_packet[h_size:]

    return prot, transport_payload

