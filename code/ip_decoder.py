from utils import *

def ip_deco(raw_bytes):
    print("\n----------------IP Header --------------- Layer 2 ")
    ip_header = raw_bytes[14:34]
    version = ip_header[0] >> 4
    ihl = ip_header[0] & 0x0F 
    h_size=ihl*4
    ip_start=14
    ip_header = raw_bytes[ip_start : ip_start + h_size]
    tos = ip_header[1]
    ttl = ip_header[8]
    prot = ip_header[9]
    hc = ip_header[10:12]
    src = ip_header[12:16]
    dest = ip_header[16:20]
    print("Version         :", version)
    print("IHL             :", ihl)
    print("TOS             :", tos)
    print("TTL             :", ttl)
    print("Protocol        :", get_protocol(prot))
    print("Header Checksum :", hc.hex())
    print("Source Ip       :", get_ip(src))
    print("Destination Ip  :", get_ip(dest))

