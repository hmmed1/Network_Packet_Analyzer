from utils import mac_format

def eth_deco(raw_bytes):
    eth_header = raw_bytes[0:14]
    dest_mac = eth_header[0:6]
    src_mac = eth_header[6:12]
    eth_type = eth_header[12:14]
    print("\n----------------Ethernet Frame --------------- Layer 1 ")
    print("Destination Mac :", mac_format(dest_mac))
    print("Source Mac      :", mac_format(src_mac))
    print("Eth Type        :", eth_type.hex())
