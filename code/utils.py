def mac_format(raw):
    return ':'.join(f'{b:02x}' for b in raw)

def get_ip(ip):
    return '.'.join(f'{b}' for b in ip)

def get_protocol(protocol_number):
    protocol_map = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 89: "OSPF"}
    return protocol_map.get(protocol_number, f"UNKNOWN ({protocol_number})")

def decode_tcp_flags(flags_byte):
    flags = []
    if flags_byte & 0x01: flags.append("FIN")
    if flags_byte & 0x02: flags.append("SYN")
    if flags_byte & 0x04: flags.append("RST")
    if flags_byte & 0x08: flags.append("PSH")
    if flags_byte & 0x10: flags.append("ACK")
    if flags_byte & 0x20: flags.append("URG")
    return flags if flags else ["NONE"]