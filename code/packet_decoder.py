from ethernet_decoder import eth_deco
from ip_decoder import ip_deco
from transport_deco import transport_decoder
def process(packet):
    raw_bytes = packet.original

    eth_type, payload = eth_deco(raw_bytes)

    if eth_type == 0x0800:  
        protocol, transport_payload = ip_deco(payload)

        transport_decoder(protocol, transport_payload)