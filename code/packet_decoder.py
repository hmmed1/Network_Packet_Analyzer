from ethernet_decoder import eth_deco
from ip_decoder import ip_deco
from transport_deco import transport_decoder
def process(packet):
    raw_bytes = packet.original
    eth_deco(raw_bytes)
    ip_deco(raw_bytes)
    transport_decoder(raw_bytes)
