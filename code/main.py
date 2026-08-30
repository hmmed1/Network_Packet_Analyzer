from scapy.all import sniff
from packet_decoder import process

packet_list = []
def collect_packet (packet):
    packet_list.append(packet)
    print("\n\n-------------------- Packet Number: "+str(len(packet_list))+"--------------------\n\n")
    process(packet)
sniff(prn=collect_packet, stop_filter=lambda p: len(packet_list) >= 10)
print(len(packet_list))