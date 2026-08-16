from scapy.all import sniff
from packet_decoder import process


sniff(prn=process, count=1)
