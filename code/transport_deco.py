from utils import decode_tcp_flags, get_protocol


def transport_decoder(prot, transport_payload):

    if prot == 6:
        transport_header = transport_payload[:20]
        decode_tcp(transport_header)

    elif prot == 17:
        transport_header = transport_payload[:8]
        decode_udp(transport_header)

    else:
        print(f"\nSkipping protocol {get_protocol(prot)}")


def decode_tcp(transport_header):
    print("\n---------------- TCP Header ----------------")

    src_port = int.from_bytes(transport_header[0:2], byteorder="big")
    dest_port = int.from_bytes(transport_header[2:4], byteorder="big")
    seq_n = int.from_bytes(transport_header[4:8], byteorder="big")
    ack_n = int.from_bytes(transport_header[8:12], byteorder="big")

    d_off = (transport_header[12] >> 4) * 4
    flags_byte = transport_header[13]

    checksum = int.from_bytes(
        transport_header[16:18],
        byteorder="big"
    )

    urg_p = int.from_bytes(
        transport_header[18:20],
        byteorder="big"
    )

    print("Source Port      :", src_port)
    print("Destination Port :", dest_port)
    print("Sequence Number  :", seq_n)
    print("Ack Number       :", ack_n)
    print("Data Offset (Size):", d_off, "bytes")
    print("Flags            :", decode_tcp_flags(flags_byte))
    print("Checksum         :", checksum)
    print("Urgent Pointer   :", urg_p)


def decode_udp(transport_header):
    print("\n---------------- UDP Header ----------------")

    src_port = int.from_bytes(transport_header[0:2], byteorder="big")
    dest_port = int.from_bytes(transport_header[2:4], byteorder="big")
    length = int.from_bytes(transport_header[4:6], byteorder="big")
    checksum = int.from_bytes(transport_header[6:8], byteorder="big")

    print("Source Port      :", src_port)
    print("Destination Port :", dest_port)
    print("UDP Length       :", length)
    print("Checksum         :", checksum)