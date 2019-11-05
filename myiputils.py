import struct, socket
# Funções que foram usadas no TCP e também são úteis
# para a implementação do protocolo IP
from mytcputils import str2addr, addr2str, calc_checksum


IPPROTO_ICMP = 1
IPPROTO_TCP = 6


def read_ipv4_header(datagram, verify_checksum=False):
    # https://en.wikipedia.org/wiki/IPv4#Header
    vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, \
        checksum, src_addr, dest_addr = \
        struct.unpack('!BBHHHBBHII', datagram[:20])
    version = vihl >> 4
    ihl = vihl & 0xf
    assert version == 4
    dscp = dscpecn >> 2
    ecn = dscpecn & 0b11
    flags = flagsfrag >> 13
    frag_offset = flagsfrag & 0x1fff
    src_addr = addr2str(datagram[12:16])
    dst_addr = addr2str(datagram[16:20])
    if verify_checksum:
        assert calc_checksum(datagram[:4*ihl]) == 0
    payload = datagram[4*ihl:total_len]

    return dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload

def make_ipv4_header(src_addr, dest_addr, payload):
    # https://en.wikipedia.org/wiki/IPv4#Header
    # min header size = 16 octets / 126 bytes
    # Default values
    # 1st octet
    ver = (4 << 4)
    ihl = 5
    # 2nd octet
    dscp = ecn = 0
    # 3rd octet
    header_len = 20 + len(payload)
    # 4th octet
    identification = 0
    # 5th octet
    flags = (0 << 13)
    # 6th octet
    ttl = 64
    # 7th octet
    proto = IPPROTO_TCP
    # 8th & 9th octet
    checksum = 0
    # 10th to 12th octet
    src_addr = socket.inet_aton(src_addr)
    # 13th to 16th octet
    dest_addr = socket.inet_aton(dest_addr)
    pseudo = struct.pack('!BBHHHBBH4s4s', ver + ihl, dscp + ecn, header_len, identification, \
        flags, ttl, proto, checksum, src_addr, dest_addr)
    checksum = calc_checksum(pseudo[:4*ihl])
    pack = struct.pack('!BBHHHBBH4s4s', ver + ihl, dscp + ecn, header_len, identification, \
        flags, ttl, proto, checksum, src_addr, dest_addr) + payload
    return pack
